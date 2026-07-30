//! M3c: OPTIONAL mutually-authenticated TLS (mTLS) for the mesh
//! (SPEC §13.1 "mutually authenticated channels").
//!
//! M1–M3b run over plain TCP: every envelope is SIGNED (§10.2 —
//! authentication + integrity at the message layer) but nothing is
//! encrypted in transit and there is no transport-level peer
//! authentication. This module adds an optional TLS 1.3 layer (rustls
//! with the ring provider, blocking `std::net` streams — still no
//! async runtime) wrapping each TCP connection. The wire format
//! INSIDE the TLS stream is unchanged: length-prefixed canonical
//! `Encode`/`Decode` frames of signed envelopes.
//!
//! Trust model — certificate pinning to the committee, NO PKI, no
//! system roots: every party has a self-signed certificate (rcgen in
//! tests and demos) and each node pins the EXACT certificate of every
//! committee member. An outgoing connection accepts only the pinned
//! certificate of the party it connects to, so the TLS peer identity
//! IS the expected [`PartyId`]; an incoming connection accepts only a
//! pinned committee certificate and is attributed to the matching
//! party. Message attribution stays cryptographic — §10.2 envelope
//! signatures are verified regardless of TLS (defense in depth, never
//! a replacement: TLS adds confidentiality in transit and
//! transport-level peer authentication; end-to-end accountability
//! still comes from the signed envelopes). A real deployment
//! substitutes its own PKI and certificate issuance for the rcgen
//! self-signed certs (SPEC §13.1); the pinning verifiers here are the
//! reference.
//!
//! Failure policy: a handshake failure (unpinned certificate,
//! plaintext peer, corrupt stream) rejects the connection with a loud
//! log. There is NO fallback to plaintext once TLS is configured.
//!
//! H2: both handshakes run under [`HANDSHAKE_TIMEOUT`]. The strategy is
//! socket timeouts — the simplest approach compatible with blocking
//! rustls: the `TcpStream` gets short read/write timeouts, and the
//! `complete_io` loop treats `WouldBlock`/`TimedOut` as a tick
//! (retrying until the deadline) — a peer that connects and never
//! completes the handshake is rejected within the timeout instead of
//! parking the accept thread forever.

use std::collections::BTreeMap;
use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName,
    Error as RustlsError, ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
};

use ohm_ecdsa::PartyId;

/// The DNS name sent in the client's ClientHello. The pinning
/// verifiers authenticate by exact certificate equality and ignore the
/// server name, but rustls requires one — a fixed committee-wide name.
pub const TLS_SERVER_NAME: &str = "ohm-ecdsa.node";

/// H2: deadline for the blocking mTLS handshake (both directions). A
/// peer that never completes the handshake is rejected within this
/// budget instead of parking a thread; localhost handshakes complete in
/// milliseconds, so 10 s is generous.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The socket poll interval inside the handshake loop (see the module
/// docs): how often a stalled handshake re-checks its deadline.
const HANDSHAKE_POLL: Duration = Duration::from_millis(250);

/// `party-<id>.crt.pem` — one party's public certificate.
pub fn cert_file(dir: &Path, id: PartyId) -> PathBuf {
    dir.join(format!("party-{id}.crt.pem"))
}

/// `party-<id>.key.pem` — one party's SECRET certificate key.
pub fn key_file(dir: &Path, id: PartyId) -> PathBuf {
    dir.join(format!("party-{id}.key.pem"))
}

/// Generate one self-signed certificate for a party (rcgen, ECDSA
/// P-256 — the ring provider verifies it). Returns
/// `(cert_pem, key_pem)`; the key is SECRET material.
pub fn generate_party(id: PartyId) -> io::Result<(String, String)> {
    let names = vec![
        TLS_SERVER_NAME.to_string(),
        format!("party-{id}.ohm-ecdsa.node"),
    ];
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(names)
        .map_err(|e| io::Error::other(format!("rcgen: {e}")))?;
    Ok((cert.pem(), signing_key.serialize_pem()))
}

/// Generate and write `party-<id>.crt.pem` / `party-<id>.key.pem` for
/// every id (the `setup`/`spawn-demo` ceremony step; real deployments
/// substitute their own PKI, SPEC §13.1). The key PEMs are secret —
/// written `0600` (H5).
pub fn write_committee_certs(dir: &Path, ids: &[PartyId]) -> io::Result<()> {
    for &id in ids {
        let (cert_pem, key_pem) = generate_party(id)?;
        std::fs::write(cert_file(dir, id), cert_pem)?;
        crate::seal::write_secret_file(&key_file(dir, id), key_pem.as_bytes())?;
    }
    Ok(())
}

/// One node's mTLS material: its own certificate + secret key and the
/// PINNED certificate of every committee member (including itself).
pub struct CommitteeTls {
    me: PartyId,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    pinned: BTreeMap<PartyId, CertificateDer<'static>>,
}

impl CommitteeTls {
    /// Build from DER bytes (tests construct certs with rcgen in
    /// memory). `pinned` must contain an entry for `me` itself.
    pub fn from_der(
        me: PartyId,
        cert: Vec<u8>,
        key: Vec<u8>,
        pinned: BTreeMap<PartyId, Vec<u8>>,
    ) -> io::Result<Self> {
        let invalid =
            |what: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("tls: {what}"));
        let cert = CertificateDer::from(cert);
        let key = PrivateKeyDer::Pkcs8(key.into());
        let mut pinned_der = BTreeMap::new();
        for (id, der) in pinned {
            pinned_der.insert(id, CertificateDer::from(der));
        }
        if !pinned_der.contains_key(&me) {
            return Err(invalid(
                "the pinned set must contain this node's own certificate",
            ));
        }
        if pinned_der.get(&me) != Some(&cert) {
            return Err(invalid("own certificate does not match its pinned entry"));
        }
        Ok(Self {
            me,
            cert,
            key,
            pinned: pinned_der,
        })
    }

    /// Load from PEM files: this node's `cert`/`key` plus every
    /// `party-<id>.crt.pem` under `pinned_dir` (the PUBLIC pinned set
    /// — the same directory [`write_committee_certs`] writes).
    pub fn from_pem_files(
        me: PartyId,
        cert: &Path,
        key: &Path,
        pinned_dir: &Path,
    ) -> io::Result<Self> {
        let invalid =
            |what: String| io::Error::new(io::ErrorKind::InvalidInput, format!("tls: {what}"));
        let cert = CertificateDer::from_pem_file(cert)
            .map_err(|e| invalid(format!("reading {}: {e}", cert.display())))?;
        let key = PrivateKeyDer::from_pem_file(key)
            .map_err(|e| invalid(format!("reading {}: {e}", key.display())))?;
        let mut pinned = BTreeMap::new();
        for entry in std::fs::read_dir(pinned_dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(id) = name
                .strip_prefix("party-")
                .and_then(|r| r.strip_suffix(".crt.pem"))
                .and_then(|n| n.parse::<PartyId>().ok())
            else {
                continue;
            };
            let der = CertificateDer::from_pem_file(&path)
                .map_err(|e| invalid(format!("reading {}: {e}", path.display())))?;
            pinned.insert(id, der);
        }
        if pinned.is_empty() {
            return Err(invalid(format!(
                "no party-*.crt.pem certificates under {}",
                pinned_dir.display()
            )));
        }
        let mut pinned_der = BTreeMap::new();
        for (id, der) in &pinned {
            pinned_der.insert(*id, der.as_ref().to_vec());
        }
        Self::from_der(
            me,
            cert.as_ref().to_vec(),
            key.secret_der().to_vec(),
            pinned_der,
        )
    }

    /// The pinned certificate of a party.
    pub fn pinned_cert(&self, id: PartyId) -> Option<&CertificateDer<'static>> {
        self.pinned.get(&id)
    }

    /// Client-side TLS for the outgoing connection TO `peer`: the
    /// server certificate verifier accepts ONLY the pinned certificate
    /// of `peer` — the TLS peer identity is the expected [`PartyId`]
    /// by construction. This node presents its own certificate (mTLS).
    fn client_config(&self, peer: PartyId) -> io::Result<Arc<ClientConfig>> {
        let pinned = self.pinned.get(&peer).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tls: no pinned certificate for party {peer}"),
            )
        })?;
        let provider = default_provider();
        let verifier = PinnedServerCertVerifier {
            pinned,
            algs: provider.signature_verification_algorithms,
        };
        let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_err)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(tls_err)?;
        Ok(Arc::new(cfg))
    }

    /// Server-side TLS for accepted connections: client certificates
    /// are MANDATORY and verified against the pinned committee set
    /// (any member's exact certificate).
    fn server_config(&self) -> io::Result<Arc<ServerConfig>> {
        let provider = default_provider();
        let verifier = PinnedClientCertVerifier {
            pinned: self.pinned.values().cloned().collect(),
            algs: provider.signature_verification_algorithms,
        };
        let cfg = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_err)?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(tls_err)?;
        Ok(Arc::new(cfg))
    }

    /// Run the blocking client handshake on `tcp` toward `peer`
    /// (fails closed: any handshake error rejects the connection).
    /// H2: bounded by [`HANDSHAKE_TIMEOUT`] (see the module docs).
    pub(crate) fn client_handshake(
        &self,
        peer: PartyId,
        tcp: TcpStream,
    ) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
        let cfg = self.client_config(peer)?;
        let name = ServerName::try_from(TLS_SERVER_NAME).expect("a valid DNS name constant");
        let mut conn = ClientConnection::new(cfg, name).map_err(tls_err)?;
        let mut sock = tcp;
        sock.set_read_timeout(Some(HANDSHAKE_POLL))?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        while conn.is_handshaking() {
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if Instant::now() > deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "tls: client handshake timed out",
                        ));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(StreamOwned::new(conn, sock))
    }

    /// Run the blocking server handshake on an accepted `tcp`
    /// connection, returning the stream and the party the peer
    /// authenticated AS (the pinned-set entry matching its exact
    /// certificate — the client verifier already rejected anything
    /// else). H2: bounded by [`HANDSHAKE_TIMEOUT`] (see the module docs).
    pub(crate) fn server_handshake(
        &self,
        tcp: TcpStream,
    ) -> io::Result<(StreamOwned<ServerConnection, TcpStream>, PartyId)> {
        let cfg = self.server_config()?;
        let mut conn = ServerConnection::new(cfg).map_err(tls_err)?;
        let mut sock = tcp;
        sock.set_read_timeout(Some(HANDSHAKE_POLL))?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        while conn.is_handshaking() {
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if Instant::now() > deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "tls: server handshake timed out",
                        ));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let peer = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| {
                self.pinned
                    .iter()
                    .find(|(_, pinned)| pinned.as_ref() == cert.as_ref())
                    .map(|(id, _)| *id)
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "tls: peer certificate is not in the pinned committee set",
                )
            })?;
        if peer == self.me {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tls: peer presented this node's own certificate",
            ));
        }
        Ok((StreamOwned::new(conn, sock), peer))
    }
}

fn tls_err(e: RustlsError) -> io::Error {
    io::Error::other(format!("tls: {e}"))
}

/// Server-certificate verifier for OUTGOING connections: accepts
/// exactly the one pinned certificate of the expected peer (chain
/// building, expiry and server-name checks are replaced by exact
/// committee pinning — the handshake-signature checks below still
/// prove the peer holds the certificate's private key).
#[derive(Debug)]
struct PinnedServerCertVerifier {
    pinned: CertificateDer<'static>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Client-certificate verifier for INCOMING connections: accepts any
/// certificate in the pinned committee set (mTLS — a client without a
/// committee certificate is rejected during the handshake).
#[derive(Debug)]
struct PinnedClientCertVerifier {
    pinned: Vec<CertificateDer<'static>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if self
            .pinned
            .iter()
            .any(|c| c.as_ref() == end_entity.as_ref())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    /// Per-party `(cert_der, key_der)`.
    type OwnCerts = BTreeMap<PartyId, (Vec<u8>, Vec<u8>)>;
    /// Party → pinned cert DER.
    type PinnedCerts = BTreeMap<PartyId, Vec<u8>>;

    /// Generate a cert per party; return per-party DER certs and the
    /// shared pinned map.
    fn committee(ids: &[PartyId]) -> (OwnCerts, PinnedCerts) {
        let mut own = BTreeMap::new();
        let mut pinned = BTreeMap::new();
        for &id in ids {
            let names = vec![TLS_SERVER_NAME.to_string()];
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(names).unwrap();
            own.insert(
                id,
                (cert.der().as_ref().to_vec(), signing_key.serialize_der()),
            );
            pinned.insert(id, cert.der().as_ref().to_vec());
        }
        (own, pinned)
    }

    fn verifier_input(certs: &OwnCerts, id: PartyId) -> CertificateDer<'static> {
        CertificateDer::from(certs[&id].0.clone())
    }

    #[test]
    fn pinned_server_verifier_accepts_only_the_pinned_cert() {
        let (own, pinned) = committee(&[1, 2, 3]);
        let provider = default_provider();
        let v = PinnedServerCertVerifier {
            pinned: CertificateDer::from(pinned[&1].clone()),
            algs: provider.signature_verification_algorithms,
        };
        let name = ServerName::try_from(TLS_SERVER_NAME).unwrap();
        let now = UnixTime::now();
        // The pinned certificate is accepted …
        assert!(v
            .verify_server_cert(&verifier_input(&own, 1), &[], &name, &[], now)
            .is_ok());
        // … any other committee member's certificate is NOT (pinning is
        // to the EXPECTED party, not to the committee).
        assert!(v
            .verify_server_cert(&verifier_input(&own, 2), &[], &name, &[], now)
            .is_err());
    }

    #[test]
    fn pinned_client_verifier_accepts_committee_rejects_strangers() {
        let (own, pinned) = committee(&[1, 2]);
        let provider = default_provider();
        let v = PinnedClientCertVerifier {
            pinned: pinned.values().cloned().map(CertificateDer::from).collect(),
            algs: provider.signature_verification_algorithms,
        };
        let now = UnixTime::now();
        assert!(v
            .verify_client_cert(&verifier_input(&own, 1), &[], now)
            .is_ok());
        assert!(v
            .verify_client_cert(&verifier_input(&own, 2), &[], now)
            .is_ok());
        // A stranger's self-signed certificate is rejected.
        let (strangers, _) = committee(&[9]);
        assert!(v
            .verify_client_cert(&verifier_input(&strangers, 9), &[], now)
            .is_err());
    }

    #[test]
    fn from_der_rejects_inconsistent_material() {
        let (own, pinned) = committee(&[1, 2]);
        // Own certificate missing from the pinned set.
        let mut sparse = pinned.clone();
        sparse.remove(&1);
        assert!(CommitteeTls::from_der(1, own[&1].0.clone(), own[&1].1.clone(), sparse).is_err());
        // Own certificate not matching its pinned entry.
        let mut swapped = pinned.clone();
        swapped.insert(1, pinned[&2].clone());
        assert!(CommitteeTls::from_der(1, own[&1].0.clone(), own[&1].1.clone(), swapped).is_err());
        // Consistent material builds.
        assert!(CommitteeTls::from_der(1, own[&1].0.clone(), own[&1].1.clone(), pinned).is_ok());
    }
}
