//! H5 (SPEC §13.3): page locking (`mlock`) for long-lived secret
//! material — the in-memory half of key-material protection. The core
//! erases secrets on free (`zeroize`, compiler-fenced); this module keeps
//! the OS from writing those secrets to swap while they LIVE: key
//! shares, the transport signing key, and pooled presignature records
//! are wrapped at the node boundary (core structs are NOT touched).
//!
//! Two wrappers:
//!
//! * [`LockedSecret<T>`] — a heap-allocated secret whose pages are
//!   `mlock`ed on construction and `munlock`ed on drop. `T` MUST
//!   self-erase on drop (every wrapped type does: k256's `SecretKey`/
//!   `SigningKey`, the core's `Presignature`/`KeyShare`/`TripleShare` —
//!   all zeroize their scalars in `Drop`). Drop order: this wrapper
//!   unlocks the pages, then the inner value's own `Drop` erases it —
//!   the unlock-to-erase window is a handful of instructions with no
//!   allocation in between.
//! * [`LockedBytes`] — the same for raw byte secrets with no self-erasure
//!   (the H5 storage key): the buffer is erased with volatile writes +
//!   a compiler fence BEFORE `munlock`.
//!
//! Policy — FAIL-OPEN WITH A LOUD WARNING: if `mlock` fails
//! (`RLIMIT_MEMLOCK` too small, no `CAP_IPC_LOCK`, an OS that restricts
//! wiring), the wrapper logs a WARNING and continues UNLOCKED. Failing
//! closed would make every default dev machine (and most containers,
//! where the default `RLIMIT_MEMLOCK` is 64 KiB) unable to run a node at
//! all; swap protection is a hardening layer, not a correctness
//! invariant, and a node that cannot start protects nothing. Deployments
//! that require the guarantee must treat the warning as fatal at the ops
//! level. This is the ONLY fail-open path in H5 — at-rest integrity
//! ([`crate::seal`]) fails closed.
//!
//! Only the two `mlock`/`munlock` syscalls below are `unsafe` (libc has
//! no safe API); everything else in the module is safe Rust.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// TEST HOOK: simulate `mlock` failure (RLIMIT_MEMLOCK exhausted) to
/// exercise the fail-open path without OS-specific limit fiddling.
static FORCE_MLOCK_FAILURE: AtomicBool = AtomicBool::new(false);

/// The OS page size, resolved once.
#[cfg(unix)]
fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: `sysconf(_SC_PAGESIZE)` has no failure mode that
        // matters here; fall back to the common 4 KiB.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(n).ok().filter(|n| *n > 0).unwrap_or(4096)
    })
}

/// Round `ptr..ptr+len` outward to page boundaries.
#[cfg(unix)]
fn page_round(ptr: *const u8, len: usize) -> (*mut libc::c_void, usize) {
    let page = page_size();
    let addr = ptr as usize;
    let start = addr & !(page - 1);
    let end = (addr + len).div_ceil(page) * page;
    (start as *mut libc::c_void, end - start)
}

/// Pin the pages holding `ptr..ptr+len` so the kernel cannot swap them
/// out. Returns the OS error on failure (caller decides the policy).
#[cfg(unix)]
fn lock_pages(ptr: *const u8, len: usize) -> io::Result<()> {
    if FORCE_MLOCK_FAILURE.load(Ordering::SeqCst) {
        return Err(io::Error::other("simulated mlock failure (test hook)"));
    }
    let (addr, len) = page_round(ptr, len);
    // SAFETY: `addr..addr+len` is the page-rounded range covering the
    // caller's live heap allocation; `mlock` only pins whole pages and
    // never reads or writes their contents.
    if unsafe { libc::mlock(addr, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Undo [`lock_pages`]. Errors are ignored: the pages are about to be
/// freed anyway (the kernel unwires a freed mapping regardless).
#[cfg(unix)]
fn unlock_pages(ptr: *const u8, len: usize) {
    let (addr, len) = page_round(ptr, len);
    // SAFETY: see `lock_pages`; `munlock` on a still-mapped range is
    // always safe, and a failure (already unwired) is harmless.
    unsafe { libc::munlock(addr, len) };
}

/// Non-Unix fallback: no `mlock` — report unsupported and let the
/// caller's fail-open policy log and continue.
#[cfg(not(unix))]
fn lock_pages(_ptr: *const u8, _len: usize) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "mlock is not supported on this platform",
    ))
}

#[cfg(not(unix))]
fn unlock_pages(_ptr: *const u8, _len: usize) {}

/// The fail-open warning (module docs explain the policy).
fn warn_unlocked(what: &str, len: usize, e: &io::Error) {
    eprintln!(
        "WARNING [H5]: mlock failed for a {len}-byte {what} ({e}); continuing UNLOCKED — \
         the OS may swap this secret to disk. Raise RLIMIT_MEMLOCK (ulimit -l) or grant \
         CAP_IPC_LOCK to enable locking. (Documented fail-open policy, node/src/locked.rs.)"
    );
}

/// A heap-allocated secret whose pages are `mlock`ed for its whole
/// lifetime (see the module docs for the fail-open policy and the drop
/// order). Derefs to `&T`; [`LockedSecret::into_inner`] transfers the
/// value out (unlocking first — the caller takes over erasure).
///
/// `T` MUST erase itself on drop (zeroize); the wrapper does not and
/// cannot overwrite `T` soundly (it may own interior heap allocations).
pub struct LockedSecret<T> {
    /// `Some` until [`LockedSecret::into_inner`] takes it.
    inner: Option<Box<T>>,
    locked: bool,
}

impl<T> LockedSecret<T> {
    /// Move `value` onto the heap and `mlock` its pages. On `mlock`
    /// failure: log a WARNING and continue unlocked (fail-open — see the
    /// module docs).
    pub fn new(value: T) -> Self {
        let inner = Box::new(value);
        let mut locked = false;
        let len = std::mem::size_of::<T>();
        if len > 0 {
            let ptr = (&*inner) as *const T as *const u8;
            match lock_pages(ptr, len) {
                Ok(()) => locked = true,
                Err(e) => warn_unlocked(std::any::type_name::<T>(), len, &e),
            }
        }
        Self {
            inner: Some(inner),
            locked,
        }
    }

    /// The wrapped secret.
    pub fn get(&self) -> &T {
        self.inner.as_deref().expect("locked secret present")
    }

    /// Whether the pages are actually locked (false after a fail-open
    /// `mlock` failure — tests assert the policy on this).
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Unlock and move the secret out (the caller owns erasure from here).
    pub fn into_inner(mut self) -> T {
        let inner = self.inner.take().expect("locked secret present");
        if self.locked {
            unlock_pages((&*inner) as *const T as *const u8, std::mem::size_of::<T>());
        }
        *inner
    }
}

impl<T> std::ops::Deref for LockedSecret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.get()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for LockedSecret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedSecret")
            .field("inner", &self.inner)
            .field("locked", &self.locked)
            .finish()
    }
}

impl<T> Drop for LockedSecret<T> {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            if self.locked {
                unlock_pages(
                    (&**inner) as *const T as *const u8,
                    std::mem::size_of::<T>(),
                );
            }
        }
        // `inner`'s own Drop runs right after this and erases the secret
        // (T's contract — see the struct docs).
    }
}

/// A page-locked byte buffer for secrets with no self-erasing `Drop`
/// (the H5 storage key). Unlike [`LockedSecret<T>`] the buffer is erased
/// HERE — volatile writes plus a compiler fence — BEFORE `munlock`, so
/// the plaintext never outlives the lock.
pub struct LockedBytes {
    inner: Option<Box<[u8]>>,
    locked: bool,
}

/// Compiler-fenced erasure (what `zeroize` does for the core; node-side
/// byte buffers erase through this instead of a new dependency).
fn erase(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, writable byte of the buffer;
        // the volatile write cannot be elided by the optimizer.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

impl LockedBytes {
    /// Move `bytes` onto the heap and `mlock` its pages (fail-open with a
    /// WARNING on `mlock` failure — see the module docs).
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let inner: Box<[u8]> = bytes.into().into_boxed_slice();
        let mut locked = false;
        if !inner.is_empty() {
            match lock_pages(inner.as_ptr(), inner.len()) {
                Ok(()) => locked = true,
                Err(e) => warn_unlocked("byte secret", inner.len(), &e),
            }
        }
        Self {
            inner: Some(inner),
            locked,
        }
    }

    /// The wrapped bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_deref().expect("locked bytes present")
    }

    /// Whether the pages are actually locked (see [`LockedSecret::is_locked`]).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl std::ops::Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        if let Some(inner) = &mut self.inner {
            erase(inner); // erase BEFORE unlocking: plaintext never outlives the lock
            if self.locked {
                unlock_pages(inner.as_ptr(), inner.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Restore the failure hook even when a test panics (the static is
    /// process-global and tests run in parallel).
    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            FORCE_MLOCK_FAILURE.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn locked_secret_roundtrip_contents_intact() {
        let secret = [0xA5u8; 64];
        let locked = LockedSecret::new(secret);
        // Lock best-effort: on a host that denies mlock this logs and
        // continues — either way the contents must be intact.
        eprintln!("[test] LockedSecret locked = {}", locked.is_locked());
        assert_eq!(*locked.get(), secret);
        assert_eq!(locked.len(), 64);
        let back = locked.into_inner();
        assert_eq!(back, secret);
    }

    #[test]
    fn locked_bytes_roundtrip_contents_intact() {
        let bytes: Vec<u8> = (0..200u8).map(|b| b ^ 0x3C).collect();
        let locked = LockedBytes::new(bytes.clone());
        eprintln!("[test] LockedBytes locked = {}", locked.is_locked());
        assert_eq!(locked.as_slice(), bytes.as_slice());
        assert_eq!(&locked[..], bytes.as_slice());
    }

    #[test]
    fn mlock_failure_fails_open_with_contents_intact() {
        let _guard = HookGuard;
        FORCE_MLOCK_FAILURE.store(true, Ordering::SeqCst);
        let secret = LockedSecret::new([7u8; 32]);
        // Fail-open: not locked, but fully usable — availability over
        // swap protection (the documented policy).
        assert!(!secret.is_locked());
        assert_eq!(*secret.get(), [7u8; 32]);
        let bytes = LockedBytes::new(vec![9u8; 16]);
        assert!(!bytes.is_locked());
        assert_eq!(bytes.as_slice(), &[9u8; 16]);
        // Both drop unlocked without attempting munlock.
    }

    #[test]
    fn empty_and_zst_locking_is_a_noop() {
        let bytes = LockedBytes::new(Vec::<u8>::new());
        assert!(!bytes.is_locked()); // nothing to lock
        assert!(bytes.as_slice().is_empty());
    }
}
