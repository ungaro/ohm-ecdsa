//! Transport substrate: canonical framing, the full-mesh TCP node, the
//! M1 `Transport` impl, and the optional committee-pinned mTLS layer.

pub mod mesh;
pub mod tls;
pub mod transport;
pub mod wire;
