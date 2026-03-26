/// Constructs the DSSE Pre-Authentication Encoding byte string.
///
/// This is the exact byte sequence that gets signed and verified —
/// never the raw payload alone. Including both the payloadType and its
/// length in the signed bytes prevents type-confusion attacks where an
/// attacker signs bytes under type B that parse validly under type A.
///
/// Format (DSSE spec):
/// ```text
/// "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
/// ```
/// where SP is ASCII space (0x20) and LEN(s) is the decimal string of len(s).
///
/// # Examples
///
/// ```
/// use treeship_core::attestation::pae;
///
/// let result = pae("application/example", b"hello");
/// assert_eq!(result, b"DSSEv1 19 application/example 5 hello");
/// ```
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_len  = payload_type.len();
    let pay_len   = payload.len();

    // Pre-allocate the exact capacity:
    // "DSSEv1 " (7) + digits(type_len) + " " + type + " " + digits(pay_len) + " " + payload
    let cap = 7
        + digits(type_len)
        + 1
        + type_len
        + 1
        + digits(pay_len)
        + 1
        + pay_len;

    let mut buf = Vec::with_capacity(cap);

    buf.extend_from_slice(b"DSSEv1 ");
    buf.extend_from_slice(type_len.to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload_type.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(pay_len.to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload);

    buf
}

/// Returns the number of decimal digits needed to represent n.
fn digits(n: usize) -> usize {
    if n == 0 { 1 } else { (n as f64).log10().floor() as usize + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_matches_spec() {
        let got = pae("application/example", b"hello");
        assert_eq!(got, b"DSSEv1 19 application/example 5 hello");
    }

    #[test]
    fn empty_payload() {
        let got = pae("text/plain", b"");
        assert_eq!(got, b"DSSEv1 10 text/plain 0 ");
    }

    #[test]
    fn deterministic() {
        let payload = br#"{"type":"treeship/action/v1"}"#;
        let a = pae("application/vnd.treeship.action.v1+json", payload);
        let b = pae("application/vnd.treeship.action.v1+json", payload);
        assert_eq!(a, b);
    }

    #[test]
    fn type_isolation() {
        // Same payload, different types → different PAE bytes.
        // If this were equal, a type-confusion attack would be possible.
        let payload = b"{\"x\":1}";
        let a = pae("application/type-a", payload);
        let b = pae("application/type-b", payload);
        assert_ne!(a, b, "PAE must differ for different payloadTypes");
    }

    #[test]
    fn payload_isolation() {
        // Same type, different payload → different PAE bytes.
        let a = pae("application/example", b"hello");
        let b = pae("application/example", b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn capacity_is_exact() {
        // The pre-allocated capacity should match the final length.
        // This catches off-by-one errors in the capacity calculation.
        let pt = "application/vnd.treeship.action.v1+json";
        let payload = br#"{"type":"treeship/action/v1","actor":"agent://researcher"}"#;
        let result = pae(pt, payload);
        // capacity == len since we pre-allocate exactly right
        assert_eq!(result.capacity(), result.len());
    }

    #[test]
    fn treeship_action_type() {
        let pt      = "application/vnd.treeship.action.v1+json";
        let payload = b"{}";
        let got     = pae(pt, payload);
        // "DSSEv1 39 application/vnd.treeship.action.v1+json 2 {}"
        // len("application/vnd.treeship.action.v1+json") == 39
        assert_eq!(pt.len(), 39, "sanity: payload type length");
        let want = b"DSSEv1 39 application/vnd.treeship.action.v1+json 2 {}";
        assert_eq!(got, want.as_ref());
    }
}
