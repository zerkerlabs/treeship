use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// A DSSE envelope. This is the portable artifact unit — everything
/// Treeship stores, transmits, and verifies is an `Envelope`.
///
/// The `payload` field is base64url-encoded statement bytes.
/// The `signatures` are over `PAE(payloadType, decode(payload))`.
/// The outer JSON is never signed — only the PAE construction is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// base64url-encoded statement bytes (compact JSON).
    pub payload: String,

    /// MIME type of the statement.
    /// Format: `"application/vnd.treeship.<type>.v1+json"`
    #[serde(rename = "payloadType")]
    pub payload_type: String,

    /// Signatures over `PAE(payloadType, decode(payload))`.
    /// v1: always exactly one Ed25519 signature.
    pub signatures: Vec<Signature>,
}

/// One signer's signature over the PAE-encoded envelope content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Stable key identifier from the keystore.
    pub keyid: String,

    /// base64url-encoded raw signature bytes (64 bytes for Ed25519).
    pub sig: String,
}

/// Errors that can occur when working with envelopes.
#[derive(Debug)]
pub enum EnvelopeError {
    Base64Decode(String),
    JsonParse(String),
    EmptyPayload,
    EmptyPayloadType,
    NoSignatures,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64Decode(e)  => write!(f, "base64 decode: {}", e),
            Self::JsonParse(e)     => write!(f, "json parse: {}", e),
            Self::EmptyPayload     => write!(f, "payload is empty"),
            Self::EmptyPayloadType => write!(f, "payloadType is empty"),
            Self::NoSignatures     => write!(f, "no signatures in envelope"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl Envelope {
    /// Decodes the base64url payload back to raw bytes.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        URL_SAFE_NO_PAD
            .decode(&self.payload)
            .map_err(|e| EnvelopeError::Base64Decode(e.to_string()))
    }

    /// Deserializes the payload into type `T`.
    pub fn unmarshal_statement<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<T, EnvelopeError> {
        let bytes = self.payload_bytes()?;
        serde_json::from_slice(&bytes)
            .map_err(|e| EnvelopeError::JsonParse(e.to_string()))
    }

    /// Decodes a single `Signature`'s sig field to raw bytes.
    pub fn sig_bytes(sig: &Signature) -> Result<Vec<u8>, EnvelopeError> {
        URL_SAFE_NO_PAD
            .decode(&sig.sig)
            .map_err(|e| EnvelopeError::Base64Decode(
                format!("sig for key {}: {}", sig.keyid, e)
            ))
    }

    /// Serializes the envelope to compact JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, EnvelopeError> {
        serde_json::to_vec(self)
            .map_err(|e| EnvelopeError::JsonParse(e.to_string()))
    }

    /// Parses an envelope from JSON bytes, validating required fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let e: Envelope = serde_json::from_slice(bytes)
            .map_err(|e| EnvelopeError::JsonParse(e.to_string()))?;
        if e.payload.is_empty()      { return Err(EnvelopeError::EmptyPayload); }
        if e.payload_type.is_empty() { return Err(EnvelopeError::EmptyPayloadType); }
        if e.signatures.is_empty()   { return Err(EnvelopeError::NoSignatures); }
        Ok(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStmt {
        actor: String,
    }

    fn make_envelope(payload: &str) -> Envelope {
        Envelope {
            payload:      URL_SAFE_NO_PAD.encode(payload),
            payload_type: "application/vnd.treeship.action.v1+json".into(),
            signatures:   vec![Signature { keyid: "key_test".into(), sig: "c2ln".into() }],
        }
    }

    #[test]
    fn payload_bytes_roundtrip() {
        let original = b"{\"actor\":\"agent://test\"}";
        let env = Envelope {
            payload:      URL_SAFE_NO_PAD.encode(original),
            payload_type: "application/vnd.treeship.action.v1+json".into(),
            signatures:   vec![],
        };
        assert_eq!(env.payload_bytes().unwrap(), original);
    }

    #[test]
    fn unmarshal_statement() {
        let stmt = TestStmt { actor: "agent://test".into() };
        let json = serde_json::to_vec(&stmt).unwrap();
        let env  = Envelope {
            payload:      URL_SAFE_NO_PAD.encode(&json),
            payload_type: "application/vnd.treeship.action.v1+json".into(),
            signatures:   vec![],
        };
        let decoded: TestStmt = env.unmarshal_statement().unwrap();
        assert_eq!(decoded, stmt);
    }

    #[test]
    fn json_roundtrip() {
        let env      = make_envelope("{\"actor\":\"agent://test\"}");
        let json     = env.to_json().unwrap();
        let restored = Envelope::from_json(&json).unwrap();
        assert_eq!(restored.payload, env.payload);
        assert_eq!(restored.payload_type, env.payload_type);
    }

    #[test]
    fn from_json_rejects_empty_payload() {
        let json = br#"{"payload":"","payloadType":"text/plain","signatures":[{"keyid":"k","sig":"s"}]}"#;
        assert!(Envelope::from_json(json).is_err());
    }

    #[test]
    fn from_json_rejects_no_signatures() {
        let json = br#"{"payload":"YQ","payloadType":"text/plain","signatures":[]}"#;
        assert!(Envelope::from_json(json).is_err());
    }

    #[test]
    fn from_json_rejects_empty_payload_type() {
        let json = br#"{"payload":"YQ","payloadType":"","signatures":[{"keyid":"k","sig":"s"}]}"#;
        assert!(Envelope::from_json(json).is_err());
    }
}
