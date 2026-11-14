//! TLS key-exchange groups, with the names each ecosystem uses for them.

/// A TLS 1.3 key-exchange group (Go calls these `CurveID`, OpenSSL calls them groups).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Group {
    X25519,
    P256,
    P384,
    P521,
    /// Hybrid X25519 + ML-KEM-768.
    X25519MlKem768,
    /// Hybrid P-256 + ML-KEM-768.
    SecP256r1MlKem768,
    /// Hybrid P-384 + ML-KEM-1024.
    SecP384r1MlKem1024,
    /// Pure ML-KEM-1024.
    Mlkem1024,
    /// A name hybridize does not recognize, never guessed.
    Unknown(String),
}

impl Group {
    /// Parses a Go `crypto/tls` identifier, with or without the `tls.` prefix.
    pub fn from_go_ident(ident: &str) -> Group {
        match ident.strip_prefix("tls.").unwrap_or(ident) {
            "X25519" => Group::X25519,
            "CurveP256" => Group::P256,
            "CurveP384" => Group::P384,
            "CurveP521" => Group::P521,
            "X25519MLKEM768" => Group::X25519MlKem768,
            "SecP256r1MLKEM768" => Group::SecP256r1MlKem768,
            "SecP384r1MLKEM1024" => Group::SecP384r1MlKem1024,
            "MLKEM1024" => Group::Mlkem1024,
            other => Group::Unknown(other.to_string()),
        }
    }

    /// Parses an OpenSSL group name as used in `ssl_ecdh_curve` or `Groups`.
    /// Matching is case-insensitive. Prefixes such as `?` are handled by the caller.
    pub fn from_openssl_name(name: &str) -> Group {
        match name.to_ascii_lowercase().as_str() {
            "x25519" => Group::X25519,
            "prime256v1" | "secp256r1" | "p-256" => Group::P256,
            "secp384r1" | "p-384" => Group::P384,
            "secp521r1" | "p-521" => Group::P521,
            "x25519mlkem768" => Group::X25519MlKem768,
            "secp256r1mlkem768" => Group::SecP256r1MlKem768,
            "secp384r1mlkem1024" => Group::SecP384r1MlKem1024,
            "mlkem1024" => Group::Mlkem1024,
            _ => Group::Unknown(name.to_string()),
        }
    }

    /// Whether the group includes a post-quantum component (pure or hybrid).
    pub fn is_post_quantum(&self) -> bool {
        self.ml_kem_parameter_set().is_some()
    }

    /// The ML-KEM parameter set (768 or 1024) if the group uses ML-KEM.
    pub fn ml_kem_parameter_set(&self) -> Option<u16> {
        match self {
            Group::X25519MlKem768 | Group::SecP256r1MlKem768 => Some(768),
            Group::SecP384r1MlKem1024 | Group::Mlkem1024 => Some(1024),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_identifiers() {
        assert_eq!(
            Group::from_go_ident("tls.X25519MLKEM768"),
            Group::X25519MlKem768
        );
        assert_eq!(Group::from_go_ident("CurveP256"), Group::P256);
        assert_eq!(
            Group::from_go_ident("tls.SomethingNew"),
            Group::Unknown("SomethingNew".into())
        );
    }

    #[test]
    fn parses_openssl_names_case_insensitively() {
        assert_eq!(
            Group::from_openssl_name("X25519MLKEM768"),
            Group::X25519MlKem768
        );
        assert_eq!(Group::from_openssl_name("prime256v1"), Group::P256);
        assert_eq!(Group::from_openssl_name("P-384"), Group::P384);
    }

    #[test]
    fn classifies_post_quantum_groups() {
        assert!(Group::X25519MlKem768.is_post_quantum());
        assert_eq!(Group::SecP384r1MlKem1024.ml_kem_parameter_set(), Some(1024));
        assert!(!Group::X25519.is_post_quantum());
        assert!(!Group::Unknown("x".into()).is_post_quantum());
    }
}
