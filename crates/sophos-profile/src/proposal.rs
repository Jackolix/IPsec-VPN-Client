//! Parse the strongSwan proposal strings a Sophos `.scx` carries verbatim.
//!
//! Sophos Connect is itself built on strongSwan, so its profiles ship the
//! proposal in strongSwan's own syntax — `aes256-sha2_256-modp2048`. We still
//! parse it into the internal model rather than passing the string through, so
//! that an unknown token is refused here instead of being handed to charon,
//! and so the UI can show and edit the algorithms like it does for any other
//! profile.

use crate::error::ImportError;
use vpn_core::{DhGroup, EncAlg, IntegAlg, PrfAlg};

/// One parsed proposal. `dh` is optional because an ESP proposal without a
/// group simply means no PFS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proposal {
    pub enc: EncAlg,
    pub integ: IntegAlg,
    pub dh: Option<DhGroup>,
}

impl Proposal {
    /// The PRF to negotiate. strongSwan proposals may name one explicitly;
    /// Sophos's never do, and the conventional choice is the hash that backs
    /// the integrity algorithm.
    pub fn prf(&self, explicit: Option<PrfAlg>) -> PrfAlg {
        explicit.unwrap_or(match self.integ {
            IntegAlg::Sha1 => PrfAlg::Sha1,
            IntegAlg::Sha256 => PrfAlg::Sha256,
            IntegAlg::Sha384 => PrfAlg::Sha384,
            IntegAlg::Sha512 => PrfAlg::Sha512,
        })
    }
}

fn enc_token(t: &str) -> Option<EncAlg> {
    Some(match t {
        "aes128" | "aes" => EncAlg::Aes128,
        "aes192" => EncAlg::Aes192,
        "aes256" => EncAlg::Aes256,
        _ => return None,
    })
}

/// Integrity algorithms, under both spellings strongSwan accepts
/// (`sha256` and the `sha2_256` form Sophos writes).
fn integ_token(t: &str) -> Option<IntegAlg> {
    Some(match t {
        "sha1" | "sha" | "hmac_sha1" => IntegAlg::Sha1,
        "sha256" | "sha2_256" | "hmac_sha2_256" => IntegAlg::Sha256,
        "sha384" | "sha2_384" | "hmac_sha2_384" => IntegAlg::Sha384,
        "sha512" | "sha2_512" | "hmac_sha2_512" => IntegAlg::Sha512,
        _ => return None,
    })
}

fn prf_token(t: &str) -> Option<PrfAlg> {
    Some(match t {
        "prfsha1" => PrfAlg::Sha1,
        "prfsha256" => PrfAlg::Sha256,
        "prfsha384" => PrfAlg::Sha384,
        "prfsha512" => PrfAlg::Sha512,
        _ => return None,
    })
}

fn dh_token(t: &str) -> Option<DhGroup> {
    Some(match t {
        "modp1024" => DhGroup::Modp1024,
        "modp1536" => DhGroup::Modp1536,
        "modp2048" => DhGroup::Modp2048,
        "modp3072" => DhGroup::Modp3072,
        "modp4096" => DhGroup::Modp4096,
        "ecp256" => DhGroup::Ecp256,
        "ecp384" => DhGroup::Ecp384,
        _ => return None,
    })
}

/// Parse one proposal string. Returns the proposal and any explicit PRF.
///
/// A token we do not recognise is an error rather than something to skip: a
/// proposal is a negotiation offer, and quietly dropping a term from it means
/// negotiating something other than what the gateway's admin configured.
pub fn parse(
    input: &str,
    context: &'static str,
) -> Result<(Proposal, Option<PrfAlg>), ImportError> {
    let mut enc = None;
    let mut integ = None;
    let mut prf = None;
    let mut dh = None;

    for raw in input.split('-') {
        let token = raw.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        // Order matters only in that each token belongs to exactly one
        // category; a repeat means the profile offers a choice we cannot
        // represent, so keep the first and let the caller warn.
        if let Some(v) = enc_token(&token) {
            enc.get_or_insert(v);
        } else if let Some(v) = prf_token(&token) {
            prf.get_or_insert(v);
        } else if let Some(v) = integ_token(&token) {
            integ.get_or_insert(v);
        } else if let Some(v) = dh_token(&token) {
            dh.get_or_insert(v);
        } else {
            return Err(ImportError::UnknownAlgorithm { context, token });
        }
    }

    Ok((
        Proposal {
            enc: enc.ok_or(ImportError::UnknownAlgorithm {
                context,
                token: "<no encryption algorithm>".to_string(),
            })?,
            integ: integ.ok_or(ImportError::UnknownAlgorithm {
                context,
                token: "<no integrity algorithm>".to_string(),
            })?,
            dh,
        },
        prf,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_sophos_writes() {
        let (p, prf) = parse("aes256-sha2_256-modp2048", "ike").unwrap();
        assert_eq!(p.enc, EncAlg::Aes256);
        assert_eq!(p.integ, IntegAlg::Sha256);
        assert_eq!(p.dh, Some(DhGroup::Modp2048));
        assert_eq!(prf, None);
        assert_eq!(p.prf(prf), PrfAlg::Sha256);
    }

    #[test]
    fn accepts_strongswan_spelling_and_explicit_prf() {
        let (p, prf) = parse("aes128-sha384-prfsha384-ecp384", "ike").unwrap();
        assert_eq!(p.enc, EncAlg::Aes128);
        assert_eq!(p.integ, IntegAlg::Sha384);
        assert_eq!(prf, Some(PrfAlg::Sha384));
        assert_eq!(p.dh, Some(DhGroup::Ecp384));
    }

    #[test]
    fn esp_proposal_without_a_group_means_no_pfs() {
        let (p, _) = parse("aes256-sha2_256", "esp").unwrap();
        assert_eq!(p.dh, None);
    }

    /// AEAD ciphers have no separate integrity algorithm and the model cannot
    /// express them yet — better to refuse than to negotiate something else.
    #[test]
    fn rejects_unknown_token() {
        let err = parse("aes256gcm16-ecp256", "ike").unwrap_err();
        assert!(matches!(err, ImportError::UnknownAlgorithm { .. }));
    }

    #[test]
    fn rejects_proposal_without_integrity() {
        assert!(parse("aes256-modp2048", "ike").is_err());
    }
}
