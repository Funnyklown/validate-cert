use colored::Colorize;
use num_bigint::BigUint;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OidRegistry;
use x509_parser::prelude::{GeneralName, ParsedExtension};
use x509_parser::public_key::PublicKey;
/// Should be checking ocsp, but as let's encrypt is sunsetting the entire protocol as of may 2025
/// no rust crate has been built to verify an obsolete protocol.
/// see: https://letsencrypt.org/2024/12/05/ending-ocsp/
///
/// Currently only retrieves and prints the url of the ocsp responder.
pub fn check_ocsp(cert: &X509Certificate<'_>) -> anyhow::Result<()> {
    let mut ocsp_url = None;

    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for access_desc in aia.accessdescs.clone() {
                if let GeneralName::URI(uri) = &access_desc.access_location {
                    ocsp_url = Some(uri.to_string());
                    break;
                }
            }
        }
    }

    if let Some(url) = ocsp_url {
        println!("{} {}", "OCSP:".white().bold(), url);
    }

    Ok(())
}

/// Checks whether the certificate's subject & issuer are valid based on the issuer certificate.
pub fn check_identity(cert: &X509Certificate, issuer: &X509Certificate) -> anyhow::Result<()> {
    let mut valid = "OK".bold().green();
    if cert.public_key() == issuer.public_key() {
        if cert.tbs_certificate.subject != cert.tbs_certificate.issuer {
            valid = "KO".bold().red();
        }
    } else if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        valid = "KO".bold().red();
    }

    println!(
        "{} {} {:>5}",
        "Subject:".white().bold(),
        cert.tbs_certificate.subject,
        valid
    );
    println!(
        "{}  {} {:>5}",
        "Issuer:".white().bold(),
        cert.tbs_certificate.issuer,
        valid
    );

    Ok(())
}

/// Checks the signature of the current certificate using the issuer's public key.
pub fn check_sign(
    cert: &X509Certificate,
    issuer: &X509Certificate,
    registry: &OidRegistry,
) -> anyhow::Result<()> {
    let valid = if cert.verify_signature(Some(issuer.public_key())).is_err() {
        "KO".bold().red()
    } else if cert.verify_signature(None).is_ok() {
        "OK (Self-Signed)".bold().green()
    } else {
        "OK".bold().green()
    };

    let oid_name = registry
        .get(cert.signature_algorithm.oid())
        .map(|entry| entry.sn().to_string())
        .unwrap_or_else(|| cert.signature_algorithm.oid().to_id_string());

    let signature_str = format!("Signature ({}):", oid_name).white().bold();

    println!(
        "{} {} {:>5}",
        signature_str,
        crate::truncate(&hex::encode(&cert.signature_value.data), 100),
        valid
    );

    Ok(())
}

/// Checks whether the key usages of the certificate are suspicious.
pub fn check_key_usage(cert: &X509Certificate, is_leaf: bool) -> anyhow::Result<()> {
    if let Some(key_usage) = cert.key_usage()? {
        let mut valid = "OK".bold().green();

        if is_leaf || !cert.is_ca() {
            //If the cert has these, it is very sus
            if key_usage.value.crl_sign() || key_usage.value.key_cert_sign() {
                valid = "KO".bold().red();
            }
        }

        println!(
            "{} {} {:>5}",
            "Key Usage:".white().bold(),
            key_usage.value,
            valid
        );

        return Ok(());
    } else {
        println!("Key usage extension not found.");
    }

    Ok(())
}

/// Checks whether the certificate is expired.
pub fn check_expiration(cert: &X509Certificate) -> anyhow::Result<()> {
    let valid = if cert.validity.is_valid() {
        "OK".bold().green()
    } else {
        "KO".bold().red()
    };

    println!(
        "{} {} {:>5}",
        "Not Before:".white().bold(),
        cert.tbs_certificate.validity.not_before,
        valid
    );
    println!(
        "{} {} {:>5}",
        "Not After:".white().bold(),
        cert.tbs_certificate.validity.not_after,
        valid
    );

    Ok(())
}

/// Checks whether the BasicConstraints of the certificate are suspicious for the given use case.
pub fn check_basic_constraints(cert: &X509Certificate, is_leaf: bool) -> anyhow::Result<()> {
    let mut valid = "OK".green().bold();

    match cert.basic_constraints()? {
        Some(bc) => {
            // A leaf should not be a ca, conversely, a ca should never be a leaf.
            if (is_leaf && bc.value.ca) || (!is_leaf && !bc.value.ca) {
                valid = "KO".red().bold();
            }

            // If it exists, we print the path length constraint, be do no further checks
            // Room for improvement here.
            if bc.value.ca {
                if let Some(path_len) = bc.value.path_len_constraint {
                    println!("{} {}", "Path Length Constraint:".white().bold(), path_len);
                }
            }
        }
        None => {
            if !is_leaf {
                // Missing BasicConstraints is acceptable for leaf certs, but not for CA certs.
                valid = "KO".red().bold();
            }
        }
    }

    println!("{} {:>5}", "Basic Constraints:".white().bold(), valid);

    Ok(())
}

/// Manually checks the signature of the given certificate without using cryptography crates.
/// Only works with RSA and Elliptic Curves public key algorithms.
/// Assumes SHA256 is used for hashing.
pub fn check_sign_manual(
    cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> anyhow::Result<()> {
    let mut valid = "OK".green().bold();

    // fixed value as per https://www.rfc-editor.org/rfc/rfc3447#page-43
    let sha256_header = hex::decode("3031300d060960864801650304020105000420")?;

    let digest = ring::digest::digest(&ring::digest::SHA256, cert.tbs_certificate.as_ref());
    let hash = digest.as_ref();

    // expected = H(sha256_header) || H(cert)
    let mut expected = Vec::new();
    expected.extend_from_slice(&sha256_header);
    expected.extend_from_slice(hash);

    match issuer.public_key().parsed()? {
        PublicKey::RSA(rsa_pubkey) => {
            let s = BigUint::from_bytes_be(&cert.signature_value.data);
            let e = BigUint::from_bytes_be(rsa_pubkey.exponent);
            let n = BigUint::from_bytes_be(rsa_pubkey.modulus);

            // s^e[n]
            let padded_result = s.modpow(&e, &n).to_bytes_be();
            let res_slice = padded_result.as_slice();

            // remove padding as per https://www.rfc-editor.org/rfc/rfc2313.html
            // this is a bit of a hack we just look for the 0x00 that has to appear
            // after the padding and read from there
            let depadded_result = res_slice
                .iter()
                .position(|&b| b == 0x00)
                .map(|pos| &res_slice[pos + 1..])
                .unwrap_or(&[]);

            // if the depadded result is not H(sha256_header) || H(cert)
            // the signature has to be problematic
            if depadded_result != expected {
                valid = "KO".red().bold();
            }
        }
        PublicKey::EC(_ec_point) => {
            // unimplemented, X509_parser is still in development,
            // does not expose the required elements (r,s..)
            valid = "KO".red().bold();
        }
        _ => unreachable!("Unsupported Public Key Algorithm."),
    }

    println!(
        "{} {:>5}",
        "Manual Signature Verification:".bold().white(),
        valid
    );

    Ok(())
}
