use clap::{Arg, Command};
use colored::{ColoredString, Colorize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OidRegistry;
use x509_parser::pem::{self, Pem};
use x509_parser::prelude::{DistributionPointName, FromDer, GeneralName, ParsedExtension};
use x509_parser::revocation_list::CertificateRevocationList;

fn main() -> anyhow::Result<()> {
    let matches =
        Command::new("validate-cert")
            .arg(
                Arg::new("format")
                    .short('f')
                    .long("format")
                    .required(true)
                    .num_args(1)
                    .value_parser(["DER", "PEM"])
                    .help("This should be either DER or PEM."),
            )
            .arg(Arg::new("cert").num_args(0..=10).required(true).help(
                "This should be the certificate or chain of certificates we wish to validate.",
            ))
            .get_matches();

    let cert_paths = matches.get_many::<String>("cert").unwrap();

    //We parse everything first to keep certs in scope and prevent problems later
    //See https://docs.rs/x509-parser/0.17.0/x509_parser/index.html
    // "It is written in pure Rust, fast, and makes extensive use of zero-copy."
    // Dog impl, very shit
    let mut datas: Vec<Vec<u8>> = Vec::new();
    let mut pems: Vec<Pem> = Vec::new();
    let mut certs: Vec<X509Certificate<'_>> = Vec::new();

    for path in cert_paths.rev() {
        datas.push(fs::read(path)?);
    }

    if let Some(format) = matches.get_one::<String>("format") {
        match format.as_str() {
            "DER" => {
                for data in &datas {
                    certs.push(X509Certificate::from_der(data.as_slice())?.1);
                }
            }
            "PEM" => {
                for data in &datas {
                    let pem = pem::parse_x509_pem(data.as_slice())?.1;
                    pems.push(pem);
                }

                for pem in &pems {
                    let cert = pem.parse_x509()?;
                    certs.push(cert);
                }
            }
            _ => unreachable!("Unrecognized certificate format."),
        };
    }

    println!("------------------------------------------------------------");

    // Used to translate oid codes to readable strings
    let registry = OidRegistry::default().with_all_crypto();

    for (index, cert) in certs.iter().enumerate() {
        let issuer = if index == 0 {
            None
        } else {
            certs.get(index - 1)
        };

        let is_leaf = index == certs.len() - 1;

        if issuer.is_none() {
            check_identity(cert, cert)?;
        } else {
            check_identity(cert, issuer.unwrap())?;
        }

        print_pubkey(cert, &registry)?;

        //If we have no issuer, we have to be a root
        if issuer.is_none() {
            check_sign(cert, cert, &registry)?;
        } else {
            check_sign(cert, issuer.unwrap(), &registry)?;
        }

        //If we're last, we have to be a leaf
        check_key_usage(cert, is_leaf)?;
        check_expiration(cert)?;

        check_basic_constraints(cert, is_leaf)?;

        // Roots don't have CRLs for obvious reasons
        if issuer.is_some() {
            check_crl(cert, issuer.unwrap())?;
            check_ocsp(cert)?;

            check_sign_manual(&cert, &issuer.unwrap())?;
        }

       

        println!("------------------------------------------------------------");
    }
    
    Ok(())
}

fn check_sign_manual(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> anyhow::Result<()> {
    let sign_algo = cert.signature_algorithm.parameters().unwrap();

    println!("sign: {:#?}", sign_algo);
    Ok(())
}

/// Should be checking ocsp, but as let's encrypt is sunsetting the entire protocol as of may 2025
/// no rust crate has been built to verify an obsolete protocol.
/// see: https://letsencrypt.org/2024/12/05/ending-ocsp/
///
/// Currently only retrieves and prints the url of the ocsp responder.
fn check_ocsp(cert: &X509Certificate<'_>) -> anyhow::Result<()> {
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

/// Checks whether the given certificate's crl marks it as revoked using helper functions.
fn check_crl(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> anyhow::Result<()> {
    let mut crl = None;
    let mut valid = "OK".green().bold();

    for ext in cert.extensions_map()?.values() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for point in points.iter() {
                if let Some(DistributionPointName::FullName(general_names)) =
                    &point.distribution_point
                {
                    for general_name in general_names {
                        if let GeneralName::URI(uri) = general_name {
                            crl = Some(uri);

                            valid = get_crl_state(uri, cert, issuer)
                                .unwrap_or("KO (Check Failed)".red().bold());
                        }
                    }
                }
            }
        }
    }

    if crl.is_none() {
        valid = "KO".red().bold();
    }

    println!(
        "{} {} {:>5}",
        "CRL:".white().bold(),
        if crl.is_some() { crl.unwrap() } else { "" },
        valid
    );
    Ok(())
}

/// Retrieves the crl from cache if it exists, or fetches it if not available.
/// Returns the state of the certificate passed as argument:
/// OK / KO (Revoked) / KO (Bad Signature)
fn get_crl_state(
    uri: &str,
    cert: &X509Certificate,
    issuer: &X509Certificate,
) -> anyhow::Result<ColoredString> {
    let filename = uri.split('/').last().unwrap();
    let cache_folder = PathBuf::from("crl_cache");
    let filepath = cache_folder.join(filename);

    if !cache_folder.exists() {
        fs::create_dir(&cache_folder)?;
    }

    let data = match fs::read(&filepath) {
        Ok(data) => data,
        Err(_) => {
            let data = reqwest::blocking::get(uri)?.bytes()?.to_vec();
            fs::write(&filepath, &data)?;
            data
        }
    };

    let (_, crl) = CertificateRevocationList::from_der(&data)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // If the cache is stale, we need to fetch the new version of the crl.
    if now < crl.last_update().timestamp()
        || now > crl.next_update().unwrap_or(crl.last_update()).timestamp()
    {
        let data = reqwest::blocking::get(uri)?.bytes()?.to_vec();
        fs::write(&filepath, &data)?;
        let (_, crl) = CertificateRevocationList::from_der(&data)?;
        return Ok(validate_crl(&crl, cert, issuer));
    }

    Ok(validate_crl(&crl, cert, issuer))
}

/// Helper function, given a crl and a certificate child/issuer chain, returns the state of the certificate:
/// OK / KO (Bad Signature) / KO (Revoked)
fn validate_crl(
    crl: &CertificateRevocationList,
    cert: &X509Certificate,
    issuer: &X509Certificate,
) -> ColoredString {
    if crl.verify_signature(issuer.public_key()).is_err() {
        return "KO (Bad Signature)".bold().red();
    }
    if crl
        .iter_revoked_certificates()
        .any(|c| c.serial() == &cert.serial)
    {
        return "KO (Revoked)".bold().red();
    }

    "OK".bold().green()
}

/// Checks whether the BasicConstraints of the certificate are suspicious for the given use case.
fn check_basic_constraints(cert: &X509Certificate, is_leaf: bool) -> anyhow::Result<()> {
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

/// Prints the public key of the given certificate with nice formatting.
/// Uses the oid registry to map oid numbers to names.
fn print_pubkey(cert: &X509Certificate, registry: &OidRegistry) -> anyhow::Result<()> {
    let oid_name = registry
        .get(cert.public_key().algorithm.oid())
        .map(|entry| entry.sn().to_string())
        .unwrap_or_else(|| cert.public_key().algorithm.oid().to_id_string());

    let pubkey_str = format!("Public Key ({}):", oid_name).white().bold();

    println!(
        "{} {}",
        pubkey_str,
        hex::encode(&cert.public_key().subject_public_key.data),
    );
    Ok(())
}

/// Checks whether the certificate's subject & issuer are valid based on the issuer certificate.
fn check_identity(cert: &X509Certificate, issuer: &X509Certificate) -> anyhow::Result<()> {
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
fn check_sign(
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
        hex::encode(&cert.signature_value.data),
        valid
    );

    Ok(())
}

/// Checks whether the key usages of the certificate are suspicious.
fn check_key_usage(cert: &X509Certificate, is_leaf: bool) -> anyhow::Result<()> {
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
fn check_expiration(cert: &X509Certificate) -> anyhow::Result<()> {
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
