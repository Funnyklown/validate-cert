use colored::{ColoredString, Colorize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{DistributionPointName, FromDer, GeneralName, ParsedExtension};
use x509_parser::revocation_list::CertificateRevocationList;

/// Checks whether the given certificate's crl marks it as revoked using helper functions.
pub fn check_crl(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> anyhow::Result<()> {
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
pub fn get_crl_state(
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
pub fn validate_crl(
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
