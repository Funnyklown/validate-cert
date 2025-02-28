use clap::Arg;
use clap::Command;
use der::{Decode, DecodePem};
use std::fs;
use std::path::PathBuf;
use x509_cert::{Certificate, certificate::CertificateInner};
use x509_parser::prelude::FromDer;
use x509_parser::prelude::KeyUsage;

// validate-cert -format DER|PEM myRCAcertfile

fn main() -> anyhow::Result<()> {
    let matches = Command::new("validate-cert")
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .required(true)
                .num_args(1)
                .value_parser(["DER", "PEM"])
                .help("This should be either DER or PEM."),
        )
        .arg(
            Arg::new("cert")
                .num_args(0..=10)
                .required(true)
                .help("This should be the certificate we wish to validate."),
        )
        .get_matches();

    let cert_paths = matches.get_many::<String>("cert").unwrap();

    if let Some(format) = matches.get_one::<String>("format") {
        match format.as_str() {
            "DER" => {
                for cert_path in cert_paths {
                    let cert = read_der(PathBuf::from(cert_path.to_string()))?;
                    println!("Subject: {}", cert.tbs_certificate.subject);
                    println!("Issuer: {}", cert.tbs_certificate.issuer);
                    check_key_usage(&cert)?;
                }
            }
            "PEM" => {
                for cert_path in cert_paths {
                    let cert = read_pem(PathBuf::from(cert_path.to_string()))?;
                    println!("Subject: {}", cert.tbs_certificate.subject);
                    println!("Issuer: {}", cert.tbs_certificate.issuer);
                    check_key_usage(&cert)?;
                }
            }
            _ => unreachable!(),
        };
    }

    Ok(())
}

fn check_key_usage(cert: &Certificate) -> anyhow::Result<()> {
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let key_usage = KeyUsage::from_der(&ext.extn_value.as_bytes())?;

            println!("Key Usage: {}", key_usage.1);
            return Ok(());
        }
        println!("Key Usage extension not found.");
    } else {
        println!("No extensions found in the certificate.");
    }
    //TODO! add logic to check if key usage is correct for the scope 
    Ok(())
}

fn check_expiration(cert: &Certificate) -> anyhow::Result<()> {
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
    let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();

    

    if 

    Ok(())
}

fn read_der(cert_path: PathBuf) -> anyhow::Result<CertificateInner> {
    let data = fs::read_to_string(cert_path)?;
    let cert = Certificate::from_der(data.as_bytes())?;

    Ok(cert)
}

fn read_pem(cert_path: PathBuf) -> anyhow::Result<CertificateInner> {
    let data = fs::read_to_string(cert_path)?;
    let cert = Certificate::from_pem(data.as_bytes())?;

    Ok(cert)
}
