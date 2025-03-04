use clap::{Arg, Command};
use colored::Colorize;
use std::fs;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OidRegistry;
use x509_parser::pem::{self, Pem};
use x509_parser::prelude::FromDer;

mod checks;
mod crl;

use checks::*;
use crl::*;

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
            check_sign_manual(cert, cert)?;
        } else {
            check_sign(cert, issuer.unwrap(), &registry)?;
            check_sign_manual(cert, issuer.unwrap())?;
        }

        //If we're last, we have to be a leaf
        check_key_usage(cert, is_leaf)?;
        check_expiration(cert)?;

        check_basic_constraints(cert, is_leaf)?;

        // Roots don't have CRLs for obvious reasons
        if issuer.is_some() {
            check_crl(cert, issuer.unwrap())?;
            check_ocsp(cert)?;
        }

        println!("------------------------------------------------------------");
    }

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
        truncate(
            &hex::encode(&cert.public_key().subject_public_key.data),
            100
        )
    );
    Ok(())
}

pub fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let mut truncated = s.chars().take(max_len).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}
