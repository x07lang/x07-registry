use serde::Serialize;

#[derive(Debug, Serialize)]
struct AdminError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct AdminResponse<T> {
    ok: bool,
    command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<AdminError>,
}

fn print_usage() {
    eprintln!(
        "Usage:\n  x07-registry-admin backfill-pkg-signatures [--write]\n\n\
Backfills missing ed25519 signatures for existing package_versions rows.\n\
By default this is a dry-run; pass --write to apply updates."
    );
}

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        std::process::exit(if args.is_empty() { 2 } else { 0 });
    }

    let cmd = args.remove(0);
    if cmd != "backfill-pkg-signatures" {
        eprintln!("ERROR: unknown command: {cmd}");
        print_usage();
        std::process::exit(2);
    }

    let mut dry_run = true;
    for flag in args {
        match flag.as_str() {
            "--write" => dry_run = false,
            other => {
                eprintln!("ERROR: unknown flag: {other}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    let cfg = x07_registry::RegistryConfig::from_env();
    let signing = match cfg.pkg_signing.clone() {
        Some(v) => v,
        None => {
            let resp: AdminResponse<()> = AdminResponse {
                ok: false,
                command: "backfill.pkg_signatures",
                result: None,
                error: Some(AdminError {
                    code: "X07REG_ADMIN_SIGNING_DISABLED",
                    message: "package signing is not enabled (hint: set X07_REGISTRY_PKG_SIGNING_ED25519_SECRET_B64 and X07_REGISTRY_PKG_SIGNING_KEY_ID before running this backfill)".to_string(),
                }),
            };
            println!("{}", serde_json::to_string_pretty(&resp).expect("serialize"));
            std::process::exit(2);
        }
    };

    let db = x07_registry::connect_db(&cfg).await;
    let report = match x07_registry::backfill_pkg_signatures(&db, &signing, dry_run).await {
        Ok(v) => v,
        Err(message) => {
            let resp: AdminResponse<()> = AdminResponse {
                ok: false,
                command: "backfill.pkg_signatures",
                result: None,
                error: Some(AdminError {
                    code: "X07REG_ADMIN_BACKFILL_FAILED",
                    message,
                }),
            };
            println!("{}", serde_json::to_string_pretty(&resp).expect("serialize"));
            std::process::exit(1);
        }
    };

    let resp = AdminResponse {
        ok: true,
        command: "backfill.pkg_signatures",
        result: Some(report),
        error: None,
    };
    println!("{}", serde_json::to_string_pretty(&resp).expect("serialize"));
}

