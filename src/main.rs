use anyhow::Result;
use clap::Parser;
use rusnmp::{manager::Manager, snmp::pdu::ObjectSyntax};

#[derive(Parser, Debug)]
#[clap(version = "1.0")]
struct Cli {
    #[clap(required = true)]
    target: String,
    #[clap(required = true)]
    community: String,
    #[clap(required = true)]
    oid: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = Manager::new();

    println!(
        "Sending GetRequest to {} with community '{}' for OID {}...",
        cli.target, cli.community, cli.oid
    );

    let varbind = manager.get(&cli.target, &cli.community, &cli.oid).await?;

    println!("\n--- Success! ---");
    println!(
        "OID: {}",
        varbind
            .oid
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    );

    match varbind.value {
        ObjectSyntax::OctetString(val) => {
            println!("Value: {}", String::from_utf8_lossy(&val));
        }
        ObjectSyntax::Integer(val) => {
            println!("Value: {}", val);
        }
        ObjectSyntax::Counter32(val) => {
            println!("Value: {}", val);
        }
        ObjectSyntax::Gauge32(val) => {
            println!("Value: {}", val);
        }
        ObjectSyntax::TimeTicks(val) => {
            println!("Value: {}", val);
        }
        ObjectSyntax::Counter64(val) => {
            println!("Value: {}", val);
        }
        other => {
            println!("Value: {:?}", other);
        }
    }

    Ok(())
}
