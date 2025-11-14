use std::env::var;

use anyhow::Result;
use clap::Parser;
use futures::future::join_all;
use rusnmp::{
    manager::Manager,
    snmp::pdu::{ObjectSyntax, VarBind},
};

#[derive(Parser, Debug)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    Get {
        #[clap(short, long, required = true)]
        community: String,
        #[clap(short, long, required = true)]
        oid: String,
        #[clap( required = true , num_args = 1..)]
        targets: Vec<String>,
    },
    Walk {
        #[clap(short, long, required = true)]
        community: String,
        #[clap(short, long, required = true)]
        oid: String,
        #[clap( required = true , num_args = 1..)]
        targets: Vec<String>,
    },
    Bulk {
        #[clap(short, long, required = true)]
        community: String,

        #[clap(short, long, default_value_t = 0)]
        non_repeaters: i32,

        #[clap(short, long, default_value_t = 10)]
        max_repititions: i32,

        #[clap(short, long, required = true)]
        target: Vec<String>,

        #[clap(short, long, num_args = 1..)]
        oids: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = Manager::new();

    match cli.command {
        Command::Get {
            targets,
            community,
            oid,
        } => {
            println!("Starting GET for {} targets", targets.len());

            let futures = targets.iter().map(|target| {
                println!("---spawining task for {}", target);
                manager.get(target, &community, &oid)
            });

            let results = join_all(futures).await;

            for (target, result) in targets.iter().zip(results) {
                println!("\n--- Result for {} ---", target);
                match result {
                    Ok(varbind) => print_varbind(&varbind),
                    Err(e) => println!("Error: {}", e),
                }
            }
        }
        Command::Walk {
            targets,
            community,
            oid,
        } => {
            let futures = targets.iter().map(|target| {
                println!("- Spawning task for {}", target);
                manager.walk(target, &community, &oid)
            });

            // Run all tasks concurrently
            let results = join_all(futures).await;

            // Loop through the results and print them
            for (target, result) in targets.iter().zip(results) {
                println!("\n--- Result for {} ---", target);
                match result {
                    Ok(varbinds) => {
                        println!("Success! (Found {} results)", varbinds.len());
                        for varbind in varbinds {
                            print_varbind(&varbind);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
        }
        Command::Bulk {
            community,
            non_repeaters,
            max_repititions,
            target,
            oids,
        } => {
            println!(
                " --- starting getbulk for {} (NR : {} , MR :{})----",
                target, non_repeaters, max_repititions
            );

            let oid_strs: Vec<&str> = oids.iter().map(AsRef::as_ref).collect();

            let varbinds = manager
                .get_bulk(
                    &target,
                    &community,
                    non_repeaters,
                    max_repititions,
                    &oid_strs,
                )
                .await?;

            println!("SUccess found {} results" , varbinds.len());

            for varbind in varbinds {
                print_varbind(&varbind);
            }
        }
    }
    Ok(())
}

fn print_varbind(varbind: &VarBind) {
    let oid_str = varbind
        .oid
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".");

    print!("OID: {} | Value: ", oid_str);

    match &varbind.value {
        ObjectSyntax::OctetString(val) => {
            println!("{}", String::from_utf8_lossy(val));
        }
        ObjectSyntax::Integer(val) => println!("{}", val),
        ObjectSyntax::Counter32(val) => println!("{}", val),
        ObjectSyntax::Gauge32(val) => println!("{}", val),
        ObjectSyntax::TimeTicks(val) => println!("{}", val),
        ObjectSyntax::Counter64(val) => println!("{}", val),
        other => println!("{:?}", other),
    }
}
