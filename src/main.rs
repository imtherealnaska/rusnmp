use anyhow::Result;
use clap::Parser;
use futures::future::join_all;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
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

        #[clap(short, long, required = true)]
        target: String,

        #[clap(short, long, default_value_t = 0)]
        non_repeaters: i32,

        #[clap(short, long, default_value_t = 10)]
        max_repititions: i32,

        #[clap(required = true , num_args = 1..)]
        oids: Vec<String>,
    },
    BulkWalk {
        #[clap(short, long, required = true)]
        community: String,

        #[clap(short, long, required = true)]
        target: String,

        #[clap(short, long, default_value_t = 20)]
        max_repetitions: i32,

        #[clap(required = true)]
        oid: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = Manager::new();

    let multip_progress = MultiProgress::new();
    let main_pb = multip_progress.add(ProgressBar::new(0));
    main_pb.set_style(ProgressStyle::default_bar().template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos/len} ({percent}%)",
    )?);

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

            println!("SUccess found {} results", varbinds.len());

            for varbind in varbinds {
                print_varbind(&varbind);
            }
        }
        Command::BulkWalk {
            community,
            target,
            max_repetitions,
            oid,
        } => {
            println!(
                "--- Starting BULK WALK for {} (MR: {}) ---",
                target, max_repetitions
            );

            let varbinds = manager
                .bulk_walk(&target, &community, &oid, max_repetitions)
                .await?;

            println!("\n--- Success  (Found {} results) ---", varbinds.len());
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
