use std::sync::Arc;

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

        #[clap(short, long, required = true)]
        oid: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let manager = Arc::new(Manager::new());
    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new(0)); // Main progress bar
    main_pb.set_style(ProgressStyle::default_bar().template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)",
    )?);

    let (results, targets) = match cli.command {
        Command::Get {
            community,
            oid,
            targets,
        } => {
            main_pb.set_length(targets.len() as u64);
            main_pb.set_message("Running GET");
            let mut tasks = Vec::new();

            for target in &targets {
                let task_pb = multi_progress.add(ProgressBar::new_spinner());
                task_pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .unwrap(),
                );
                task_pb.set_message(format!("GET: {}", target));

                let manager = Arc::clone(&manager);
                let community = community.clone();
                let oid = oid.clone();
                let target = target.clone();
                let main_pb = main_pb.clone();

                tasks.push(tokio::spawn(async move {
                    task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                    let result = manager
                        .get(&target, &community, &oid)
                        .await
                        .map(|vb| vec![vb]);
                    task_pb.finish_with_message(format!("GET: {}", target));
                    main_pb.inc(1);
                    result
                }));
            }
            (join_all(tasks).await, targets)
        }

        Command::Walk {
            community,
            oid,
            targets,
        } => {
            main_pb.set_length(targets.len() as u64);
            main_pb.set_message("Running WALK");
            let mut tasks = Vec::new();

            for target in &targets {
                // --- INDICATIF: Create spinner for each task ---
                let task_pb = multi_progress.add(ProgressBar::new_spinner());
                task_pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .unwrap(),
                );
                task_pb.set_message(format!("WALK: {}", target));

                let manager = Arc::clone(&manager);
                let community = community.clone();
                let oid = oid.clone();
                let target = target.clone();
                let main_pb = main_pb.clone();

                // --- NEW: Spawn a true tokio task ---
                tasks.push(tokio::spawn(async move {
                    task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                    let result = manager.walk(&target, &community, &oid).await;
                    task_pb.finish_with_message(format!("WALK: {}", target));
                    main_pb.inc(1);
                    result
                }));
            }
            (join_all(tasks).await, targets)
        }

        // --- Other commands (Bulk, BulkWalk) ---
        // We'll leave these as-is for now, they won't get progress bars
        // but they will still work.
        Command::Bulk {
            community,
            target,
            non_repeaters,
            max_repititions,
            oids,
        } => {
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
            println!("\n--- Success! (Found {} results) ---", varbinds.len());
            for varbind in varbinds {
                print_varbind(&varbind);
            }
            return Ok(()); // Exit early
        }
        Command::BulkWalk {
            community,
            target,
            max_repetitions,
            oid,
        } => {
            let varbinds = manager
                .bulk_walk(&target, &community, &oid, max_repetitions)
                .await?;
            println!("\n--- Success! (Found {} results) ---", varbinds.len());
            for varbind in varbinds {
                print_varbind(&varbind);
            }
            return Ok(()); // Exit early
        }
    };

    // --- INDICATIF: Clean up ---
    main_pb.finish_with_message("All tasks complete!");

    // 4. Print results
    println!("\n--- === All Results === ---");
    for (target, result) in targets.iter().zip(results) {
        println!("\n--- Result for {} ---", target);
        // The result from tokio::spawn is itself a Result
        match result {
            Ok(Ok(varbinds)) => {
                // Task succeeded, manager succeeded
                println!("Success! (Found {} results)", varbinds.len());
                for varbind in varbinds {
                    print_varbind(&varbind);
                }
            }
            Ok(Err(e)) => {
                // Task succeeded, manager returned an error
                println!("Error: {}", e);
            }
            Err(e) => {
                // Task itself panicked
                println!("Task Panicked: {}", e);
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
