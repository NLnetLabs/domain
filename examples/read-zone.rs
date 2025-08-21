//! Reads a zone file.

use std::fs::File;
use std::process::exit;
use std::time::SystemTime;
use std::{env, io::BufReader};

use domain::new::zonefile::simple::ZonefileScanner;

fn main() {
    let mut args = env::args();
    let prog_name = args.next().unwrap(); // SAFETY: O/S always passes our name as the first argument.
    let zone_files: Vec<_> = args.collect();

    if zone_files.is_empty() {
        eprintln!("Usage: {prog_name} <path/to/zonefile/to/read> [<more>, <zone>, <files>, <to>, <read>, ...]");
        exit(2);
    }

    for zone_file in zone_files {
        print!("Processing {zone_file}: ");
        let start = SystemTime::now();
        let file = BufReader::new(File::open(&zone_file).unwrap());
        let mut scanner = ZonefileScanner::new(file, None);

        let mut i = 0;
        while let Some(entry) = scanner.scan().transpose() {
            i += 1;
            if let Err(err) = entry {
                eprintln!("Could not parse {zone_file}: {err}");
                exit(1);
            }

            if i % 100_000_000 == 0 {
                println!(
                    "Processed {}M records ({:.03}s)",
                    i / 1_000_000,
                    start.elapsed().unwrap().as_secs_f32()
                );
            }
        }

        println!(
            "Complete with {} records ({:.03}s)\n",
            i,
            start.elapsed().unwrap().as_secs_f32()
        );
    }
}
