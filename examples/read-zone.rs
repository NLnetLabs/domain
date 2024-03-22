//! Reads a zone file.

use std::process::exit;

use domain::zonefile::inplace::Entry;

fn main() {
    use domain::zonefile::inplace::Zonefile;
    use std::env;
    use std::fs::File;
    use std::time::SystemTime;

    let mut args = env::args();
    let prog_name = args.next().unwrap(); // SAFETY: O/S always passes our name as the first argument.
    let zone_files: Vec<_> = args.collect();

    if zone_files.is_empty() {
        eprintln!("Usage: {} <path/to/zonefile/to/read> [<more>, <zone>, <files>, <to>, <read>, ...]", prog_name);
        exit(2);
    }

    for zone_file in zone_files {
        print!("Processing {}: ", zone_file);
        let start = SystemTime::now();
        let mut reader =
            Zonefile::load(&mut File::open(&zone_file).unwrap()).unwrap();
        println!(
            "Data loaded ({:.03}s).",
            start.elapsed().unwrap().as_secs_f32()
        );

        let mut i = 0;
        let mut last_entry = None;
        loop {
            match reader.next_entry() {
                Ok(entry) if entry.is_some() => {
                    last_entry = entry;
                }
                Ok(_) => break, // EOF
                Err(err) => {
                    eprintln!(
                        "\nAn error occurred while reading {zone_file}:"
                    );
                    eprintln!("  Error: {err}");
                    if let Some(entry) = &last_entry {
                        if let Entry::Record(record) = &entry {
                            // let record = record.unwrap().into_record::<ZoneRecordData<_, ParsedDname<_>>>().unwrap().unwrap();
                            eprintln!(
                                "\nThe last record read was:\n{record}."
                            );
                        } else {
                            eprintln!("\nThe last record read was:\n{last_entry:#?}.");
                        }
                        eprintln!("\nTry commenting out the line after that record with a leading ; (semi-colon) character.")
                    }
                    exit(1);
                }
            }
            i += 1;
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
