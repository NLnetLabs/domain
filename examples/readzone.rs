//! Reads a zone file.

fn main() {
    use domain::zonefile::scan::Zonefile;
    use std::env;
    use std::fs::File;
    use std::time::SystemTime;

    for arg in env::args().skip(1) {
        print!("Processing {}: ", arg);
        let start = SystemTime::now();
        let mut zone = Zonefile::load(&mut File::open(arg).unwrap()).unwrap();
        println!(
            "Data loaded ({:.03}s).",
            start.elapsed().unwrap().as_secs_f32()
        );
        let mut i = 0;
        while let Some(_) = zone.next_entry().unwrap() {
            i += 1;
            if i % 100_000_000 == 0 {
                eprintln!(
                    "Processed {}M records ({:.03}s)",
                    i / 1_000_000,
                    start.elapsed().unwrap().as_secs_f32()
                );
            }
        }
        eprintln!(
            "Complete with {} records ({:.03}s)\n",
            i,
            start.elapsed().unwrap().as_secs_f32()
        );
    }
}
