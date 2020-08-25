//! Various utility functions.

use std::io;
use std::fs::File;
use std::path::Path;


//------------ Functions -----------------------------------------------------

pub fn save<P: AsRef<Path>>(path: P, content: &str) -> Result<(), io::Error> {
    let mut file = File::create(path)?;
    io::Write::write_all(&mut file, content.as_bytes())
}

