//! Reads a zone file.

extern crate domain;

use std::env;
use domain::master::reader::Reader;


fn main() {
    for arg in env::args().skip(1) {
        print!("{}: ", arg);
        let reader = Reader::open(arg).unwrap();
        let mut items = 0;
        let mut err = false;
        for item in reader {
            match item {
                Ok(_) => {
                    items += 1;
                }
                Err(e) => {
                    err = true;
                    print!("\n    {:?}", e)
                }
            }
        }
        if err {
            println!("");
        }
        else {
            println!("{} items.", items)
        }
    }
}
