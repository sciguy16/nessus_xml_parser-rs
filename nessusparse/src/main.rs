// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use clap::Clap;
use nessus_xml_parser::NessusScan;
use std::fs::read;

fn main() {
    let opts = Opts::parse();

    let xml = read(opts.file).unwrap();
    let xml = String::from_utf8_lossy(&xml);

    let nessus = NessusScan::parse(&xml);

    println!("nessus: {:?}", nessus);
}


#[derive(Clap)]
struct Opts {
	#[clap(short, long)]
	file: String,
}