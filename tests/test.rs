// Copyright 2020 David Young
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nessus_xml_parser::*;

static NESSUS: &str = include_str!("nessus-02_v_unknown.xml");

#[test]
fn load_xml() {
    let n = NessusScan::parse(&NESSUS);

    dbg!(&n);

    //panic!();
}
