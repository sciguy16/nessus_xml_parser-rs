# nessus_xml_parser
![Build](https://github.com/sciguy16/nessus_xml_parser-rs/workflows/Build/badge.svg?branch=master&event=push)
![Documentation](https://docs.rs/nessus_xml_parser/badge.svg)


Parse Nessus XML files for use in Rust projects. This has been tested on
a small sample of Nessus files, however
[the documentation](https://static.tenable.com/documentation/nessus_v2_file_format.pdf)
is full of typos and contradictions, so this may not work on all possible
Nessus files.
Please [report any issues](https://github.com/sciguy16/nessus_xml_parser-rs/issues)
with minimal examples of files that aren't properly parsed.


## Usage example
```rust
use nessus_xml_parser::NessusScan;
let xml = r#"
<?xml version="1.0" ?>
<NessusClientData_v2>
  ...
</NessusClientData_v2>
"#;
let nessus = NessusScan::parse(&xml).unwrap();
for host in nessus.hosts() {
	println!("Hostname: {}", host.name);
}
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
