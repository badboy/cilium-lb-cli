extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate bpf_map;

use std::io::Write;
use clap::{Arg, ArgMatches, App, AppSettings, SubCommand};

use bpf_map::Map;

error_chain! {
    foreign_links {
        Io(::std::io::Error);
    }
}

pub fn report_error(e: Error) {
    let _ = write!(::std::io::stderr(), "error:");
    let _ = writeln!(::std::io::stderr(), " {}", e);
    for e in e.iter().skip(1) {
        let _ = writeln!(::std::io::stderr(), "   caused by: {}", e);
    }
}

fn hex_print(data: &[u8]) {
    for (idx, row) in data.chunks(16).enumerate() {
        print!("{:>08x}  ", idx*16);
        for (pos, c) in row.iter().enumerate() {
            print!("{:>02x} ", c);
            if pos == 7 {
                print!(" ");
            }
        }
        if row.len() < 7 {
            print!(" ");
        }
        let fillup = 16-row.len();
        for _ in 0..(fillup*3) { print!(" "); }

        print!(" |");
        for &c in row {
            if c >= ' ' as u8 && c <= '~' as u8 {
                let c = c as char;
                print!("{}", c);
            } else {
                print!(".");
            }
        }
        print!("|");

        println!("");
    }
}

fn info<'a>(args: &ArgMatches<'a>) -> Result<()> {
    let map_path: String = args.value_of_os("MAP_PATH")
        .expect("TARGET is required")
        .to_os_string()
        .into_string().map_err(|_| "MAP_PATH must be valid unicode")?;

    Map::from_path(&map_path).map(|map| {
        println!("{}", map);
        ()
    }).chain_err(|| format!("Failed to parse info about map"))
}

fn dump<'a>(args: &ArgMatches<'a>) -> Result<()> {
    let map_path: String = args.value_of_os("MAP_PATH")
        .expect("TARGET is required")
        .to_os_string()
        .into_string().map_err(|_| "MAP_PATH must be valid unicode")?;

    let map = Map::from_path(&map_path)
        .chain_err(|| format!("Failed to parse info about map"))?;

    for (key, val) in &map {
        println!("Key:");
        hex_print(&key);
        println!("Value:");
        hex_print(&val);
        println!("");
    }

    Ok(())
}

fn main() {
    let app = App::new("bpf-map")
        .version("0.1.0")
        .author("Jan-Erik Rediger <janerik@fnordig.de>")
        .about("Inspect persisted BPF maps")
        .settings(&[AppSettings::SubcommandRequired])
        .subcommand(SubCommand::with_name("info")
                    .about("Print metadata information of map")
                    .arg(Arg::with_name("MAP_PATH").required(true)
                         .help("Path to the map")))
        .subcommand(SubCommand::with_name("dump")
                    .about("Dump contents of map")
                    .arg(Arg::with_name("MAP_PATH").required(true)
                         .help("Path to the map")));

    let args = app.get_matches();

    ::std::process::exit(match args.subcommand() {
        ("info", matches) => info(matches.expect("arguments present")),
        ("dump", matches) => dump(matches.expect("arguments present")),
        (s, _) => panic!("unimplemented subcommand {}!", s),
    }.map(|_| 0).unwrap_or_else(|err| {
        report_error(err);
        1
    }));
}
