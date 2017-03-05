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

fn main() {
    let app = App::new("bpf-map")
        .version("0.1.0")
        .author("Jan-Erik Rediger <janerik@fnordig.de>")
        .about("Inspect persisted BPF maps")
        .settings(&[AppSettings::SubcommandRequired])
        .subcommand(SubCommand::with_name("info")
                    .about("Print metadata information of map")
                    .arg(Arg::with_name("MAP_PATH").required(true)
                         .help("name of the fuzz target")));

    let args = app.get_matches();

    ::std::process::exit(match args.subcommand() {
        ("info", matches) => info(matches.expect("arguments present")),
        (s, _) => panic!("unimplemented subcommand {}!", s),
    }.map(|_| 0).unwrap_or_else(|err| {
        report_error(err);
        1
    }));
}
