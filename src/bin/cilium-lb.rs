extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate cilium_lb;

use std::io::Write;
use std::collections::HashMap;
use clap::{Arg, ArgMatches, App, AppSettings, SubCommand};

use cilium_lb::Map;
use cilium_lb::service;

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

fn list<'a>(args: &ArgMatches<'a>) -> Result<()> {
    let map_path = "/sys/fs/bpf/tc/globals/cilium_lb4_services";
    let map = Map::from_path(&map_path)
        .chain_err(|| format!("Failed to parse info about map"))?;

    let mut lb : HashMap<service::Frontend, Vec<(u16, service::Backend)>> = HashMap::new();

    for (key, val) in &map {
        unsafe {
            let frontend = service::Frontend::from_packed(&key);
            let backend = service::Backend::from_packed(&val);

            let mut master = frontend.clone();
            master.slave(0);

            let mut elem = lb.entry(master).or_insert_with(|| Vec::new());
            if frontend.slave > 0 {
                elem.push((frontend.slave, backend));
            }
        }
    }

    for (frontend, backends) in lb {
        println!("{} ->", frontend.addr());
        for (id, backend) in backends {
            print!("                       ");
            println!("({}) {}", id, backend.target());
        }
    }

    Ok(())
}

fn main() {
    let app = App::new("cilium-lb")
        .version("0.1.0")
        .author("Jan-Erik Rediger <janerik@fnordig.de>")
        .about("Manage load-balanced services")
        .settings(&[AppSettings::SubcommandRequired])
        .subcommand(SubCommand::with_name("list")
                    .about("List current services"))
        .subcommand(SubCommand::with_name("add")
                    .about("Add new service with backends"))
        .subcommand(SubCommand::with_name("del")
                    .about("Delete service and all backends"));

    let args = app.get_matches();

    ::std::process::exit(match args.subcommand() {
        ("list", matches) => list(matches.expect("arguments present")),
        (s, _) => panic!("unimplemented subcommand {}!", s),
    }.map(|_| 0).unwrap_or_else(|err| {
        report_error(err);
        1
    }));
}
