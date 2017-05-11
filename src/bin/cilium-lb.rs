extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate cilium_lb;

use std::io::Write;
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::str::FromStr;
use std::slice;
use clap::{Arg, ArgMatches, App, AppSettings, SubCommand};

use cilium_lb::{bpf, service, Map};

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

fn list<'a>(_args: &ArgMatches<'a>) -> Result<()> {
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

fn del<'a>(args: &ArgMatches<'a>) -> Result<()> {
    let map_path = "/sys/fs/bpf/tc/globals/cilium_lb4_services";
    let map = Map::from_path(&map_path)
        .chain_err(|| format!("Failed to parse info about map"))?;

    let service: String = args.value_of_os("SERVICE")
        .expect("SERVICE is required")
        .to_os_string()
        .into_string().map_err(|_| "SERVICE must be valid unicode")?;
    let service_addr = SocketAddrV4::from_str(&service)
        .chain_err(|| format!("Failed to parse service address"))?;

    let mut lb : Vec<u16> = Vec::new();

    for (key, _val) in &map {
        unsafe {
            let frontend = service::Frontend::from_packed(&key);

            if frontend.addr() == service_addr {
                lb.push(frontend.slave);
            }
        }
    }

    lb.sort();

    if lb.is_empty() {
        println!("No service with address {} found. Nothing deleted.", service_addr);
    }

    let mut frontend = service::Frontend::new(service_addr);
    for id in lb {
        println!("Deleting service {} slave {}", service_addr, id);
        frontend.slave(id);

        unsafe {
            let raw = frontend.to_packed();
            let raw_slice = slice::from_raw_parts(raw, map.key_size);
            let res = bpf::delete_elem(&map, raw_slice);
            service::free_packed(raw);
            res?;
        }
    }

    Ok(())
}

fn add<'a>(args: &ArgMatches<'a>) -> Result<()> {
    let map_path = "/sys/fs/bpf/tc/globals/cilium_lb4_services";
    let map = Map::from_path(&map_path)
        .chain_err(|| format!("Failed to parse info about map"))?;

    let service: String = args.value_of_os("SERVICE")
        .expect("SERVICE is required")
        .to_os_string()
        .into_string().map_err(|_| "SERVICE must be valid unicode")?;
    let service_addr = SocketAddrV4::from_str(&service)
        .chain_err(|| format!("Failed to parse service address"))?;

    let backend: String = args.value_of_os("BACKEND")
        .expect("BACKEND is required")
        .to_os_string()
        .into_string().map_err(|_| "BACKEND must be valid unicode")?;
    let backend_addr = SocketAddrV4::from_str(&backend)
        .chain_err(|| format!("Failed to parse backend address"))?;

    let mut frontends : Vec<u16> = Vec::new();

    for (key, val) in &map {
        unsafe {
            let frontend = service::Frontend::from_packed(&key);
            let backend = service::Backend::from_packed(&val);

            if frontend.addr() == service_addr && frontend.slave > 0 {
                if backend.target() == backend_addr {
                    println!("Backend already in the list.");
                    return Ok(());
                }
                frontends.push(frontend.slave);
            }
        }
    }

    let next_id = frontends.into_iter().max().unwrap_or(0) + 1;

    let mut frontend = service::Frontend::new(service_addr);
    let empty = service::Backend::empty();
    let backend = service::Backend::new(backend_addr, 1);
    unsafe {
        {
            frontend.slave(0);
            let raw_fe = frontend.to_packed();
            let raw_fe_slice = slice::from_raw_parts(raw_fe, map.key_size);
            let raw_be = empty.to_packed();
            let raw_be_slice = slice::from_raw_parts(raw_be, map.value_size);

            let res = bpf::update_elem(&map, raw_fe_slice, raw_be_slice);
            service::free_packed(raw_fe);
            service::free_packed(raw_be);
            res?;
        }

        {
            frontend.slave(next_id);
            println!("Adding backend {} slave {} for frontend {}", backend_addr, next_id, service_addr);
            let raw_fe = frontend.to_packed();
            let raw_fe_slice = slice::from_raw_parts(raw_fe, map.key_size);
            let raw_be = backend.to_packed();
            let raw_be_slice = slice::from_raw_parts(raw_be, map.value_size);

            let res = bpf::update_elem(&map, raw_fe_slice, raw_be_slice);
            service::free_packed(raw_fe);
            service::free_packed(raw_be);
            res?;
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
                    .about("Add new service with backends")
                    .arg(Arg::with_name("SERVICE").required(true)
                        .help("Service Identifier (Frontend IP/Port)"))
                    .arg(Arg::with_name("BACKEND").required(true)
                        .help("Service Identifier (IP/Port)")))
        .subcommand(SubCommand::with_name("del")
                    .about("Delete service and all backends")
                    .arg(Arg::with_name("SERVICE").required(true)
                        .help("Service Identifier (Frontend IP/Port)")));

    let args = app.get_matches();

    ::std::process::exit(match args.subcommand() {
        ("list", matches) => list(matches.expect("arguments present")),
        ("del", matches) => del(matches.expect("arguments present")),
        ("add", matches) => add(matches.expect("arguments present")),
        (s, _) => panic!("unimplemented subcommand {}!", s),
    }.map(|_| 0).unwrap_or_else(|err| {
        report_error(err);
        1
    }));
}
