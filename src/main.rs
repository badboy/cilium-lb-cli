use std::os::raw::{c_char, c_int};
use std::os::unix::io::RawFd;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::default::Default;
use std::convert::From;

mod map;

use map::{Map, MapType};

extern {
    fn obj_get(pathname: *const c_char) -> c_int;
    fn bpf_lookup_elem(fd: c_int, key: *const u8, value: *mut u8) -> c_int;
    fn bpf_get_next_key(fd: c_int, key: *const u8, next_key: *mut u8) -> c_int;
}

fn bpf_obj_get_fd(pathname: &str) -> RawFd {
    let cstr = CString::new(pathname).unwrap();

    unsafe {
        obj_get(cstr.as_ptr())
    }
}

fn bpf_get_map(pathname: &str) -> io::Result<Map> {
    let fd = bpf_obj_get_fd(pathname);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let fdinfo = format!("/proc/self/fdinfo/{}", fd);
    let mut infofile = File::open(fdinfo)?;

    let mut buf = String::new();
    infofile.read_to_string(&mut buf)?;

    let mut m = Map::default();
    m.fd = fd;

    for line in buf.lines() {
        let vals = line.split('\t').collect::<Vec<_>>();
        assert_eq!(2, vals.len());

        let key = &vals[0];
        let val = &vals[1];

        match *key {
            "map_type:" => m.map_type = val.parse::<u8>().map(|v| MapType::from(v)).unwrap(),
            "key_size:" => m.key_size = val.parse::<usize>().unwrap(),
            "value_size:" => m.value_size = val.parse::<usize>().unwrap(),
            "max_entries:" => m.max_entries = val.parse::<usize>().unwrap(),
            "map_flags:" => m.map_flags = usize::from_str_radix(&val[2..], 16).unwrap(),
            _ => {}
        }
    }

    Ok(m)
}

fn main() {
    let f = "/sys/fs/bpf/tc/globals/filter_mac";

    let map = bpf_get_map(f).unwrap();
    println!("{}", map);
}
