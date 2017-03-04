use std::os::raw::{c_char, c_int};
use std::os::unix::io::RawFd;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::default::Default;
use std::convert::From;
use std::fmt::{self, Display};

#[derive(Debug)]
#[repr(u8)]
pub enum MapType {
    Unspec,
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PerCPUHash,
    PerCPUArray,
    StackTrace,
    CgroupArray,
    LRUHash,
    LRUPerCPUHash,
    LPMTrie,
}

impl From<u8> for MapType {
    fn from(val: u8) -> MapType {
        use MapType::*;
        assert!(val <= MapType::LPMTrie as u8);

        match val {
            0 => Unspec,
            1 => Hash,
            2 => Array,
            3 => ProgArray,
            4 => PerfEventArray,
            5 => PerCPUHash,
            6 => PerCPUArray,
            7 => StackTrace,
            8 => CgroupArray,
            9 => LRUHash,
            10 => LRUPerCPUHash,
            11 => LPMTrie,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct Map {
    map_type: MapType,
    key_size: usize,
    value_size: usize,
    max_entries: usize,
    map_flags: usize,
}

impl Default for Map {
    fn default() -> Map {
        Map {
            map_type: MapType::Unspec,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            map_flags: 0,
        }
    }
}

impl Display for Map {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Type:          {:?}\n", self.map_type)?;
        write!(f, "Key size:      {:?}\n", self.key_size)?;
        write!(f, "Value size:    {:?}\n", self.value_size)?;
        write!(f, "Max entries:   {:?}", self.max_entries)
    }
}

extern {
    fn obj_get(pathname: *const c_char) -> c_int;
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
