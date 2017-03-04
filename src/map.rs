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

#[derive(Debug)]
pub struct Map {
    pub map_type: MapType,
    pub key_size: usize,
    pub value_size: usize,
    pub max_entries: usize,
    pub map_flags: usize,
}

impl From<u8> for MapType {
    fn from(val: u8) -> MapType {
        use self::MapType::*;
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
