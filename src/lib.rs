//! Load data from persisted BPF maps from the kernel.
//!
//! ## Example
//!
//! ```rust,no_run
//! let map = bpf_map::Map::from_path("/sys/fs/bpf/tc/globals/my_map").unwrap();
//! println!("Map info:\n{}", map);
//! ```

pub mod bpf;
mod map;

pub use map::{Map, MapType};
