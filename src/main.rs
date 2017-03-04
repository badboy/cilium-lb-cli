mod map;
mod bpf;

use map::Map;

fn main() {
    let f = "/sys/fs/bpf/tc/globals/filter_mac";

    let map = Map::from_path(f).unwrap();
    println!("{}", map);
}
