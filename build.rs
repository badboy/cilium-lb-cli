extern crate gcc;

fn main() {
    gcc::compile_library("libminbpf.a", &["src/minlibbpf.c"]);
}
