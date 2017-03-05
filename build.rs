extern crate gcc;

fn main() {
    gcc::Config::new()
                .file("src/minlibbpf.c")
                .include("/usr/include")
                .compile("libminbpf.a");
}
