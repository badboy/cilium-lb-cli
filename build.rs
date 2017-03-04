extern crate gcc;

fn main() {
    gcc::compile_library("libobj_get.a", &["src/obj_get.c"]);
}
