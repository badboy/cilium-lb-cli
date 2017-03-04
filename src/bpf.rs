use std::os::unix::io::RawFd;
use std::os::raw::{c_char, c_int};
use std::ffi::CString;
use std::io;

use map::Map;

extern {
    fn obj_get(pathname: *const c_char) -> c_int;
    fn bpf_lookup_elem(fd: c_int, key: *const u8, value: *mut u8) -> c_int;
    fn bpf_get_next_key(fd: c_int, key: *const u8, next_key: *mut u8) -> c_int;
}

pub fn lookup_elem(map: &Map, key: &[u8]) -> io::Result<Vec<u8>> {
    assert!(map.fd > 0);
    assert_eq!(map.key_size, key.len());

    unsafe {
        let mut value = Vec::with_capacity(map.value_size);

        let res = bpf_lookup_elem(map.fd, key.as_ptr(), value.as_mut_ptr());
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        value.set_len(map.value_size);
        Ok(value)
    }
}

pub fn get_next_key(map: &Map, old_key: &[u8]) -> io::Result<Vec<u8>> {
    assert!(map.fd > 0);
    assert_eq!(map.key_size, old_key.len());

    unsafe {
        let mut next_key = Vec::with_capacity(map.key_size);

        let res = bpf_get_next_key(map.fd, old_key.as_ptr(), next_key.as_mut_ptr());
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        next_key.set_len(map.key_size);
        Ok(next_key)
    }
}

pub fn obj_get_fd(pathname: &str) -> RawFd {
    let cstr = CString::new(pathname).unwrap();

    unsafe {
        obj_get(cstr.as_ptr())
    }
}
