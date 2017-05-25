use std::{mem, ptr, slice};
use std::net::SocketAddrV4;

/// struct lb4_key
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
#[repr(C,packed)]
pub struct Frontend {
    pub address: u32,
    pub dport: u16,
    pub slave: u16,
}

/// struct lb4_service
#[derive(Clone, Debug)]
#[repr(C,packed)]
pub struct Backend {
    pub target: u32,
    pub port: u16,
    pub count: u16,
    pub rev_nat_index: u16,
    pub weight: u16,
}

impl Frontend {
    pub fn new<A: Into<SocketAddrV4>>(a: A) -> Frontend {
        let addr = a.into();
        let ip = addr.ip();
        let octets = ip.octets();
        let address = (octets[0] as u32) << 24
            | (octets[1] as u32) << 16
            | (octets[2] as u32) << 8
            | (octets[3] as u32);

        Frontend {
            address: address.to_be(),
            dport: addr.port().to_be(),
            slave: 0,
        }
    }

    pub fn slave(&mut self, slave: u16) {
        self.slave = slave;
    }

    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.address.to_be().into(), self.dport.to_be())
    }

    pub fn to_bytes(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const _ as *const u8,
                                  mem::size_of::<Frontend>())
        }
    }

    pub unsafe fn from_packed(data: &[u8]) -> Frontend {
        assert!(data.len() == mem::size_of::<Frontend>());

        let mut front = Frontend { address: 0, dport: 0, slave: 0 };
        ptr::copy_nonoverlapping(data.as_ptr(),
                                 &mut front as *mut _ as *mut u8,
                                 mem::size_of::<Frontend>());

        front
    }
}

impl Backend {
    pub fn new<A: Into<SocketAddrV4>>(a: A, count: u16) -> Backend {
        let addr = a.into();
        let ip = addr.ip();
        let octets = ip.octets();
        let address = (octets[0] as u32) << 24
            | (octets[1] as u32) << 16
            | (octets[2] as u32) << 8
            | (octets[3] as u32);

        Backend {
            target: address.to_be(),
            port: addr.port().to_be(),
            count: count,
            rev_nat_index: 0,
            weight: 0,
        }
    }

    pub fn empty() -> Backend {
        Backend {
            target: 0,
            port: 0,
            count: 0,
            rev_nat_index: 0,
            weight: 0,
        }
    }

    pub fn count(&mut self, count: u16) {
        self.count = count;
    }

    pub fn target(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.target.to_be().into(), self.port.to_be())
    }

    pub fn to_bytes(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const _ as *const u8,
                                  mem::size_of::<Backend>())
        }
    }

    pub unsafe fn from_packed(data: &[u8]) -> Backend {
        assert!(data.len() == mem::size_of::<Backend>());

        let mut back = Backend { target: 0, port: 0, count: 0, rev_nat_index: 0, weight: 0 };
        ptr::copy_nonoverlapping(data.as_ptr(),
                                 &mut back as *mut _ as *mut u8,
                                 mem::size_of::<Backend>());

        back
    }
}
