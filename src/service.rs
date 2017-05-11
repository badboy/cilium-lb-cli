use std::net::SocketAddrV4;

extern {
    #[link_name = "free_packed"]
    fn _free_packed(ptr: *const u8);
    fn to_packed_key(ptr: *const Frontend) -> *mut u8;
    fn to_packed_svc(ptr: *const Backend) -> *mut u8;

    fn from_packed_key(ptr: *const u8, key: *mut Frontend);
    fn from_packed_svc(ptr: *const u8, svc: *mut Backend);
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct Frontend {
    pub address: u32,
    pub dport: u16,
    pub slave: u16,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Backend {
    pub target: u32,
    pub port: u16,
    pub count: u16,
    pub rev_nat_index: u16,
    pub weight: u16,
}
pub fn free_packed(ptr: *const u8) {
    unsafe {
        _free_packed(ptr);
    }
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
            address: address,
            dport: addr.port(),
            slave: 0,
        }
    }

    pub fn slave(&mut self, slave: u16) {
        self.slave = slave;
    }

    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.address.into(), self.dport)
    }

    pub fn to_packed(&self) -> *const u8 {
        unsafe {
            to_packed_key(self as *const _)
        }
    }

    pub unsafe fn from_packed(data: &[u8]) -> Frontend {
        let mut front = Frontend { address: 0, dport: 0, slave: 0 };

        from_packed_key(data.as_ptr(), &mut front as *mut _);
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
            target: address,
            port: addr.port(),
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
        SocketAddrV4::new(self.target.into(), self.port)
    }

    pub fn to_packed(&self) -> *const u8 {
        unsafe {
            to_packed_svc(self as *const _)
        }
    }

    pub unsafe fn from_packed(data: &[u8]) -> Backend {
        let mut front = Backend { target: 0, port: 0, count: 0, rev_nat_index: 0, weight: 0 };

        from_packed_svc(data.as_ptr(), &mut front as *mut _);
        front
    }
}
