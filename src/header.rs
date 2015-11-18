
/// DNS message header.
///
pub struct Header {
    // The header is stored as a u32 in host byte order. Don't forget
    // to_be() and from_be() when doing wire translation.
    inner: u32
}

impl Header {
    pub fn new() -> Header {
        Header { inner: 0 }
    }

    pub fn from_u32(inner: u32) -> Header {
        Header { inner: inner }
    }

    pub fn id(&self) -> u16 {
        (self.inner >> 16) as u16
    }
    pub fn set_id(&mut self, id: u16) -> &mut Header {
        self.inner = self.inner & 0xFFFF | (id as u32);
        self
    }

    pub fn qr(&self) -> bool { self.check_bit(15) }
    pub fn set_qr(&mut self, qr: bool) -> &mut Header { self.set_bit(15, qr) }
    
    pub fn opcode(&self) -> Opcode {
        Opcode::from_u8((self.inner >> 11) as u8 & 0x0F )
    }
    pub fn set_opcode(&mut self, opcode: Opcode) -> &mut Header {
        self.inner = self.inner & 0xFFFF87FF 
                   | ((opcode.to_u8() as u32) << 11);
        self
    }

    pub fn aa(&self) -> bool { self.check_bit(11) }
    pub fn set_aa(&mut self, aa: bool) -> &mut Header { self.set_bit(11, aa) }

    pub fn tc(&self) -> bool { self.check_bit(10) }
    pub fn set_tc(&mut self, tc: bool) -> &mut Header { self.set_bit(10, tc) }

    pub fn rd(&self) -> bool { self.check_bit(9) }
    pub fn set_rd(&mut self, rd: bool) -> &mut Header { self.set_bit(9, rd) }

    pub fn ra(&self) -> bool { self.check_bit(8) }
    pub fn set_ra(&mut self, ra: bool) -> &mut Header { self.set_bit(8, ra) }

    pub fn z(&self) -> bool { self.check_bit(7) }
    pub fn set_z(&mut self, z: bool) -> &mut Header { self.set_bit(7, z) }

    pub fn ad(&self) -> bool { self.check_bit(6) }
    pub fn set_ad(&mut self, ad: bool) -> &mut Header { self.set_bit(6, ad) }

    pub fn cd(&self) -> bool { self.check_bit(5) }
    pub fn set_cd(&mut self, cd: bool) -> &mut Header { self.set_bit(5, cd) }

    pub fn rcode(&self) -> Rcode {
        Rcode::from_u8((self.inner as u8) & 0x0F)
    }
    pub fn set_rcode(&mut self, rcode: Rcode) -> &mut Header {
        self.inner = self.inner &0xFFFFFFF0 | rcode.to_u8() as u32;
        self
    }

    fn check_bit(&self, bit: usize) -> bool {
        self.inner & 1 << bit != 0
    }
    fn set_bit(&mut self, bit: usize, set: bool) -> &mut Header {
        if set { self.inner |= 1 << bit }
        else { self.inner &= !(1 << bit) };
        self
    }
}

//------------ Opcode -------------------------------------------------------

/// The opcode specifies the kind of query.
///
pub enum Opcode {
    /// a standard query [RFC1035]
    Query,

    /// a inverse query [RFC1035]
    IQuery,

    /// a server status request [RFC1035]
    Status,

    /// a NOTIFY query [RFC1996]
    Notify,

    /// an UPDATE query [RFC2136]
    Update,

    /// unassigned opcode: 3, 6-15
    Unassigned(u8)
}

impl Opcode {
    fn from_u8(octet: u8) -> Opcode {
        match octet {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            3 | 6 ... 15 => Opcode::Unassigned(octet),
            _ => panic!()
        }
    }

    fn to_u8(&self) -> u8 {
        match *self {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Unassigned(i) => {
                match i {
                    3 | 6 ... 15 => i,
                    _ => panic!()
                }
            }
        }
    }
}


//------------ Rcode --------------------------------------------------------

/// Response code.
///
/// This is the four bit error code in the message header.
///
pub enum Rcode {
    /// no error condition [RFC1035]
    NoError,

    /// format error [RFC1035]
    FormErr,

    /// server failure [RFC1035]
    ServFail,

    /// name error [RFC1035]
    NXDomain,

    /// not implemented [RFC1035]
    NotImp,

    /// query refused [RFC1035]
    Refused,

    /// name exists when it should not [RFC2136]
    YXDomain,

    /// RR set exists when it should not [RFC2136]
    YXRRSet,

    /// RR set that should exist does not [RFC2136]
    NXRRSet,

    /// server not authoritative for zone [RFC2136] or not authorized [RFC2845]
    NotAuth,

    /// name not contained in zone [RFC2136]
    NotZone,

    /// unassigned: 11-15
    Unassigned(u8)
}

impl Rcode {
    fn from_u8(i: u8) -> Rcode {
        match i {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NXDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            6 => Rcode::YXDomain,
            7 => Rcode::YXRRSet,
            8 => Rcode::NXRRSet,
            9 => Rcode::NotAuth,
            10 => Rcode::NotZone,
            11 ... 15 => Rcode::Unassigned(i),
            _ => panic!()
        }
    }

    fn to_u8(&self) -> u8 {
        match *self {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NXDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::YXDomain => 6,
            Rcode::YXRRSet => 7,
            Rcode::NXRRSet => 8,
            Rcode::NotAuth => 9,
            Rcode::NotZone => 10,
            Rcode::Unassigned(i) => match i {
                11 ... 15 => i,
                _ => panic!()
            }
        }
    }
}


//------------ Tests -----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_id() {
        assert_eq!(Header::from_u32(0xDE550100).id(), 0xDE55);
    }
}
