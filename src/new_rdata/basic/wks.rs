use core::fmt;

use domain_macros::*;

use crate::new_base::wire::AsBytes;

use super::A;

//----------- Wks ------------------------------------------------------------

/// Well-known services supported on this domain.
#[derive(AsBytes, BuildBytes, ParseBytesByRef, UnsizedClone)]
#[repr(C, packed)]
pub struct Wks {
    /// The address of the host providing these services.
    pub address: A,

    /// The IP protocol number for the services (e.g. TCP).
    pub protocol: u8,

    /// A bitset of supported well-known ports.
    pub ports: [u8],
}

//--- Formatting

impl fmt::Debug for Wks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Ports<'a>(&'a [u8]);

        impl fmt::Debug for Ports<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let entries = self
                    .0
                    .iter()
                    .enumerate()
                    .flat_map(|(i, &b)| (0..8).map(move |j| (i, j, b)))
                    .filter(|(_, j, b)| b & (1 << j) != 0)
                    .map(|(i, j, _)| i * 8 + j);

                f.debug_set().entries(entries).finish()
            }
        }

        f.debug_struct("Wks")
            .field("address", &format_args!("{}", self.address))
            .field("protocol", &self.protocol)
            .field("ports", &Ports(&self.ports))
            .finish()
    }
}

//--- Equality

impl PartialEq for Wks {
    fn eq(&self, other: &Self) -> bool {
        if self.address != other.address || self.protocol != other.protocol {
            return false;
        }

        // Iterate through the ports, ignoring trailing zero bytes.
        let mut lp = self.ports.iter();
        let mut rp = other.ports.iter();
        while lp.len() > 0 || rp.len() > 0 {
            match (lp.next(), rp.next()) {
                (Some(l), Some(r)) if l != r => return false,
                (Some(l), None) if *l != 0 => return false,
                (None, Some(r)) if *r != 0 => return false,
                _ => {}
            }
        }
        true
    }
}

impl Eq for Wks {}
