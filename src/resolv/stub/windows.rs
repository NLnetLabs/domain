use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::vec::Vec;

use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::AF_UNSPEC,
};

pub struct AddressLookup {
    pub dns_servers: Vec<SocketAddr>,
}

impl AddressLookup {
    pub fn new() -> Self {
        let mut dns_servers = vec![];

        if let Some(buffer) = Self::get_adapter_adresses() {
            let dns_servers_set = Self::get_dns_servers_from_buffer(&buffer);
            dns_servers = dns_servers_set.into_iter().collect();
        }

        Self { dns_servers }
    }

    fn get_adapter_adresses() -> Option<Vec<u8>> {
        let mut buffer_size: u32 = 0;

        let family = AF_UNSPEC as u32;
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME;

        // SAFETY: GetAdaptersAddresses is a win32 API function that will override the
        // buffer_size value with the needed size for the next invocation. So the pointer
        // that we pass as the fourth argument is also a null-pointer and the buffer_size
        // value starts with a size of zero.
        unsafe {
            let res = GetAdaptersAddresses(
                family,
                flags,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut buffer_size as *mut _,
            );

            if res != ERROR_BUFFER_OVERFLOW {
                return None;
            }
        }

        let mut buffer = vec![0u8; buffer_size as usize];

        // SAFETY: Now that we know how many bytes we need to get all information we
        // allocate a buffer with enough empty space and pass it to the function.
        unsafe {
            let res = GetAdaptersAddresses(
                family,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr() as *mut _,
                &mut buffer_size as *mut _,
            );

            if res != NO_ERROR {
                return None;
            }
        }

        Some(buffer)
    }

    fn get_dns_servers_from_buffer(buffer: &[u8]) -> HashSet<SocketAddr> {
        let mut dns_servers = HashSet::new();

        let mut address_info_ptr =
            buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !address_info_ptr.is_null() {
            // SAFETY: We checked above that the pointer is not null.
            let address_info = unsafe { *address_info_ptr };

            let mut dns_server_address_ptr =
                address_info.FirstDnsServerAddress;

            while !dns_server_address_ptr.is_null() {
                // SAFETY: We checked above that the pointer is not null.
                let dns_server_address = unsafe { *dns_server_address_ptr };

                match (
                    dns_server_address.Address.iSockaddrLength,
                    dns_server_address.Address.lpSockaddr.is_null(),
                ) {
                    (16, false) => {
                        use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
                        let sock_addr_ptr =
                            dns_server_address.Address.lpSockaddr
                                as *mut SOCKADDR_IN;
                        // SAFETY: We checked in the match statement that the pointer is not null.
                        let sock_addr = unsafe { *sock_addr_ptr };

                        // SAFETY: Accessing the data through s_b{1,2,3,4} is always safe,
                        // as all bit patterns are valid for u8. Also all union members have
                        // the same size.
                        let sock_addr = unsafe {
                            SocketAddrV4::new(
                                Ipv4Addr::new(
                                    sock_addr.sin_addr.S_un.S_un_b.s_b1,
                                    sock_addr.sin_addr.S_un.S_un_b.s_b2,
                                    sock_addr.sin_addr.S_un.S_un_b.s_b3,
                                    sock_addr.sin_addr.S_un.S_un_b.s_b4,
                                ),
                                53,
                            )
                        };
                        dns_servers.insert(SocketAddr::V4(sock_addr));
                    }
                    (28, false) => {
                        use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6;
                        let sock_addr_ptr =
                            dns_server_address.Address.lpSockaddr
                                as *mut SOCKADDR_IN6;
                        // SAFETY: We checked in the match statement that the pointer is not null.
                        let sock_addr = unsafe { *sock_addr_ptr };

                        // SAFETY: Accessing the data through Word[u16; 8] is always safe,
                        // as all bit patterns are valid for u16. Also all union members have
                        // the same size.
                        let ip_addr = unsafe {
                            Ipv6Addr::new(
                                u16::from_be(sock_addr.sin6_addr.u.Word[0]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[1]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[2]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[3]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[4]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[5]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[6]),
                                u16::from_be(sock_addr.sin6_addr.u.Word[7]),
                            )
                        };

                        // SAFETY: Accessing sin6_scope_id is always safe, as all bit patters are
                        // valid inside u32 and all union member have the same size.
                        let scope_id =
                            unsafe { sock_addr.Anonymous.sin6_scope_id };

                        let sock_addr = SocketAddrV6::new(
                            ip_addr,
                            53,
                            sock_addr.sin6_flowinfo,
                            scope_id,
                        );
                        dns_servers.insert(SocketAddr::V6(sock_addr));
                    }
                    _ => (),
                }

                dns_server_address_ptr = dns_server_address.Next;
            }
            address_info_ptr = address_info.Next;
        }

        dns_servers
    }
}
