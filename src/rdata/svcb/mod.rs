//! Record data for SVCB/HTTPS records.
//!
//! Service binding records are an IETF standard currently in development as
//! [draft-ietf-dnsop-svcb-https](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/).
//! They provide clients with information for accessing a service in one
//! place rather than via multiple records.
//!
//! Service bindings come as two record types with identical record data
//! format. The SVCB record type can be used for any service by prefixing the
//! service in question to the query name. The HTTPS record type is for use
//! with the HTTPS protocol and can be used without a prefix. Additional
//! record types for other protocols may be defined in the future.
//!
//! The type [`SvcbRdata<..>`][SvcbRdata] implements the record data of all
//! of these types. It takes a marker struct as its first type argument.
//! Type aliases for the two current types are provided via [`Svcb`] and
//! [`Https`]. Like most complex record data types, they still are generic
//! over an octets sequence and a domain name.
//!
//! The record data itself consists of a priority providing the order of
//! records if more than one is given, a target name which indicates the
//! name of the host where the service is provided, and a possible empty
//! sequence of service parameters further describing properties of the
//! service. These parameters are represented by the [SvcParams] type.
//! They consist of a sequence of different parameter values. Types for
//! the defined values are available in the [value] sub-module.
//! A new sequence of values can be constructed using the [`SvcParamsBuilder`]
//! type.
//!
pub use self::params::{
    ComposeSvcParamValue, LongSvcParam, ParseSvcParamValue, PushError,
    SvcParamValue, SvcParams, SvcParamsBuilder, SvcParamsError,
    UnknownSvcParam, ValueIter,
};
pub use self::rdata::{Https, HttpsVariant, Svcb, SvcbRdata, SvcbVariant};

mod params;
mod rdata;
pub mod value;
