use octseq::builder::{
    BuilderAppendError, EmptyBuilder, FromBuilder, Truncate,
};
use crate::base::iana::{Class, Rtype};
use crate::base::name::ToDname;
use crate::base::record::{Record, Ttl};
use crate::base::rdata::ComposeRecordData;
use crate::base::serial::Serial;
use crate::rdata::dnssec::{Ds, Dnskey, Nsec, ProtoRrsig, Rrsig, RtypeBitmap};
use super::key::SigningKey;


pub trait Rrset {
    type Owner: ToDname;
    type RecordData<'a>: ComposeRecordData where Self: 'a;
    type Iter<'a>: Iterator<Item = Self::RecordData<'a>> where Self: 'a;

    fn owner(&self) -> &Self::Owner;
    fn class(&self) -> Class;
    fn rtype(&self) -> Rtype;
    fn ttl(&self) -> Ttl;
    fn iter(&self) -> Self::Iter<'_>;

    fn sign<Octs, Name, Key>(
        &self,
        apex: Name,
        expiration: Serial,
        inception: Serial,
        key: Key,
    ) -> Result<Rrsig<Octs, Name>, Key::Error>
    where
        Octs: From<<Key as SigningKey>::Signature> + AsRef<[u8]>,
        Name: ToDname,
        Key: SigningKey,
    {
        let rrsig = ProtoRrsig::new(
            self.rtype(),
            key.algorithm()?,
            self.owner().rrsig_label_count(),
            self.ttl(),
            expiration,
            inception,
            key.key_tag()?,
            apex,
        );
        let sig = key.sign(|buf| {
            rrsig.compose_canonical(buf)?;
            for item in self.iter() {
                // We can’t use Record because it wants its rtype in the Data
                // type. Luckily, composing a record is straighforward:
                self.owner().compose_canonical(buf)?;
                self.rtype().compose(buf)?;
                self.class().compose(buf)?;
                self.ttl().compose(buf)?;
                item.compose_canonical_len_rdata(buf)?;
            }
            Ok(())
        })?;
        Ok(rrsig.into_rrsig(Octs::from(sig)).expect("long signature"))
    }
}

pub trait Rrfamily {
    type Owner: ToDname;
    type Rrset<'a>: Rrset where Self: 'a;
    type Iter<'a>: Iterator<Item = Self::Rrset<'a>> where Self: 'a;

    fn owner(&self) -> &Self::Owner;
    fn class(&self) -> Class;
    fn iter(&self) -> Self::Iter<'_>;


    //--- Things to do at the zone apex

    fn dnskey<K: SigningKey, Octets: From<K::Octets>>(
        &self,
        ttl: Ttl,
        key: K
    ) -> Result<Record<Self::Owner, Dnskey<Octets>>, K::Error>
    where
        Self::Owner: Clone
    {
        key.dnskey().map(|data| {
            self.to_record(ttl, data.convert())
        })
    }

    fn ds<K: SigningKey>(
        &self,
        ttl: Ttl,
        key: K,
    ) -> Result<Record<Self::Owner, Ds<K::Octets>>, K::Error>
    where
        Self::Owner: ToDname + Clone,
    {
        key.ds(self.owner()).map(|ds| {
            self.to_record(ttl, ds)
        })
    }


    //--- Things to do everywhere

    fn to_record<D>(&self, ttl: Ttl, data: D) -> Record<Self::Owner, D>
    where
        Self::Owner: Clone
    {
        Record::new(self.owner().clone(), self.class(), ttl, data)
    }

    fn rtype_bitmap<Octs>(
        &self
    ) -> Result<RtypeBitmap<Octs>, BuilderAppendError<Octs>>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder:
            EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
    {
        let mut bitmap = RtypeBitmap::<Octs>::builder();
        // Assume there’s going to be an RRSIG.
        bitmap.add(Rtype::Rrsig)?;
        for rrset in self.iter() {
            bitmap.add(rrset.rtype())?;
        }
        Ok(bitmap.finalize())
    }

    fn nsec<Octs, Name>(
        &self, next_name: Name
    ) -> Result<Nsec<Octs, Name>, BuilderAppendError<Octs>>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder:
            EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
    {
        Ok(Nsec::new(next_name, self.rtype_bitmap()?))
    }
}

