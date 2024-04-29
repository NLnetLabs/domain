use crate::base::Name;
use crate::base::NameBuilder;
use crate::base::ParsedName;
use crate::rdata::Dname;
use bytes::Bytes;

pub fn map_dname(
    owner: &Name<Bytes>,
    dname: &Dname<ParsedName<Bytes>>,
    name: &Name<Bytes>,
) -> Name<Bytes> {
    println!("map_dname: for name {name:?}, dname owner {owner:?}");
    let mut tmp_name = name.clone();
    let mut new_name = NameBuilder::new_bytes();
    let owner_labels = owner.label_count();
    while tmp_name.label_count() > owner_labels {
        println!("adding label {:?}", tmp_name.first());
        new_name.append_label(tmp_name.first().as_slice()).unwrap();
        tmp_name = tmp_name.parent().unwrap();
    }
    let name = new_name.append_origin(dname.dname()).unwrap();
    println!("Now at {:?}", name);
    name
}
