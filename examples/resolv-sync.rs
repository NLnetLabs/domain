use domain::base::name::Name;
use domain::base::Rtype;
use domain::rdata::AllRecordData;
use domain::resolv::StubResolver;
use std::env;
use std::str::FromStr;

fn main() {
    let mut args = env::args().skip(1);
    let name = args
        .next()
        .and_then(|arg| Name::<Vec<_>>::from_str(&arg).ok());
    let rtype = args.next().and_then(|arg| Rtype::from_str(&arg).ok());
    let (name, rtype) = match (name, rtype) {
        (Some(name), Some(rtype)) => (name, rtype),
        _ => {
            println!("Usage: sync <domain> <record type>");
            return;
        }
    };

    let res = StubResolver::run(move |stub| async move {
        stub.query((name, rtype)).await
    });
    let res = res.unwrap();
    let res = res.answer().unwrap().limit_to::<AllRecordData<_, _>>();
    for record in res {
        let record = record.unwrap();
        println!("{record}");
    }
}
