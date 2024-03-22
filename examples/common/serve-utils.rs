use bytes::Bytes;
use domain::{
    base::{Dname, Message, MessageBuilder, ParsedDname, Rtype},
    rdata::ZoneRecordData,
    zonetree::Answer,
};

pub fn generate_wire_query(
    qname: &Dname<Bytes>,
    qtype: Rtype,
) -> Message<Vec<u8>> {
    let query = MessageBuilder::new_vec();
    let mut query = query.question();
    query.push((qname, qtype)).unwrap();
    query.into()
}

pub fn generate_wire_response(
    wire_query: &Message<Vec<u8>>,
    zone_answer: Answer,
) -> Message<Vec<u8>> {
    let builder = MessageBuilder::new_vec();
    let response = zone_answer.to_message(wire_query, builder);
    response.into()
}

pub fn print_dig_style_response(
    query: &Message<Vec<u8>>,
    response: &Message<Vec<u8>>,
    short: bool,
) {
    if !short {
        let qh = query.header();
        let rh = response.header();
        println!("; (1 server found)");
        println!(";; global options:");
        println!(";; Got answer:");
        println!(
            ";; ->>HEADER<<- opcode: {}, status: {}, id: {}",
            qh.opcode(),
            rh.rcode(),
            rh.id()
        );
        print!(";; flags: ");
        if rh.aa() {
            print!("aa ");
        }
        if rh.ad() {
            print!("ad ");
        }
        if rh.cd() {
            print!("cd ");
        }
        if rh.qr() {
            print!("qr ");
        }
        if rh.ra() {
            print!("ra ");
        }
        if rh.rd() {
            print!("rd ");
        }
        if rh.tc() {
            print!("tc ");
        }
        let counts = response.header_counts();
        println!(
            "; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
            counts.qdcount(),
            counts.ancount(),
            counts.arcount(),
            counts.adcount()
        );

        // TODO: add OPT PSEUDOSECTION

        if let Ok(question) = query.sole_question() {
            println!(";; QUESTION SECTION:");
            println!(
                ";{} {} {}",
                question.qname(),
                question.qclass(),
                question.qtype()
            );
            println!();
        }
    }

    let sections = [
        ("ANSWER", response.answer()),
        ("AUTHORITY", response.authority()),
        ("ADDITIONAL", response.additional()),
    ];
    for (name, section) in sections {
        if let Ok(section) = section {
            if section.count() > 0 {
                if !short {
                    println!(";; {name} SECTION:");
                }

                for record in section {
                    let record = record
                        .unwrap()
                        .into_record::<ZoneRecordData<_, ParsedDname<_>>>()
                        .unwrap()
                        .unwrap();

                    if short {
                        println!("{}", record.data());
                    } else {
                        println!("{record}");
                    }
                }

                if !short {
                    println!();
                }
            }
        }
    }
}
