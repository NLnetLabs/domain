// Validator

use crate::base::Message;
use crate::dep::octseq::Octets;
use context::ValidationContext;
use group::GroupList;
use std::fmt::Debug;

pub fn validate_msg<Octs>(msg: Message<Octs>, vc: &ValidationContext)
where Octs: Clone + Debug + Octets
{
    // First convert the Answer and Authority sections to lists of RR groups
    let mut answers = GroupList::<(), _>::new();
    for rr in msg.answer().unwrap() {
	answers.add(rr.unwrap());
    }
    let mut authorities = GroupList::<(), _>::new();
    for rr in msg.authority().unwrap() {
	authorities.add(rr.unwrap());
    }

    println!("Answer groups: {answers:?}");
    println!("Authority groups: {authorities:?}");

    // Get rid of redundant unsigned CNAMEs
    answers.remove_redundant_cnames();

    // Validate each group
    for g in answers.iter() {
	println!("Validating group {g:?}");
	g.validate_with_vc(vc);
    }
    for g in authorities.iter() {
	println!("Validating group {g:?}");
	todo!();
	//g.validate_with_vc();
    }
    todo!();
}

mod anchor;
pub mod context;
mod group;
mod types;
