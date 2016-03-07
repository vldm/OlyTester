extern crate time;
extern crate libc;

mod process;
use process::{ProcessConfig, Verdict};

fn main() {
		let input = vec!["test".to_owned(),"test2".to_owned()];
		let output = input.clone();
		let x = ProcessConfig::new("tac").run((input,output));
	    assert_eq!(x,Verdict::WrongOutput);
	    println!("{:?}", x);
}
