use time::{Duration, PreciseTime};
use std::time::Duration as StdDuration;
use std::convert::AsRef;
use std::ffi::OsStr;
use std::process::{Command, Stdio, ChildStdout, ChildStdin, Child};
use std::sync::{Arc, TryLockError,  Mutex};
use std::thread;
use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Write, Error};
use std::str::FromStr;
use std::num::ParseIntError;
use std::thread::JoinHandle;
use std::result::Result;
use libc::{sysconf, _SC_PAGESIZE};

#[derive(Debug, Eq, PartialEq)]
pub enum Verdict {
	Ok,
	MemoryOverflow,
	TimeOut,
	Panic,
	WrongOutput,
	Internal
}



macro_rules!  check_option {
    ($x:expr) => (match $x {
       	Some(x) => x,
			_ => return Verdict::Internal
		})
}
macro_rules!  check_result {
    ($x:expr) => (match $x {
        Ok(x) => x,
			_ => return Verdict::Internal
		})
}

macro_rules!  pi_set_max {
    ($max:ident, $cur:ident, $($x:ident),+ ) => (
			$(
				if $max.$x < $cur.$x {
					$max.$x = $cur.$x;
				}
			)+
    	)
}
macro_rules!  pi_check {
    ($cur:expr, $check:expr) => (
			if let Some(cur) = $cur {
				if cur < $check { true } else { false }
			} else { false}
    	)
}
#[derive(Debug)]
pub struct ProcessInfo {
	pub sys_time: usize,
	pub user_time: usize,
	pub real_time: Duration,
	pub rss: usize,
	pub virtual_mem: usize,
}

impl ProcessInfo {

	pub fn new() -> ProcessInfo {
		ProcessInfo {
			sys_time: 0,
			user_time: 0,
			real_time: Duration::seconds(0),
			rss: 0,
			virtual_mem: 0,
		}
	}
	pub fn from_file(stat: PathBuf) -> Result<ProcessInfo, ParseIntError>{
		macro_rules!  parse_pi_elem {
		($pi:ident: $parts:ident => $($var:ident : $val:expr),+ ) => (
		    	$(
	    			$pi.$var = try!(usize::from_str($parts[$val]));
				)+
			)
		}
		let mut file = File::open(stat).unwrap();
		let mut data = String::new();
		let _ = file.read_to_string(&mut data);
		let parts:Vec<&str> = data.split(' ').filter(|s| s.len() > 0).collect();
		let mut process_info = ProcessInfo::new();
		parse_pi_elem!(process_info: parts => 
			sys_time: 15,
			user_time: 14,

			rss: 23,
			virtual_mem: 22
		);
		Ok(process_info)
	}
}

pub struct ProcessConfig {
	max_memory: Option<usize>,
	max_time: Option<usize>,
	command: Command,
	period: StdDuration,
	page_size: usize,
}

impl ProcessConfig{
	pub fn new<S: AsRef<OsStr>>(program: S) -> ProcessConfig {
		let mut command = Command::new(program);
		command.stdin(Stdio::piped());
		command.stdout(Stdio::piped());
		ProcessConfig {
			max_memory: None,
			max_time: None,
			command: command,
			period: StdDuration::from_millis(250),
			page_size: unsafe { sysconf(_SC_PAGESIZE) as usize },
		}
	}
	
	pub fn max_memory(&mut self, max_memory: usize) -> &mut ProcessConfig {
		self.max_memory = Some(max_memory);
		self
	}

	pub fn max_time(&mut self, max_time:usize) -> &mut ProcessConfig {
		self.max_time = Some(max_time);
		self
	}

	pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut ProcessConfig
	{
		self.command.arg(arg);
		self
	}

	pub fn args<S: AsRef<OsStr>>(&mut self, args: &[S]) -> &mut ProcessConfig
	{
		self.command.args(args);
		self
	}


	fn start_read(mut stdout: ChildStdout) -> Result<Vec<u8>, Error>{
			let mut ret:Vec<u8> = Vec::new();
            stdout.read_to_end(&mut ret).map(|_| ret)
	}
	fn write(mut stdin: ChildStdin, input: &Vec<u8>)
	{
    	let _ = stdin.write_all(&input);
    	let _ = stdin.flush();
    }
	fn spawn_watcher(max_memory: Option<usize>,	max_time: Option<usize>, 
						page_size: usize, mutex:Arc<Mutex<()>>, 
							mut child: Child, period: StdDuration)-> JoinHandle<Result<ProcessInfo,Verdict>>
	{	
		fn is_locked (mutex:&Mutex<()>) -> bool {
			match mutex.try_lock() {
					Err(TryLockError::Poisoned(_)) => false,
					Err(_) => { // if mutex blocked 
							true
					},
					_ => false
				}
		}
	
    	thread::spawn(move || {
    		let pid = child.id();
    		let stat = PathBuf::from(&format!("/proc/{}/stat", pid) );
			let mut max = Result::Ok(ProcessInfo::new());
			
			while is_locked(&mutex) && max.is_ok()
			{ 
				let stat = ProcessInfo::from_file(stat.clone()).unwrap();
				max = max.map(|mut max | {
					pi_set_max!(max, stat, sys_time, user_time, 
										 rss, virtual_mem);
					max
				}).and_then(|max|{
					if pi_check!(max_memory, max.virtual_mem + max.rss * page_size){
						Err(Verdict::MemoryOverflow)
					}
					else if pi_check!(max_time, max.user_time + max.sys_time){
						Err(Verdict::TimeOut)
					}
					else {
						Ok(max)
					}
				});
				thread::sleep(period);
			}
			// kill when we over
			child.kill(); 
			if let Ok(x) =  child.wait(){
				if x.success() 
				{
					return max
				}
			}
			Err(Verdict::Panic)
			
		})
    }

	pub fn run(&mut self, (input, output): (Vec<String>, Vec<String>) ) -> Verdict {
		let input:Vec<u8> = input.iter()
                          .flat_map(|s| s.bytes().chain(vec![ b'\n']))
                          .collect();

		let output:Vec<u8> = output.iter()
                          .flat_map(|s| s.bytes().chain(vec![ b'\n']))
                          .collect();

      	let mut child =  check_result!(self.command.spawn());
		let stdout = check_option!(child.stdout.take());
		let stdin = check_option!(child.stdin.take());

		//inner block for guard drop
        let (reader, watcher, start ) = {
        	
        	let mutex =  Arc::new(Mutex::new(()));
        	let _guard = mutex.lock();

	        //mutex just for notify thread to stop, Arc to allow move borrowed value
			let watcher = ProcessConfig::spawn_watcher(self.max_memory, self.max_time, self.page_size,
														 mutex.clone(), child, self.period.clone());
	        //calculate time after spawn
			let start = PreciseTime::now();
			//Write and Destroy stdin
			ProcessConfig::write(stdin, &input);
			//start read
        	let reader = ProcessConfig::start_read(stdout);
    		(reader, watcher, start)
	    };
        let mut process_info = match check_result!(watcher.join()) {
        	Ok(x) => x,
        	Err(y) => return y, // return verdict from watcher
        };

        process_info.real_time = start.to(PreciseTime::now());
        let programout = check_result!(reader);
        println!("result = {:?}", process_info);
        if programout == output {
        	Verdict::Ok
        }
        else {
        	Verdict::WrongOutput
        }
	}
}

pub mod test{
	use process::ProcessConfig;
	use process::Verdict;
	#[test]
	pub fn test_cat () {
		let input = vec!["test".to_owned()];
		let output = input.clone();
		let x = ProcessConfig::new("cat").run((input,output));
	    assert_eq!(x,Verdict::Ok);
	    println!("{:?}", x);

	}
	#[test]
	pub fn test_cat_multiline () {
		let input = vec!["test".to_owned(), "test2".to_owned()];
		let output = input.clone();
		let x = ProcessConfig::new("cat").run((input,output));
	    assert_eq!(x,Verdict::Ok);
	    println!("{:?}", x);

	}
	#[test]
	pub fn test_tac () {
		let input = vec!["test".to_owned()];
		let output = input.clone();
		let x = ProcessConfig::new("tac").run((input,output));
	    assert_eq!(x,Verdict::Ok);
	    println!("{:?}", x);

	}
		#[test]
	pub fn test_tac_multiline () {
		let input = vec!["test".to_owned(),"test2".to_owned()];
		let output = input.clone();
		let x = ProcessConfig::new("tac").run((input,output));
	    assert_eq!(x,Verdict::WrongOutput);
	    println!("{:?}", x);

	}
}