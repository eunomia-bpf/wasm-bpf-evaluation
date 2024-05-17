use std::{ffi::CStr, slice, time::Duration};

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    __pad0: [u8; 4],
    duration_ns: u64,
    comm: [u8; 16],
    filename: [u8; 127],
    exit_event: u8,
}

fn main() -> Result<()> {
    let bpf_object = include_bytes!("../bootstrap.bpf.o");
    let mut obj = ObjectBuilder::default()
        .debug(true)
        .open_memory(bpf_object)
        .with_context(|| anyhow!("Failed to open"))?
        .load()
        .with_context(|| anyhow!("Failed to load"))?;
    let mut links = vec![];
    for prog in obj.progs_iter_mut() {
        println!("Attach: {}", prog.name());
        links.push(prog.attach()?);
    }
    let map = obj.map("rb").unwrap();
    let mut poll = RingBufferBuilder::new();
    poll.add(&map, |v| {
        let event_slice = unsafe { slice::from_raw_parts(v.as_ptr() as *const Event, 1) };
        let event = &event_slice[0];
        let pid = event.pid;
        let ppid = event.ppid;
        let exit_code = event.exit_code;
        if event.exit_event == 1 {
            print!(
                "{:<8} {:<5} {:<16} {:<7} {:<7} [{}]",
                "TIME",
                "EXIT",
                unsafe { CStr::from_ptr(event.comm.as_ptr() as *const i8) }
                    .to_str()
                    .unwrap(),
                pid,
                ppid,
                exit_code
            );
            if event.duration_ns != 0 {
                print!(" ({}ms)", event.duration_ns / 1000000);
            }
            println!();
        } else {
            println!(
                "{:<8} {:<5} {:<16} {:<7} {:<7} {}",
                "TIME",
                "EXEC",
                unsafe { CStr::from_ptr(event.comm.as_ptr() as *const i8) }
                    .to_str()
                    .unwrap(),
                pid,
                ppid,
                unsafe { CStr::from_ptr(event.filename.as_ptr() as *const i8) }
                    .to_str()
                    .unwrap()
            );
        }
        0
    })?;

    let poll = poll.build()?;
    loop {
        poll.poll(Duration::from_millis(100))?;
    }
}
