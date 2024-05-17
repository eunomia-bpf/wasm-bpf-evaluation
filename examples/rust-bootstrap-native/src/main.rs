use std::{
    ffi::{c_void, CStr, CString},
    slice,
};

use libbpf_sys::{
    bpf_object__find_map_fd_by_name, bpf_object__find_program_by_name, bpf_object__load,
    bpf_object__open_mem, bpf_program__attach, ring_buffer__new, ring_buffer__poll,
};

fn main() {
    // embed and open the bpf object
    let bpf_object = include_bytes!("../bootstrap.bpf.o");
    // load the object
    // let obj_ptr =
    //     binding::wasm_load_bpf_object(bpf_object.as_ptr() as u32, bpf_object.len() as i32);
    let obj_ptr = unsafe {
        bpf_object__open_mem(
            bpf_object.as_ptr() as *const c_void,
            bpf_object.len().try_into().unwrap(),
            std::ptr::null(),
        )
    };

    if obj_ptr.is_null() {
        println!("Failed to load bpf object");
        return;
    }
    unsafe { bpf_object__load(obj_ptr) };
    {
        let prog = unsafe {
            bpf_object__find_program_by_name(obj_ptr, CString::new("handle_exec").unwrap().as_ptr())
        };

        let link = unsafe { bpf_program__attach(prog) };

        if link.is_null() {
            println!("Unable to attach handle_exec");
            return;
        }
    }

    {
        let prog = unsafe {
            bpf_object__find_program_by_name(obj_ptr, CString::new("handle_exit").unwrap().as_ptr())
        };

        let link = unsafe { bpf_program__attach(prog) };

        if link.is_null() {
            println!("Unable to attach handle_exit");
            return;
        }
    }
    let map_fd =
        unsafe { bpf_object__find_map_fd_by_name(obj_ptr, CString::new("rb").unwrap().as_ptr()) };
    // get the map fd for ring buffer
    if map_fd < 0 {
        println!("Failed to get map fd: {}", map_fd);
        return;
    }
    let rb = unsafe {
        ring_buffer__new(
            map_fd,
            Some(handle_event),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    loop {
        // polling the buffer
        unsafe { ring_buffer__poll(rb, 100) };
    }
}

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

/// handle ring buffer events
extern "C" fn handle_event(_ctx: *mut c_void, data: *mut c_void, _data_sz: u64) -> i32 {
    let event_slice = unsafe { slice::from_raw_parts(data as *const Event, 1) };
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
    return 0;
}
