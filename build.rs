extern crate xdrgen;

use std::process::Command;
use std::fs::OpenOptions;
use std::env;
use std::path::PathBuf;
use std::io::Write;

fn compile(source: &str) {
    // compiling remote_protocol.x is a bit more involved
    // first process it with cpp to eval defines
    let cpp = Command::new("/usr/bin/cpp")
    // constants from libvirt-host.h
        .arg("-include")
        .arg("libvirt-defs.h")
        .arg(source)
        .output().unwrap();

    // then write output to temporarily file
    let out_dir = env::var("OUT_DIR").unwrap();
    let mut path = PathBuf::from(out_dir);
    path.push(source);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path).unwrap();
    file.write_all(&cpp.stdout).unwrap();

    // finally run xdrgen
    let path_str = format!("{}", path.display());
    xdrgen::compile(path_str).unwrap();
}

fn main() {
    compile("virnetprotocol.x");
    compile("remote_protocol.x");
}
