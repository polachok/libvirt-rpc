extern crate xdrgen;

fn main() {
    xdrgen::compile("virnetprotocol.x").unwrap();
}
