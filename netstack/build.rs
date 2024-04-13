use std::env;

fn main() {
    let mut target = env::current_dir().unwrap();
    target.pop();
    target.push("rustbpf");
    target.push("target");

    println!("cargo:rustc-link-search=native={}", target.display());
    println!("cargo:rustc-link-lib=static=netstack")
}
