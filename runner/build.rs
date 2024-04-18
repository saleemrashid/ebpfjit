use std::env;

const PACKAGES: &'static [&'static str] = &["netstack"];

fn main() {
    let native = env::var("CARGO_FEATURE_NATIVE").is_ok();

    if !native {
        let mut target = env::current_dir().unwrap();
        target.push("../modules/target");

        println!("cargo:rustc-link-search=native={}", target.display());
        for package in PACKAGES {
            println!("cargo:rerun-if-changed={}/lib{package}.a", target.display());
            println!("cargo:rustc-link-lib=static={}", package);
        }
    }
}
