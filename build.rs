use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=HARMONIA_BUILD_ENV_SHA");
    match env::var("HARMONIA_BUILD_ENV_SHA") {
        Ok(value) => {
            assert!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "HARMONIA_BUILD_ENV_SHA must be exactly 64 lowercase hexadecimal characters"
            );
            println!("cargo:rustc-env=HARMONIA_BUILD_ENV_SHA={value}");
        }
        Err(_) => println!("cargo:rustc-env=HARMONIA_BUILD_ENV_SHA=unset"),
    }
}
