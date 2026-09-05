use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=HARMONIA_COMPONENT");
    let component = env::var("HARMONIA_COMPONENT").unwrap_or_else(|_| "harmonia".to_string());
    println!("cargo:rustc-env=HARMONIA_COMPONENT={component}");

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
