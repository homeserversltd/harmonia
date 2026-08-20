fn main() {
    if let Err(err) = harmonia::invoke(std::env::args().skip(1).collect()) {
        eprintln!("harmonia_error={err}");
        std::process::exit(1);
    }
}
