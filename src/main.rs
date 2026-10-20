fn main() {
    let code = harmonia::invoke_with_exit_code(std::env::args().skip(1).collect());
    if code != 0 {
        std::process::exit(code);
    }
}
