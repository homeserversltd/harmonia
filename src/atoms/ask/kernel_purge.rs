//! The kernel-only subset of apt's simulated removal plan.
pub(crate) fn removal_names(output: &str) -> Vec<String> {
    output.lines().filter_map(|line| {
        let name = line.strip_prefix("Remv ")?.split_whitespace().next()?;
        Some(name.to_string())
    }).collect()
}

pub(crate) fn purge_transaction_names(output: &str) -> Vec<String> {
    output.lines().filter_map(|line| {
        let rest = line.strip_prefix("Purg ").or_else(|| line.strip_prefix("Remv "))?;
        Some(rest.split_whitespace().next()?.to_string())
    }).collect()
}

pub(crate) fn kernel_plan(output: &str) -> Vec<String> {
    removal_names(output).into_iter().filter(|name| {
        ["image", "headers", "modules", "kbuild", "binary", "base"].iter().any(|family| {
            let prefix = format!("linux-{family}-");
            name.strip_prefix(&prefix).is_some_and(|suffix| {
                suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-:".contains(&b))
            })
        })
    }).collect()
}
