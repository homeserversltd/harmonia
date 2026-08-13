fn health_probe(health_url: &str, retries: usize, timeout_secs: u64) -> CmdResult {
    tools::health::curl_probe(&tools::health::ProbeRequest {
        url: health_url,
        retries,
        timeout_secs,
        expected_contains: None,
    })
}
