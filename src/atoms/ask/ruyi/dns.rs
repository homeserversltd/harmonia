//! Bounded native DNS transport, parsing, configuration, and focused tests.
use super::valid_name;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_MAX_NAMESERVERS: usize = 3;
const DNS_RESPONSE_BUFFER: usize = 4096;
const DNS_MALFORMED: &str = "ruyi-local-dns-response-malformed";
const DNS_QUERY_FAILED: &str = "ruyi-local-dns-query-failed";
const DNS_QUERY_TIMEOUT_ERROR: &str = "ruyi-local-dns-query-timeout";
const DNS_SERVFAIL: &str = "ruyi-local-dns-response-servfail";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DnsLookup {
    Absent,
    Answers(Vec<Ipv4Addr>),
}

trait DnsTransport {
    fn exchange(
        &mut self,
        nameserver: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String>;
}

struct UdpDnsTransport;

impl DnsTransport for UdpDnsTransport {
    fn exchange(
        &mut self,
        nameserver: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let bind = if nameserver.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|_| DNS_QUERY_FAILED.to_string())?;
        socket
            .connect(nameserver)
            .map_err(|_| DNS_QUERY_FAILED.to_string())?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|_| DNS_QUERY_FAILED.to_string())?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| DNS_QUERY_FAILED.to_string())?;
        socket.send(query).map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                DNS_QUERY_TIMEOUT_ERROR.to_string()
            }
            _ => DNS_QUERY_FAILED.to_string(),
        })?;
        let mut response = [0_u8; DNS_RESPONSE_BUFFER];
        let length = socket
            .recv(&mut response)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                    DNS_QUERY_TIMEOUT_ERROR.to_string()
                }
                _ => DNS_QUERY_FAILED.to_string(),
            })?;
        Ok(response[..length].to_vec())
    }
}

fn configured_nameservers(contents: &str) -> Vec<SocketAddr> {
    let mut nameservers = Vec::new();
    for line in contents.lines() {
        let fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>();
        if fields.first() != Some(&"nameserver") {
            continue;
        }
        let Some(address) = fields.get(1).and_then(|value| value.parse::<IpAddr>().ok()) else {
            continue;
        };
        let nameserver = SocketAddr::new(address, 53);
        if !nameservers.contains(&nameserver) {
            nameservers.push(nameserver);
        }
        if nameservers.len() == DNS_MAX_NAMESERVERS {
            break;
        }
    }
    nameservers
}

fn dns_query_id() -> u16 {
    static NEXT_ID: AtomicU16 = AtomicU16::new(0x5259);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn encode_dns_name(name: &str, output: &mut Vec<u8>) -> Result<(), String> {
    if !valid_name(name) {
        return Err("ruyi-local-dns-name-invalid".into());
    }
    for label in name.split('.') {
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

fn build_dns_query(name: &str, id: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(12 + name.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    // QR=0, opcode=0, RD=1, one A/IN question.
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    encode_dns_name(name, &mut query)?;
    query.extend_from_slice(&[0, 1, 0, 1]);
    Ok(query)
}

fn read_dns_u16(packet: &[u8], offset: &mut usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| DNS_MALFORMED.to_string())?;
    let bytes = packet
        .get(*offset..end)
        .ok_or_else(|| DNS_MALFORMED.to_string())?;
    *offset = end;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn decode_dns_name(packet: &[u8], offset: &mut usize) -> Result<Vec<Vec<u8>>, String> {
    let mut cursor = *offset;
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut pointer_hops = 0;
    let mut encoded_length = 1_usize;

    loop {
        if pointer_hops > packet.len() {
            return Err(DNS_MALFORMED.into());
        }
        let length = *packet
            .get(cursor)
            .ok_or_else(|| DNS_MALFORMED.to_string())?;
        if length & 0xc0 == 0xc0 {
            let pointer_byte = *packet
                .get(
                    cursor
                        .checked_add(1)
                        .ok_or_else(|| DNS_MALFORMED.to_string())?,
                )
                .ok_or_else(|| DNS_MALFORMED.to_string())?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(pointer_byte);
            if target >= packet.len() {
                return Err(DNS_MALFORMED.into());
            }
            if !jumped {
                *offset = cursor
                    .checked_add(2)
                    .ok_or_else(|| DNS_MALFORMED.to_string())?;
                encoded_length = encoded_length
                    .checked_add(1)
                    .ok_or_else(|| DNS_MALFORMED.to_string())?;
            }
            cursor = target;
            jumped = true;
            pointer_hops += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DNS_MALFORMED.into());
        }
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| DNS_MALFORMED.to_string())?;
        encoded_length = encoded_length
            .checked_add(usize::from(length) + 1)
            .ok_or_else(|| DNS_MALFORMED.to_string())?;
        if encoded_length > 255 {
            return Err(DNS_MALFORMED.into());
        }
        if length == 0 {
            if !jumped {
                *offset = cursor;
            }
            return Ok(labels);
        }
        let end = cursor
            .checked_add(usize::from(length))
            .ok_or_else(|| DNS_MALFORMED.to_string())?;
        let label = packet
            .get(cursor..end)
            .ok_or_else(|| DNS_MALFORMED.to_string())?;
        labels.push(label.to_vec());
        cursor = end;
    }
}

fn dns_names_equal(left: &[Vec<u8>], right: &str) -> bool {
    let right = right.split('.').map(str::as_bytes).collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn read_dns_record(
    packet: &[u8],
    offset: &mut usize,
    section: u8,
    expected_name: &str,
    answers: &mut Vec<Ipv4Addr>,
    saw_unsupported_cname: &mut bool,
) -> Result<(), String> {
    let owner = decode_dns_name(packet, offset)?;
    let record_type = read_dns_u16(packet, offset)?;
    let class = read_dns_u16(packet, offset)?;
    let ttl_end = offset
        .checked_add(4)
        .ok_or_else(|| DNS_MALFORMED.to_string())?;
    if packet.get(*offset..ttl_end).is_none() {
        return Err(DNS_MALFORMED.into());
    }
    *offset = ttl_end;
    let data_length = usize::from(read_dns_u16(packet, offset)?);
    let data_end = offset
        .checked_add(data_length)
        .ok_or_else(|| DNS_MALFORMED.to_string())?;
    let data = packet
        .get(*offset..data_end)
        .ok_or_else(|| DNS_MALFORMED.to_string())?;

    if section == 0 && class == 1 && (record_type == 1 || record_type == 5) {
        if !dns_names_equal(&owner, expected_name) {
            return Err("ruyi-local-dns-answer-owner-mismatch".into());
        }
        if record_type == 1 {
            if data.len() != 4 {
                return Err(DNS_MALFORMED.into());
            }
            answers.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        } else {
            let mut cname_offset = *offset;
            decode_dns_name(packet, &mut cname_offset)?;
            if cname_offset != data_end {
                return Err(DNS_MALFORMED.into());
            }
            *saw_unsupported_cname = true;
        }
    }
    *offset = data_end;
    Ok(())
}

fn parse_dns_response(
    packet: &[u8],
    query_id: u16,
    expected_name: &str,
) -> Result<DnsLookup, String> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != query_id {
        return Err(DNS_MALFORMED.into());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // QR must be set; opcode and the reserved Z bit must be zero. AD/CD are
    // defined DNSSEC flags, while TC is rejected without a bounded TCP path.
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 || flags & 0x0040 != 0 {
        return Err(DNS_MALFORMED.into());
    }
    if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return Err(DNS_MALFORMED.into());
    }
    let answer_count = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    let authority_count = usize::from(u16::from_be_bytes([packet[8], packet[9]]));
    let additional_count = usize::from(u16::from_be_bytes([packet[10], packet[11]]));

    let mut offset = 12;
    let question_name = decode_dns_name(packet, &mut offset)?;
    if !dns_names_equal(&question_name, expected_name)
        || read_dns_u16(packet, &mut offset)? != 1
        || read_dns_u16(packet, &mut offset)? != 1
    {
        return Err(DNS_MALFORMED.into());
    }

    let mut answers = Vec::new();
    let mut saw_unsupported_cname = false;
    for (section, count) in [
        (0_u8, answer_count),
        (1_u8, authority_count),
        (2_u8, additional_count),
    ] {
        for _ in 0..count {
            read_dns_record(
                packet,
                &mut offset,
                section,
                expected_name,
                &mut answers,
                &mut saw_unsupported_cname,
            )?;
        }
    }
    if offset != packet.len() {
        return Err(DNS_MALFORMED.into());
    }
    if saw_unsupported_cname {
        return Err("ruyi-local-dns-cname-unsupported".into());
    }

    match flags & 0x000f {
        0 if answers.is_empty() => Ok(DnsLookup::Absent),
        0 => Ok(DnsLookup::Answers(answers)),
        3 if answers.is_empty() => Ok(DnsLookup::Absent),
        3 => Err(DNS_MALFORMED.into()),
        2 => Err(DNS_SERVFAIL.into()),
        _ => Err("ruyi-local-dns-response-failed".into()),
    }
}

fn resolve_ipv4_with_transport<T: DnsTransport>(
    canonical_name: &str,
    nameserver: SocketAddr,
    transport: &mut T,
) -> Result<DnsLookup, String> {
    let query_id = dns_query_id();
    let query = build_dns_query(canonical_name, query_id)?;
    let response = transport.exchange(nameserver, &query, DNS_QUERY_TIMEOUT)?;
    parse_dns_response(&response, query_id, canonical_name)
}

fn retryable_failure(error: &str) -> bool {
    matches!(
        error,
        DNS_QUERY_FAILED | DNS_QUERY_TIMEOUT_ERROR | DNS_SERVFAIL
    )
}

fn resolve_ipv4_from_config<T: DnsTransport>(
    canonical_name: &str,
    contents: &str,
    transport: &mut T,
) -> Result<DnsLookup, String> {
    let nameservers = configured_nameservers(contents);
    if nameservers.is_empty() {
        return Err("ruyi-local-dns-nameserver-absent".into());
    }
    let mut last_error = None;
    for nameserver in nameservers {
        match resolve_ipv4_with_transport(canonical_name, nameserver, transport) {
            Ok(lookup) => return Ok(lookup),
            Err(error) if retryable_failure(&error) => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| DNS_QUERY_FAILED.to_string()))
}

pub(crate) fn resolve_ipv4(canonical_name: String) -> Result<DnsLookup, String> {
    let contents = fs::read_to_string("/etc/resolv.conf")
        .map_err(|_| "ruyi-local-dns-config-unavailable".to_string())?;
    resolve_ipv4_from_config(&canonical_name, &contents, &mut UdpDnsTransport)
}
