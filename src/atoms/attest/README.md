# Attest

Before serialization, `attest` recursively scrubs every caller-injected declared secret substring. The same redacted receipt is appended to `appliance.log` and forwarded to Hyalos through the existing redaction hook.
