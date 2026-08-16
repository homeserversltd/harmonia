# Attest

Attest recursively redacts every caller-injected declared secret substring before serialization. It appends the redacted `Receipt`, then forwards fields derived from that same redacted value.
