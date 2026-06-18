# Harmonia tests

First proof ladder:

```text
cargo test
cargo run -p harmonia -- explain
cargo run -p harmonia -- inspect-profile profiles/homeserver/index.json
cargo run -p harmonia -- plan-run profiles/homeconsole/index.json --receipt-dir /tmp/harmonia-receipts
```

Future LAN proof runs copy the binary plus selected profile to insulated roots on reachable machines and collect receipts before live promotion.
