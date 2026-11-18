# AI Guardrails & PII Firewall Benchmark Results

- **Evaluation Date:** 2026-11-18
- **Hardware Platform:** Apple A18 Pro (8.0 GB RAM)
- **Operating System:** Darwin 25.4.0
- **Python Version:** 3.14.6

---

## 1. PII Redaction & Reversible Pseudonymization

| Metric | Result | Notes |
| :--- | :--- | :--- |
| **Samples Evaluated** | `500` synthetic records | Emails, PPSNs, IBANs, Phone numbers, IPs, Credit Cards |
| **Reversible Restoration Accuracy** | **`100.0%`** | 100% exact match between original and restored text |
| **Median Latency (p50)** | **`13.71 µs`** | Regex detection + reversible token generation |
| **95th Percentile Latency (p95)** | **`21.63 µs`** | Multi-entity PII token substitution |
| **Redaction Throughput** | **`54,473.8 docs/sec`** | End-to-end PII masking and tokenization rate |

---

## 2. Unicode Homoglyph Normalization & Jailbreak Defense

| Metric | Result | Notes |
| :--- | :--- | :--- |
| **Adversarial Vectors Evaluated** | `200` samples | DAN mode, Cyrillic lookalikes, zero-width chars, roleplays |
| **Jailbreak Interception Rate** | **`100.0%`** | 100% of obfuscated attacks neutralized |
| **Median Detection Latency (p50)** | **`6.96 µs`** | NFKC normalization + homoglyph translation |
| **95th Percentile Latency (p95)** | **`7.54 µs`** | Multi-pattern regex matching overhead |

---

## Reproduce Benchmarks

```bash
python scripts/run_firewall_benchmarks.py
```
