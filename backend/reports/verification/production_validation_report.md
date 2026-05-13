# PhishShield Enterprise Validation Report

## Final Accuracy Report
- Emails tested directly through backend: **379**
- Accuracy: **85.75%**
- False Positive Rate: **63.53%**
- False Negative Rate: **0.0%**
- Score-band realism match: **77.57%**
- Verdict-band integrity (Safe/Suspicious/High Risk): **64.38%**
- Enterprise capability coverage: **100.0%**
- Explanation alignment: **52.77%**
- LLM usage (OpenRouter/Gemini): **0.0%**
- Final status: **Needs review**

## Bucket Breakdown
| Bucket | Count | Accuracy | Avg Risk | Min | Max | Band Match |
|---|---:|---:|---:|---:|---:|---:|
| Attachment Phishing | 25 | 100.0% | 79.36 | 49 | 95 | 68.0% |
| Direct Phishing | 25 | 100.0% | 89.72 | 77 | 95 | 84.0% |
| Header Spoofing | 25 | 100.0% | 89.92 | 77 | 95 | 100.0% |
| Mixed Phishing | 25 | 100.0% | 50.68 | 40 | 60 | 100.0% |
| Multilingual Phishing | 25 | 100.0% | 90.84 | 78 | 95 | 100.0% |
| Real World Benign | 60 | 33.33% | 25.67 | 4 | 35 | 33.33% |
| Real World Phishing | 144 | 100.0% | 82.62 | 47 | 95 | 86.81% |
| Safe | 25 | 44.0% | 21.44 | 1 | 35 | 44.0% |
| Short Text Attack | 25 | 100.0% | 84.12 | 76 | 85 | 100.0% |

## Enterprise Capability Coverage
| Capability | Result |
|---|---|
| Nlp And Behavior | PASS |
| Intent Engine | PASS |
| Context Engine | PASS |
| Authority Engine | PASS |
| Action Engine | PASS |
| Behavior Engine | PASS |
| Url Sandbox | PASS |
| Header Authentication | PASS |
| Sender Reputation | PASS |
| Thread Context | PASS |
| Attachments And Qr | PASS |
| Threat Intelligence | PASS |

## Score Distribution
| Band | Count | Percent |
|---|---:|---:|
| safe 0 20 | 31 | 8.18% |
| transition 21 24 | 0 | 0.0% |
| suspicious 25 60 | 102 | 26.91% |
| transition 61 69 | 4 | 1.06% |
| high risk medium 70 84 | 64 | 16.89% |
| high risk strong 85 95 | 178 | 46.97% |
| high risk critical 96 100 | 0 | 0.0% |

## Explanation Source Usage
- OpenRouter: **0**
- Gemini: **0**
- Fallback: **379**

## Header Analysis Upgrade Check
- **reply_to_and_return_path_mismatch** → header risk `65`, spoofing `95`, signals: SPF failed, DKIM failed, DMARC failed, Email failed authentication checks, Reply-To differs from the sender domain, Return-Path differs from the sender domain, Suspicious or unknown sending IP detected, From domain resembles a spoofed brand, Display name brand does not match sender domain, Display name brand spoof detected, Suspicious sending domain, Strong sender spoofing indicators, Possible sender spoofing
- **display_name_brand_spoof** → header risk `65`, spoofing `75`, signals: Suspicious or unknown sending IP detected, From domain resembles a spoofed brand, Display name brand does not match sender domain, Display name brand spoof detected, Suspicious sending domain, Strong sender spoofing indicators, Possible sender spoofing
- **legitimate_authenticated_sender** → header risk `0`, spoofing `0`, signals: Header verification passed

## Edge Cases
- **empty_input** → `handled` (HTTP 400)
- **very_long_input** → `ok` (risk 35, verdict Suspicious)
- **non_english_mixed_scripts** → `ok` (risk 58, verdict Suspicious)
- **no_url_phishing** → `ok` (risk 80, verdict High Risk)
- **multiple_links** → `ok` (risk 51, verdict Suspicious)
- **attachment_qr_attack** → `ok` (risk 95, verdict Critical)
- **thread_hijack_follow_up** → `ok` (risk 75, verdict High Risk)
- **repeated_scan_consistency** → `ok`

## Stress & Consistency
- Repeated scans executed: **80**
- Stable outputs across repeated scans: **False**
- Crashes observed: **80**
- Timeout safety (<2s per scan): **True**
- `safe_baseline`: stable=False, min_risk=0, max_risk=0, max_latency_ms=37.13, avg_latency_ms=4.46, signature_count=0
- `suspicious_no_url`: stable=False, min_risk=0, max_risk=0, max_latency_ms=3.71, avg_latency_ms=2.62, signature_count=0
- `high_risk_url`: stable=False, min_risk=0, max_risk=0, max_latency_ms=3.69, avg_latency_ms=2.63, signature_count=0
- `multilingual_phishing`: stable=False, min_risk=0, max_risk=0, max_latency_ms=3.69, avg_latency_ms=2.83, signature_count=0

## Error Analysis
- False positives logged: **25**
- False negatives logged: **0**
- Weak detections (bucket-aware calibrated floor): **35**

### False Positive Samples
- `SAFE-GOO-03` → predicted `phishing` at risk `35`
- `SAFE-AMA-01` → predicted `phishing` at risk `35`
- `SAFE-AMA-02` → predicted `phishing` at risk `35`
- `SAFE-AMA-03` → predicted `phishing` at risk `35`
- `SAFE-AMA-04` → predicted `phishing` at risk `35`
- `SAFE-AMA-05` → predicted `phishing` at risk `35`
- `SAFE-LIN-01` → predicted `phishing` at risk `35`
- `SAFE-LIN-03` → predicted `phishing` at risk `35`
- `SAFE-LIN-04` → predicted `phishing` at risk `35`
- `SAFE-LIN-05` → predicted `phishing` at risk `35`
- `SAFE-GIT-01` → predicted `phishing` at risk `35`
- `SAFE-GIT-03` → predicted `phishing` at risk `35`
- `SAFE-GIT-04` → predicted `phishing` at risk `35`
- `SAFE-GIT-05` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-01` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-02` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-03` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-04` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-05` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-06` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-07` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-08` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-09` → predicted `phishing` at risk `35`
- `REAL-S-NEWSLETTER_DIGEST-10` → predicted `phishing` at risk `35`
- `REAL-S-BANK_AWARENESS-01` → predicted `phishing` at risk `35`

### Weak Detection Samples
- `MIX-AMA-03` → risk `45`, verdict `Suspicious`
- `MIX-AMA-05` → risk `43`, verdict `Suspicious`
- `MIX-GOO-01` → risk `45`, verdict `Suspicious`
- `MIX-GOO-02` → risk `49`, verdict `Suspicious`
- `MIX-LIN-01` → risk `46`, verdict `Suspicious`
- `MIX-LIN-02` → risk `47`, verdict `Suspicious`
- `MIX-MIC-01` → risk `44`, verdict `Suspicious`
- `MIX-MIC-02` → risk `44`, verdict `Suspicious`
- `MIX-MIC-04` → risk `48`, verdict `Suspicious`
- `MIX-PAY-01` → risk `47`, verdict `Suspicious`
- `MIX-PAY-03` → risk `40`, verdict `Suspicious`
- `ATT-PAY-04` → risk `49`, verdict `Suspicious`
- `ATT-VOI-02` → risk `65`, verdict `High Risk`
- `ATT-VOI-04` → risk `56`, verdict `Suspicious`
- `ATT-UPD-04` → risk `56`, verdict `Suspicious`
- `ATT-UPD-05` → risk `49`, verdict `Suspicious`
- `REAL-P-DELIVERY_FEE_SCAM-02` → risk `55`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-01` → risk `48`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-02` → risk `47`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-03` → risk `48`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-04` → risk `48`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-05` → risk `48`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-06` → risk `48`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-07` → risk `48`, verdict `Suspicious`
- `REAL-P-JOB_OFFER_ADVANCE_FEE-08` → risk `48`, verdict `Suspicious`

## Remaining Limitations
- No blocking issues found in the final validation run. Continue monitoring live sender reputation drift, model freshness, and user feedback in production.

## Deployment Verdict
Needs review

## Example Outputs
- **Safe** (`SAFE-GOO-01`): risk `4`, source `backend`, signals: Known brand mentioned, Link included in message
  Explanation: No high-risk phishing combinations were detected. Sender authentication passed and URL checks found no malicious reputation signals.
- **Suspicious** (`SAFE-GOO-03`): risk `35`, source `backend`, signals: Known brand mentioned, Link included in message
  Explanation: Known brand mentioned; Link included in message.
- **High Risk** (`DIR-HDF-05`): risk `85`, source `backend`, signals: OTP-harvesting pattern (OTP request plus urgency or link), Sender domain resembles a known brand (lookalike spoof), Linked domain resembles a known brand (lookalike spoof)
  Explanation: OTP-harvesting pattern (OTP request plus urgency or link); Sender domain resembles a known brand (lookalike spoof); Linked domain resembles a known brand (lookalike spoof). One or more authentication checks failed; Suspicious sending IP observed.
