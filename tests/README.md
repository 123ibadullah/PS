# PhishShield Backend Test Suite

## Run Tests

```bash
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pytest -q
```

## Included Coverage

- Safe email classification cases
- High-risk phishing classification cases
- Pipeline and endpoint stability checks
- Determinism and validation behavior checks
- Multilingual phishing checks (Hindi and Hinglish)
