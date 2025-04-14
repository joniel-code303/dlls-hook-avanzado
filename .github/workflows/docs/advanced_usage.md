# Advanced Usage Guide

## Custom Suspicious Locations
Create a `custom_rules.json` file:
```json
{
    "suspicious_paths": [
        "C:\\Malware",
        "\\\\NetworkShare\\Suspicious"
    ],
    "whitelist": [
        "C:\\Trusted\\Path"
    ]
}
```
Run with:
```bash
python escaneo_hook_dlls.py --rules custom_rules.json
```

## Memory Analysis Mode
Enable deep memory scanning:
```python
# En el código:
scan_injected_dlls(deep_scan=True)
```
