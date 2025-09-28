# Payment Proxy Tool

A small Python tool that launches a local MITM proxy (mitmproxy) to intercept a specific API response from your site while you browse. It lets you manually edit a JSON field (default `payment_price`) before the response continues to the browser.

## Features
- **Start proxy + browser** with `launcher.py`.
- **Match target requests** by host and a substring in the URL path.
- **Pause and edit** the first matching JSON response in-console.
- **Deep JSON search** including inside arrays; choose which occurrence to edit if there are multiple.

## Requirements
- Windows
- Python 3.10+ recommended
- Google Chrome installed (or start your own browser configured to use the proxy)

## Setup
```powershell
# (Optional) Create and activate a virtualenv
py -3 -m venv .venv
. .venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

## First run: install the mitm certificate
When using a MITM proxy, the browser must trust the generated certificate.

1. Start the launcher pointing to `http://mitm.it`:
   ```powershell
   python launcher.py --url http://mitm.it
   ```
2. In the opened Chrome window, follow instructions on the page to install the certificate for Windows and for Chrome (if prompted). This is a one‑time step per machine/user profile.

## Usage
Typical command for your case (based on your screenshot):
```powershell
python launcher.py \
  --url https://your-site.example \
  --target-host api.spl.web-live.link \
  --target-path-substr purchase_settings \
  --json-key payment_price
```
- **--target-host**: only intercept this host (optional but recommended).
- **--target-path-substr**: substring that must appear in the request path.
- **--json-key**: the JSON key to edit in the response.
- **--once / --no-once**: intercept only the first match (default on). Use `--no-once` to keep intercepting.

If Chrome is not auto-detected, provide its path:
```powershell
python launcher.py --chrome "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --url https://your-site.example
```

### What happens when a match is found
- The tool prints the current value of the field and asks you to paste new JSON for that field.
- Press Enter to keep the value unchanged, or paste new JSON (e.g. `{ "price": 0.01, "currency": "eur" }`).
- After you confirm, the response continues to the browser with the new data.

## Notes
- This intercepts and edits the browser’s view of the API response. It does not change the server.
- Use responsibly and only against systems you own or have permission to test.

## Troubleshooting
- If pages don’t load: ensure Chrome was launched with the `--proxy-server` option (the launcher does this) and that the mitm certificate is installed.
- If your site forces HSTS or blocks proxies, you may need to use a separate Chrome profile (the launcher creates a temporary profile) and `--ignore-certificate-errors` flag (already set).
- Check console output for mitmproxy errors.
