import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_PORT = 8080

COMMON_CHROME_PATHS = [
    r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe"),
]


def find_chrome(custom_path: str | None) -> str | None:
    if custom_path and Path(custom_path).exists():
        return custom_path
    for p in COMMON_CHROME_PATHS:
        if p and Path(p).exists():
            return p
    return shutil.which("chrome") or shutil.which("google-chrome")


def start_mitmdump(port: int, addon_path: str, opts: dict[str, str | bool]) -> subprocess.Popen:
    set_parts = []
    for k, v in opts.items():
        if isinstance(v, bool):
            v = "true" if v else "false"
        set_parts.append(f"{k}={v}")
    set_arg = ",".join(set_parts)
    cmd = [
        sys.executable.replace("pythonw.exe", "python.exe"),
        "-m",
        "mitmproxy.tools.main",
        "mitmdump",
        "-p",
        str(port),
        "-s",
        f"{addon_path}",
        "--set",
        set_arg,
    ]
    print("Starting mitmdump:", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc


def wait_for_proxy(proc: subprocess.Popen, timeout_sec: int = 10) -> None:
    start = time.time()
    while time.time() - start < timeout_sec:
        if proc.poll() is not None:
            raise RuntimeError("mitmdump exited early. Check output for errors.")
        # mitm starts fast; just sleep briefly
        time.sleep(0.3)
        return
    # If we reach here, we still assume it's up; user can see logs.


def open_chrome_with_proxy(chrome_path: str, url: str, port: int) -> subprocess.Popen:
    user_data_dir = tempfile.mkdtemp(prefix="chrome-mitm-")
    args = [
        chrome_path,
        f"--proxy-server=http://127.0.0.1:{port}",
        "--disable-features=BlockInsecurePrivateNetworkRequests",
        "--ignore-certificate-errors",
        f"--user-data-dir={user_data_dir}",
        url,
    ]
    print("Launching Chrome:", " ".join(args))
    return subprocess.Popen(args)


def main():
    parser = argparse.ArgumentParser(description="Launch a MITM proxy and open a browser to monitor and edit payment responses.")
    parser.add_argument("--url", default="http://mitm.it", help="URL to open after proxy starts.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Proxy port (default 8080).")
    parser.add_argument("--chrome", default=None, help="Path to Chrome executable. If omitted, will try common paths.")

    # Interceptor options
    parser.add_argument("--target-host", default="", help="Only intercept this host (optional). Example: api.spl.web-live.link")
    parser.add_argument("--target-path-substr", default="purchase_settings", help="Substring in request path to intercept.")
    parser.add_argument("--json-key", default="payment_price", help="JSON key to modify in response.")
    parser.add_argument("--once", action="store_true", help="Intercept only the first match (default ON). Use --no-once to disable.")
    parser.add_argument("--no-once", dest="once", action="store_false")
    parser.set_defaults(once=True)

    args = parser.parse_args()

    addon_path = str(Path(__file__).with_name("payment_interceptor.py"))
    if not Path(addon_path).exists():
        print("Addon file not found:", addon_path)
        sys.exit(1)

    # Start mitmdump
    opts = {
        "target_host": args.target_host,
        "target_path_substr": args.target_path_substr,
        "json_key": args.json_key,
        "intercept_once": args.once,
    }
    mitm_proc = start_mitmdump(args.port, addon_path, opts)
    print("Proxy output will follow. First time: open", "http://mitm.it", "in the proxied browser to install the certificate.")
    wait_for_proxy(mitm_proc)

    # Launch Chrome
    chrome_path = find_chrome(args.chrome)
    chrome_proc = None
    if chrome_path:
        try:
            chrome_proc = open_chrome_with_proxy(chrome_path, args.url, args.port)
        except Exception as e:
            print("Failed to launch Chrome:", e)
    else:
        print("Chrome not found. You can still manually configure your browser to use the proxy 127.0.0.1:" + str(args.port))

    def shutdown(*_):
        print("\nShutting down...")
        if chrome_proc and chrome_proc.poll() is None:
            try:
                chrome_proc.terminate()
            except Exception:
                pass
        if mitm_proc and mitm_proc.poll() is None:
            try:
                mitm_proc.terminate()
            except Exception:
                pass
        time.sleep(0.5)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Pipe mitm output to console
    try:
        if mitm_proc.stdout:
            for line in mitm_proc.stdout:
                print(line.rstrip())
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
