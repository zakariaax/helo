#!/usr/bin/env python3
"""Local web app for bulk TLD checks. Binds to 127.0.0.1 only.

Run: python3 server.py
Then open http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import checker

INDEX_PATH = Path(__file__).resolve().parent / "index.html"
MAX_BODY = 2_000_000


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._serve_index()
        elif path == "/api/defaults":
            boot = _bootstrap_if_ready()
            presets = checker.load_presets()
            payload = {
                "text": "\n".join(presets["all"]),
                "defaultPreset": "all",
                "presets": {
                    "all": presets["all"],
                    "famous": presets["famous"],
                    "launch": presets["launch"],
                    "countries": presets["countries"],
                },
                "maxNames": checker.MAX_NAMES,
                "maxTlds": checker.MAX_TLDS,
            }
            if boot is not None:
                payload["publication"] = boot.publication
                payload["bootstrapError"] = boot.error
                payload["suffixCount"] = len(boot.suffixes)
            self._send_json(payload)
        elif path == "/api/rdap-suffixes":
            boot = checker.get_bootstrap()
            self._send_json(
                {
                    "publication": boot.publication,
                    "error": boot.error,
                    "count": len(boot.suffixes),
                    "suffixes": sorted(boot.suffixes),
                }
            )
        elif path in ("/browser-check.js", "/tld_presets.json"):
            self._serve_static(path[1:])
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self._send_json({"error": "Not found."}, status=404)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            body = self._read_json()
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        if path == "/api/parse":
            self._handle_parse(body)
        elif path == "/api/check":
            self._handle_check(body)
        else:
            self._send_json({"error": "Not found."}, status=404)

    def _handle_parse(self, body: dict) -> None:
        outcome = checker.parse_input(body.get("names", ""), body.get("tlds", ""))
        boot = checker.get_bootstrap()
        coverage = checker.coverage_for([tld.ascii for tld in outcome.tlds], boot)
        self._send_json(
            {
                "names": [{"ascii": name.ascii, "display": name.display} for name in outcome.names],
                "tlds": [{"ascii": tld.ascii, "display": tld.display} for tld in outcome.tlds],
                "skipped": outcome.skipped[:40],
                "skippedCount": len(outcome.skipped),
                "duplicateCount": outcome.duplicate_count,
                "error": outcome.error,
                "coverage": coverage,
                "publication": boot.publication,
                "bootstrapError": boot.error,
                "suffixCount": len(boot.suffixes),
            }
        )

    def _handle_check(self, body: dict) -> None:
        raw_checks = body.get("checks")
        if not isinstance(raw_checks, list):
            self._send_json({"error": "Expected a list of checks."}, status=400)
            return
        if len(raw_checks) > checker.MAX_NAMES * checker.MAX_TLDS:
            self._send_json({"error": "That batch is too large. Split the list and check again."}, status=400)
            return
        fresh = bool(body.get("fresh"))
        pairs: list[tuple[checker.ParsedName, checker.ParsedName]] = []
        for item in raw_checks:
            try:
                pairs.append(_coerce_pair(item))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
        self._stream(pairs, fresh)

    def _stream(self, pairs: list[tuple[checker.ParsedName, checker.ParsedName]], fresh: bool) -> None:
        cancel = threading.Event()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b": ok\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

        boot = checker.get_bootstrap()
        tlds = []
        seen = set()
        for _name, tld in pairs:
            if tld.ascii not in seen:
                seen.add(tld.ascii)
                tlds.append(tld.ascii)
        coverage = checker.coverage_for(tlds, boot)
        if not _emit(
            self,
            {
                "type": "meta",
                "total": len(pairs),
                "publication": boot.publication,
                "bootstrapError": boot.error,
                "suffixCount": len(boot.suffixes),
                "rdapTlds": coverage["rdap"],
                "dnsTlds": coverage["dns"],
            },
        ):
            return
        if not pairs:
            _emit(self, {"type": "done", "completed": 0, "total": 0})
            return

        results: queue.Queue = queue.Queue()

        def run(pair: tuple[checker.ParsedName, checker.ParsedName]) -> None:
            name, tld = pair
            if cancel.is_set():
                results.put(None)
                return
            try:
                results.put(checker.check_pair(name.ascii, name.display, tld, boot, fresh=fresh))
            except Exception:
                results.put(
                    {
                        "type": "result",
                        "name": name.ascii,
                        "display": name.display,
                        "tld": tld.ascii,
                        "tldDisplay": tld.display,
                        "fqdn": f"{name.ascii}.{tld.ascii}",
                        "status": "unknown",
                        "method": "rdap" if checker.urls_for_domain(f"example.{tld.ascii}", boot) else "dns",
                        "confidence": "none",
                        "detail": "The lookup failed. Marked unknown, not available.",
                        "cached": False,
                    }
                )

        workers = min(28, max(1, len(pairs)))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tld")
        started = time.time()
        try:
            for pair in pairs:
                pool.submit(run, pair)
            completed = 0
            while completed < len(pairs):
                try:
                    item = results.get(timeout=0.5)
                except queue.Empty:
                    if cancel.is_set():
                        break
                    continue
                completed += 1
                if item is not None and not _emit(self, item):
                    cancel.set()
                    break
            _emit(
                self,
                {
                    "type": "done",
                    "completed": completed,
                    "total": len(pairs),
                    "seconds": round(time.time() - started, 2),
                },
            )
        except (BrokenPipeError, ConnectionResetError):
            cancel.set()
        finally:
            cancel.set()
            pool.shutdown(wait=False, cancel_futures=True)

    def _serve_index(self) -> None:
        try:
            payload = INDEX_PATH.read_bytes()
        except OSError:
            self._send_json({"error": "index.html is missing."}, status=500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _serve_static(self, name: str) -> None:
        path = INDEX_PATH.parent / name
        try:
            payload = path.read_bytes()
        except OSError:
            self._send_json({"error": "Not found."}, status=404)
            return
        kind = "application/json" if name.endswith(".json") else "text/javascript; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict:
        length = self.headers.get("Content-Length")
        if length is None:
            raise ValueError("Missing request body.")
        try:
            size = int(length)
        except ValueError as exc:
            raise ValueError("Invalid request body.") from exc
        if size < 0 or size > MAX_BODY:
            raise ValueError("Request body is too large.")
        raw = self.rfile.read(size)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body was not JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object.")
        return data

    def _send_json(self, payload: dict, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


def _bootstrap_if_ready() -> checker.Bootstrap | None:
    return checker.peek_bootstrap()


def _coerce_pair(item: object) -> tuple[checker.ParsedName, checker.ParsedName]:
    if not isinstance(item, dict):
        raise ValueError("Each check must be an object.")
    raw_name = str(item.get("name") or "").strip().lower()
    raw_tld = str(item.get("tld") or "").strip().lower().lstrip(".")
    try:
        name = checker.extract_name(raw_name)
        tld = checker.parse_tld_token(raw_tld)
    except ValueError as exc:
        raise ValueError(f"Invalid check ({exc}).") from exc
    if name.ascii != raw_name or tld.ascii != raw_tld:
        raise ValueError("Send each name as a single label and each TLD without a leading dot.")
    return name, tld


def _emit(handler: Handler, payload: dict) -> bool:
    raw = ("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8")
    try:
        handler.wfile.write(raw)
        handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Local bulk TLD checker")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    threading.Thread(target=checker.get_bootstrap, name="rdap-bootstrap", daemon=True).start()
    server = make_server("127.0.0.1", args.port)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Bulk TLD checker running at {url}", flush=True)
    print("Lookups stay on this machine: IANA RDAP bootstrap, registry RDAP, and public DNS.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
