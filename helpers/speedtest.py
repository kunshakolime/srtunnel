"""
helpers/speedtest.py
Speedtest-CLI wrapper: launch, poll progress, parse result, format output.
No Telegram imports. No side effects on import.
"""

import json
import logging
import os
import subprocess
import tempfile

logger = logging.getLogger(__name__)


# ── Launch ────────────────────────────────────────────────────────────────────

def start() -> tuple:
    """
    Launch speedtest in the background.
    Returns (proc, progress_file_path).
    The progress file receives one JSON blob per event (json-pretty format).
    """
    progress_file = tempfile.mktemp(suffix=".speedtest.jsonl")
    proc = subprocess.Popen(
        [
            "speedtest",
            "--format=json-pretty",
            "--progress=yes",
            "--accept-license",
            "--accept-gdpr",
        ],
        stdout=open(progress_file, "w"),
        stderr=subprocess.DEVNULL,
    )
    return proc, progress_file


# ── Poll ──────────────────────────────────────────────────────────────────────

def poll(progress_file: str) -> dict | None:
    """
    Read the latest progress event from the progress file.
    Returns a dict — all keys are optional / may be absent:

        pct     – int  0-100
        speed   – str  e.g. "45.3 Mbps"
        eta     – str  e.g. "12s"   (absent during ping / starting phase)
        phase   – str  "download" | "upload" | "ping" | "starting"

    The bot must use .get() on every key — never index directly.
    """
    try:
        text = open(progress_file).read().strip()
        if not text:
            return None

        # json-pretty spans multiple lines; try line-by-line first, then whole blob
        last = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                pass

        if last is None:
            try:
                last = json.loads(text)
            except json.JSONDecodeError:
                return None

        if last is None:
            return None

        typ = last.get("type", "")

        if typ == "testStart":
            return {"pct": 0, "phase": "starting"}

        if typ == "ping":
            return {"pct": 5, "phase": "ping"}

        if typ in ("download", "upload"):
            key      = typ
            bw_bytes = last.get(key, {}).get("bandwidth", 0)
            mbps     = round(bw_bytes * 8 / 1_048_576, 1) if bw_bytes else 0
            elapsed  = last.get(key, {}).get("elapsed", 0)
            # No percent in progress events — estimate from elapsed (typical run ~15 s)
            base_pct = 10 if typ == "download" else 55   # download=10-50, upload=55-95
            pct      = min(base_pct + int(elapsed / 150), base_pct + 45)
            eta_s    = max(0, int((15_000 - elapsed) / 1_000))
            return {
                "pct":   pct,
                "speed": f"{mbps} Mbps",
                "eta":   f"{eta_s}s",
                "phase": typ,
            }

        if typ == "result":
            return parse_result_blob(last)

    except Exception as e:
        logger.debug(f"speedtest.poll: {e}")

    return None


# ── Parse final result ────────────────────────────────────────────────────────

def parse_result(progress_file: str) -> dict | None:
    """
    Call after proc finishes. Reads the final result blob from the file.
    Returns a rich flat dict, or None on failure.
    """
    try:
        text = open(progress_file).read().strip()
        data = json.loads(text)
        if data.get("type") == "result" or ("download" in data and "upload" in data):
            return parse_result_blob(data)
    except Exception as e:
        logger.debug(f"speedtest.parse_result: {e}")
    return None


def parse_result_blob(d: dict) -> dict:
    """Turn a raw CF result JSON blob into a flat bot-ready dict."""
    dl    = d.get("download",  {})
    ul    = d.get("upload",    {})
    ping  = d.get("ping",      {})
    iface = d.get("interface", {})
    srv   = d.get("server",    {})
    res   = d.get("result",    {})

    dl_mbps = _mbps(dl.get("bandwidth"))
    ul_mbps = _mbps(ul.get("bandwidth"))

    return {
        # speeds
        "dl_mbps":       dl_mbps,
        "ul_mbps":       ul_mbps,
        "dl_bytes":      dl.get("bytes"),
        "ul_bytes":      ul.get("bytes"),
        # latency
        "ping_ms":       ping.get("latency"),
        "ping_jitter":   ping.get("jitter"),
        "ping_low":      ping.get("low"),
        "ping_high":     ping.get("high"),
        # download latency
        "dl_lat_iqm":    dl.get("latency", {}).get("iqm"),
        "dl_lat_low":    dl.get("latency", {}).get("low"),
        "dl_lat_high":   dl.get("latency", {}).get("high"),
        "dl_lat_jitter": dl.get("latency", {}).get("jitter"),
        # upload latency
        "ul_lat_iqm":    ul.get("latency", {}).get("iqm"),
        "ul_lat_low":    ul.get("latency", {}).get("low"),
        "ul_lat_high":   ul.get("latency", {}).get("high"),
        "ul_lat_jitter": ul.get("latency", {}).get("jitter"),
        # misc
        "packet_loss":   d.get("packetLoss", 0),
        "isp":           d.get("isp", ""),
        "external_ip":   iface.get("externalIp", ""),
        "iface_name":    iface.get("name", ""),
        # server
        "server_name":     srv.get("name", ""),
        "server_location": srv.get("location", ""),
        "server_country":  srv.get("country", ""),
        "server_host":     srv.get("host", ""),
        "server_ip":       srv.get("ip", ""),
        # result link
        "result_url":    res.get("url", ""),
        # convenience — kept for backward compat
        "speed": f"{dl_mbps} Mbps",
        "pct":   100,
    }


# ── Format result for Telegram ────────────────────────────────────────────────

def format_result(r: dict, bw_down: str = "", bw_up: str = "") -> str:
    """Build the final Telegram Markdown message from a parsed result dict."""

    def ms(key):   return _ms(r.get(key))
    def mbps(key): return f"{r.get(key, 0):.2f} Mbps"

    def rating(val, good, great, low_is_good=False):
        if val is None:
            return ""
        v = float(val)
        if low_is_good:
            return "🟢" if v <= great else ("🟡" if v <= good else "🔴")
        return "🟢" if v >= great else ("🟡" if v >= good else "🔴")

    dl   = r.get("dl_mbps", 0)
    ul   = r.get("ul_mbps", 0)
    ping = r.get("ping_ms")
    loss = r.get("packet_loss", 0)

    dl_cap = f" / {bw_down}" if bw_down else ""
    ul_cap = f" / {bw_up}"   if bw_up   else ""

    lines = ["*🚀 Speed Test Result*", ""]
    lines += [
        f"⬇️ Download : `{dl:.2f} Mbps`{dl_cap}  {rating(dl, 15, 50)}",
        f"⬆️ Upload   : `{ul:.2f} Mbps`{ul_cap}  {rating(ul, 5, 20)}",
        "",
        f"📶 Ping     : `{ms('ping_ms')}`  {rating(ping, 80, 40, low_is_good=True)}",
        f"〰️ Jitter   : `{ms('ping_jitter')}`  {rating(r.get('ping_jitter'), 20, 10, low_is_good=True)}",
        f"📦 Loss     : `{loss}%`  {'🟢' if loss == 0 else ('🟡' if loss < 1 else '🔴')}",
        "",
        "*Download latency*",
        f"  IQM `{ms('dl_lat_iqm')}` · Low `{ms('dl_lat_low')}` · High `{ms('dl_lat_high')}` · Jitter `{ms('dl_lat_jitter')}`",
        "",
        "*Upload latency*",
        f"  IQM `{ms('ul_lat_iqm')}` · Low `{ms('ul_lat_low')}` · High `{ms('ul_lat_high')}` · Jitter `{ms('ul_lat_jitter')}`",
    ]

    if r.get("isp") or r.get("external_ip"):
        lines += ["", f"🌐 ISP: `{r.get('isp','')}` · IP: `{r.get('external_ip','')}`"]

    if r.get("server_name"):
        lines += [f"🖥 Server: `{r['server_name']}, {r.get('server_country','')}` (`{r.get('server_host','')}`)" ]

    if r.get("result_url"):
        lines += ["", f"[📊 View full result]({r['result_url']})"]

    return "\n".join(lines)


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(progress_file: str):
    """Remove the temp progress file."""
    try:
        os.remove(progress_file)
    except Exception:
        pass


# ── Internal helpers ──────────────────────────────────────────────────────────

def _mbps(bandwidth_bytes) -> float:
    if bandwidth_bytes is None:
        return 0.0
    return round(bandwidth_bytes * 8 / 1_048_576, 2)


def _ms(val) -> str:
    return f"{round(float(val), 1)} ms" if val is not None else "—"
