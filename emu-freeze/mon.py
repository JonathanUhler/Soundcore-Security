#!/usr/bin/env python3
"""Minimal QEMU human-monitor (HMP) client over the telnet monitor socket.

launch-emulator.sh exposes the monitor as telnet:127.0.0.1:55555. This connects,
runs one or more monitor commands in order, and prints each command's output. It
lets capture.sh stop the VM, snapshot guest RAM with pmemsave, and read CR3
without an interactive telnet session. The monitor is a hypervisor-level
interface, so driving it is invisible to every in-guest anti-tamper layer.

Usage:
    python3 mon.py 127.0.0.1:55555 "stop" "pmemsave 0 0x80000000 /abs/ram.bin" "info registers"
    python3 mon.py 127.0.0.1:55555 "cont"
"""
import socket
import sys

PROMPT = "(qemu)"


def strip_telnet(data):
    """Drop telnet IAC negotiation triplets so they do not corrupt the text."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF and i + 2 < len(data):
            i += 3
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def clean(text, command):
    """Strip the echoed command line and the trailing/interleaved prompts from a
    monitor response, leaving just the command's output."""
    lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if s == PROMPT or s == "":
            continue
        if s.startswith(PROMPT):
            s = s[len(PROMPT):].strip()
            if not s:
                continue
            ln = s
        lines.append(ln)
    if lines and command.strip() and command.strip() in lines[0]:
        lines = lines[1:]
    return "\n".join(lines).strip()


class Monitor:
    def __init__(self, host, port, timeout=900):
        self.s = socket.create_connection((host, port), timeout=15)
        self.s.settimeout(timeout)
        self._read_to_prompt()

    def _read_to_prompt(self):
        buf = bytearray()
        while True:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if strip_telnet(bytes(buf)).rstrip().endswith(PROMPT.encode()):
                break
        return strip_telnet(bytes(buf)).decode("utf-8", "replace")

    def cmd(self, command):
        self.s.sendall(command.encode() + b"\n")
        return clean(self._read_to_prompt(), command)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    host, port = sys.argv[1].rsplit(":", 1)
    m = Monitor(host, int(port))
    for command in sys.argv[2:]:
        out = m.cmd(command)
        if out:
            print(out)
    m.close()


if __name__ == "__main__":
    main()
