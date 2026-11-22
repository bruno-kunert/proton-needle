#!/usr/bin/env python3
"""Native transport fixture: no Wine, discovery, prefixes, or target processes."""

import json
import os
import signal
import sys
import time

mode = sys.argv[1]
if mode == "no_read":
    time.sleep(30)
elif mode == "duplex":
    # Fill stderr before consuming a request larger than a pipe buffer.
    data = b"d" * 60000
    while data:
        data = data[os.write(2, data) :]
request = json.loads(
    sys.argv[3]
    if len(sys.argv) == 4 and sys.argv[2] == "--request-json"
    else sys.stdin.readline(65537)
)
response = {
    key: request[key] for key in ("protocol_version", "request_id", "operation")
}
response.update(status="success", error_code="", error_message="", processes=[])
if mode == "timeout":
    time.sleep(30)
elif mode == "crash":
    os.kill(os.getpid(), signal.SIGKILL)
elif mode in ("large", "stderr_large"):
    stream = sys.stderr if mode == "stderr_large" else sys.stdout
    for _ in range(300):
        stream.write("x" * 8192)
        stream.flush()
elif mode == "malformed":
    print("{not json")
elif mode == "truncated":
    sys.stdout.write(json.dumps(response)[:40])
    sys.stdout.flush()
elif mode in ("chatty", "stdout_chatty"):
    stream = sys.stderr if mode == "chatty" else sys.stdout
    while True:
        stream.write(" ")
        stream.flush()
        time.sleep(0.001)
elif mode == "closed_streams":
    os.close(1)
    os.close(2)
    time.sleep(0.1)
elif mode == "inherited_pipe":
    if os.fork():
        os._exit(0)
    time.sleep(0.1)
    print(json.dumps(response, separators=(",", ":")), flush=True)
    os._exit(0)
elif mode == "duplex":
    for byte in json.dumps(response, separators=(",", ":")).encode() + b"\n":
        os.write(1, bytes([byte]))
        time.sleep(0.001)
elif mode in ("remote_error", "remote_timeout", "remote_rejected", "remote_unknown"):
    response.update(
        status="error",
        error_code="injection_timeout"
        if mode == "remote_timeout"
        else "invalid_dll"
        if mode == "remote_error"
        else "load_library_failed",
        error_message="controlled fixture error",
    )
    if mode != "remote_unknown":
        response["inconclusive"] = mode != "remote_error"
    print(json.dumps(response, separators=(",", ":")))
else:
    if mode == "wrong_identity":
        response["request_id"] = "wrong"
    print(json.dumps(response, separators=(",", ":")))
    if mode == "nonzero":
        sys.exit(9)
