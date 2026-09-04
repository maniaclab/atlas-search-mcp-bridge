"""Source for a fake ``curl`` executable installed on PATH by tests.

Mirrors krb5-token-service's fake-kinit-on-PATH convention (tests/conftest.py's
``_install_fake_bin``): a fake external binary that records its invocation and
plays back a scripted response, so proxy_call.py's real subprocess-invocation
code path is exercised end-to-end rather than mocking ``subprocess.run``
itself.

Controlled entirely via environment variables (set by the installing
fixture), since real curl's own ``-D``/``-o`` file-writing behavior is what
this fake reproduces:

- ``FAKE_CURL_ARGS_FILE``: every argv token, one per line.
- ``FAKE_CURL_STDIN_FILE``: whatever was piped to stdin (the request body).
- ``FAKE_CURL_HEADER_BLOCKS_B64``: base64 bytes written verbatim to the
  ``-D`` path (may contain more than one blank-line-separated header block,
  simulating curl's own SPNEGO 401-then-200 exchange).
- ``FAKE_CURL_BODY_B64``: base64 bytes written verbatim to the ``-o`` path.
- ``FAKE_CURL_EXIT_CODE``: process exit code (default 0).
- ``FAKE_CURL_STDERR``: text written to stderr before exiting.
- ``FAKE_CURL_SLEEP_SECONDS``: sleep this long before responding (timeout tests).
- ``FAKE_CURL_ENV_DUMP_FILE``: if set, ``KRB5CCNAME`` from this process's own
  environment is written there as JSON — proves the caller set it via
  ``subprocess.run(..., env=...)`` without patching subprocess itself.
- ``FAKE_CURL_CCACHE_DUMP_FILE``: if set, the raw bytes at the path named by
  this process's own ``KRB5CCNAME`` are copied here — read at invocation
  time, before the caller's own cleanup (e.g. ``TicketHandle.close()``)
  deletes the real ccache file once the call returns.
"""

FAKE_CURL_SOURCE = """#!/usr/bin/env python3
import base64
import json
import os
import sys
import time

args = sys.argv[1:]

args_file = os.environ.get("FAKE_CURL_ARGS_FILE")
if args_file:
    with open(args_file, "w") as f:
        f.write("\\n".join(args))

env_dump_file = os.environ.get("FAKE_CURL_ENV_DUMP_FILE")
if env_dump_file:
    with open(env_dump_file, "w") as f:
        json.dump({"KRB5CCNAME": os.environ.get("KRB5CCNAME", "")}, f)

ccache_dump_file = os.environ.get("FAKE_CURL_CCACHE_DUMP_FILE")
if ccache_dump_file:
    ccache_path = os.environ.get("KRB5CCNAME", "")
    if ccache_path and os.path.exists(ccache_path):
        with open(ccache_path, "rb") as src, open(ccache_dump_file, "wb") as dst:
            dst.write(src.read())

header_out = None
body_out = None
i = 0
while i < len(args):
    if args[i] == "-D":
        header_out = args[i + 1]
        i += 2
        continue
    if args[i] == "-o":
        body_out = args[i + 1]
        i += 2
        continue
    i += 1

stdin_data = sys.stdin.buffer.read()
stdin_file = os.environ.get("FAKE_CURL_STDIN_FILE")
if stdin_file:
    with open(stdin_file, "wb") as f:
        f.write(stdin_data)

sleep_seconds = os.environ.get("FAKE_CURL_SLEEP_SECONDS")
if sleep_seconds:
    time.sleep(float(sleep_seconds))

stderr_msg = os.environ.get("FAKE_CURL_STDERR")
if stderr_msg:
    print(stderr_msg, file=sys.stderr)

if header_out:
    blocks_b64 = os.environ.get("FAKE_CURL_HEADER_BLOCKS_B64", "")
    with open(header_out, "wb") as f:
        f.write(base64.b64decode(blocks_b64) if blocks_b64 else b"")

if body_out:
    body_b64 = os.environ.get("FAKE_CURL_BODY_B64", "")
    with open(body_out, "wb") as f:
        f.write(base64.b64decode(body_b64) if body_b64 else b"")

sys.exit(int(os.environ.get("FAKE_CURL_EXIT_CODE", "0")))
"""
