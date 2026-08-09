#!/usr/bin/env bash
# End-to-end proof for six-seven-server: two nodes, real sockets, every
# node-to-node hop a PAXE frame.
#
# What this pins that the unit tests cannot: that a key the receiving node
# does NOT own is forwarded over PAXE and answered correctly, and that the
# same key read back from the OTHER node gives the same value. If sealing,
# the datagram round trip, or opening were broken, the forwarded cases
# would time out and this script would fail.
#
# Everything is timeout-bound and logged to .tmp/logs/<timestamp>/.
# Exit 0 only if every assertion passes.

set -u
cd "$(dirname "$0")/.."
ROOT=$PWD

STAMP=$(date +%Y%m%d_%H%M%S)
LOGDIR="$ROOT/.tmp/logs/$STAMP"
mkdir -p "$LOGDIR"

BIN="$ROOT/target/debug/six-seven-server"
if [ ! -x "$BIN" ]; then
  echo "FAIL: $BIN not found (cargo build --bins first)" >&2
  exit 1
fi

# Fixed key: this is a test fixture, not a secret. Both nodes get the same
# 32 bytes, which is what makes the link work.
KEY=$(printf '6767%.0s' {1..16})

A_ID=100; A_STOMP=127.0.0.1:6167; A_PAXE=127.0.0.1:6100
B_ID=200; B_STOMP=127.0.0.1:6267; B_PAXE=127.0.0.1:6200

cleanup() {
  [ -n "${A_PID:-}" ] && kill "$A_PID" 2>/dev/null
  [ -n "${B_PID:-}" ] && kill "$B_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

"$BIN" --id $A_ID --stomp $A_STOMP --paxe $A_PAXE \
       --peer-id $B_ID --peer $B_PAXE --key "$KEY" >"$LOGDIR/node-a.log" 2>&1 &
A_PID=$!
"$BIN" --id $B_ID --stomp $B_STOMP --paxe $B_PAXE \
       --peer-id $A_ID --peer $A_PAXE --key "$KEY" >"$LOGDIR/node-b.log" 2>&1 &
B_PID=$!

# Wait for both STOMP ports, rather than sleeping and hoping.
for _ in $(seq 1 50); do
  if nc -z 127.0.0.1 6167 2>/dev/null && nc -z 127.0.0.1 6267 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! nc -z 127.0.0.1 6167 2>/dev/null || ! nc -z 127.0.0.1 6267 2>/dev/null; then
  echo "FAIL: nodes did not start; see $LOGDIR" >&2
  cat "$LOGDIR"/node-*.log >&2
  exit 1
fi

python3 - "$LOGDIR" <<'PYTHON'
import socket, sys, time

LOGDIR = sys.argv[1]
NUL = b"\x00"
failures = []

def talk(port, requests):
    """One connection, one CONNECT, then a SEND per request. Returns bodies."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(10)
    buffered = b""

    def read_frame():
        nonlocal buffered
        while NUL not in buffered:
            chunk = s.recv(65536)
            if not chunk:
                raise AssertionError("connection closed mid-frame")
            buffered += chunk
        raw, _, buffered = buffered.partition(NUL)
        raw = raw.lstrip(b"\n")
        head, _, body = raw.partition(b"\n\n")
        return head.split(b"\n")[0].decode(), body.decode()

    s.sendall(b"CONNECT\naccept-version:1.2\n\n" + NUL)
    command, _ = read_frame()
    assert command == "CONNECTED", f"expected CONNECTED, got {command}"

    out = []
    for body in requests:
        s.sendall(f"SEND\ndestination:/queue/kv\n\n{body}".encode() + NUL)
        command, reply = read_frame()
        assert command == "MESSAGE", f"expected MESSAGE, got {command}"
        out.append(reply)
    s.sendall(b"DISCONNECT\n\n" + NUL)
    s.close()
    return out

def check(label, got, want):
    if got == want:
        print(f"  ok   {label}: {got!r}")
    else:
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
        failures.append(label)

A, B = 6167, 6267

# 67 is odd -> lower node (100 = A). 68 is even -> higher node (200 = B).
print("node A (id 100), key 67 is LOCAL and key 68 is FORWARDED over PAXE:")
got = talk(A, ["PUT 67 six seven", "GET 67", "PUT 68 six eight", "GET 68"])
check("A put 67 (local)",      got[0], "OK")
check("A get 67 (local)",      got[1], "six seven")
check("A put 68 (forwarded)",  got[2], "OK")
check("A get 68 (forwarded)",  got[3], "six eight")

print("node B (id 200), the mirror image — 67 forwards, 68 is local:")
got = talk(B, ["GET 67", "GET 68"])
check("B get 67 (forwarded)",  got[0], "six seven")
check("B get 68 (local)",      got[1], "six eight")

print("values written through one node are visible through the other:")
got = talk(B, ["PUT 69 from b", "GET 69"])
check("B put 69 (forwarded)",  got[0], "OK")
got = talk(A, ["GET 69"])
check("A get 69 (local)",      got[0], "from b")

print("removal, and the miss shape:")
got = talk(A, ["RM 68", "GET 68", "RM 68", "GET 12345"])
check("A rm 68 (forwarded)",   got[0], "OK")
check("A get 68 after rm",     got[1], "NIL")
check("A rm 68 again",         got[2], "NIL")
check("A get an absent key",   got[3], "NIL")

print("refusals are errors, not crashes:")
oversize = "PUT 71 " + "x" * 1100
got = talk(A, ["GET nope", "FROB 1", "PUT 73", oversize])
check("bad key",     got[0].startswith("ERR"), True)
check("bad verb",    got[1].startswith("ERR"), True)
check("put no value",got[2].startswith("ERR"), True)
check("oversize put",got[3].startswith("ERR"), True)

print("an empty value is a value, not a missing key:")
got = talk(A, ["PUT 75 ", "GET 75"])
check("A put 75 empty (forwarded? 75 is odd -> local)", got[0], "OK")
check("A get 75 empty", got[1], "")

if failures:
    print(f"\nFAIL: {len(failures)} assertion(s) failed: {failures}")
    sys.exit(1)
print("\nPASS: all six-seven assertions passed")
PYTHON
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "six-seven e2e: FAIL (logs in $LOGDIR)" >&2
  exit 1
fi
echo "six-seven e2e: PASS (logs in $LOGDIR)"
