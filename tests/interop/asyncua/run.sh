#!/usr/bin/env bash
# Runs the asyncua interop check against a server built from this checkout.
# Usage: tests/interop/asyncua/run.sh
# Environment: BASE_PORT (default 48400), PYTHON (default python3).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
base_port="${BASE_PORT:-48400}"
python="${PYTHON:-python3}"
work="$(mktemp -d)"
pids=()
cleanup() {
	for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null; done
	rm -rf "$work"
}
trap cleanup EXIT

"$python" -m venv "$work/venv" || exit 2
"$work/venv/bin/pip" install -q -r "$here/requirements.txt" || exit 2
(cd "$root" && go build -o "$work/server" ./tests/interop/asyncua/server) || exit 2

# start <name> <port> [server flags...]
start() {
	local name="$1" port="$2"
	shift 2
	"$work/server" -port "$port" "$@" >"$work/$name.log" 2>&1 &
	pids+=("$!")
	for _ in $(seq 1 50); do
		grep -q READY "$work/$name.log" && return 0
		sleep 0.2
	done
	echo "server '$name' did not start:" >&2
	tail -5 "$work/$name.log" >&2
	exit 2
}
ns() { grep -o 'READY ns=[0-9]*' "$work/$1.log" | cut -d= -f2; }

start encrypt "$base_port"
start sign "$((base_port + 1))" -mode Sign
start chain "$((base_port + 2))" -chain
start insecure "$((base_port + 3))" -allow-insecure

client() { "$work/venv/bin/python" "$here/client.py" "$@" 2>/dev/null | grep '^RESULT'; }
status=0
run() {
	local label="$1" name="$2" port="$3" mode="$4"
	shift 4
	echo "== $label"
	# The exit status is taken from the RESULT lines below, not from the client.
	client "opc.tcp://localhost:$port" "$(ns "$name")" "$mode" "$@" || true
}

out="$work/results.txt"
{
	run "SignAndEncrypt" encrypt "$base_port" SignAndEncrypt basic wrong_password anonymous renewal_idle renewal
	run "Sign" sign "$((base_port + 1))" Sign basic wrong_password renewal
	run "Server certificate is a chain" chain "$((base_port + 2))" SignAndEncrypt basic wrong_password
	run "None endpoint enabled beside the secured one" insecure "$((base_port + 3))" SignAndEncrypt none basic
} | tee "$out"

grep -q ': FAIL' "$out" && status=1
echo
echo "passed: $(grep -c ': PASS' "$out")  failed: $(grep -c ': FAIL' "$out")"
exit "$status"
