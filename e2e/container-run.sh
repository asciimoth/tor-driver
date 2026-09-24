#!/usr/bin/env bash
set -euo pipefail

chutney=/opt/chutney/chutney
network=/workspace/e2e/network.py
network_started=0

show_logs() {
    find -L "$CHUTNEY_DATA_DIR/nodes" -name notice.log -type f -print -exec tail -n 80 {} \; 2>/dev/null || true
}

cleanup() {
    if ((network_started)); then
        "$chutney" stop || true
    fi
}
trap cleanup EXIT INT TERM

"$chutney" init --net-from-script-path "$network"
"$chutney" configure
"$chutney" start --launch-phase 1
network_started=1
if ! "$chutney" wait_for_bootstrap --launch-phase 1; then
    show_logs
    exit 1
fi

# Start the bridge only after the authorities have a stable relay consensus.
# This prevents its first descriptor upload from racing consensus creation.
"$chutney" start --launch-phase 2
if ! "$chutney" wait_for_bootstrap --launch-phase 2; then
    show_logs
    exit 1
fi

client_torrc=
bridge_client_torrc=
for torrc in "$CHUTNEY_DATA_DIR"/nodes/*/torrc; do
    if grep -q '^Bridge obfs4 ' "$torrc"; then
        bridge_client_torrc=$torrc
    elif grep -q '^SocksPort 127\.0\.0\.1:' "$torrc"; then
        client_torrc=$torrc
    fi
done
if [[ -z "$client_torrc" || -z "$bridge_client_torrc" ]]; then
    echo "Chutney did not generate the client templates" >&2
    exit 1
fi
test_torrc=/tmp/tor-driver-test-torrc

awk '
    $1 == "TestingTorNetwork" ||
    $1 == "AddressDisableIPv6" ||
    $1 == "UseMicrodescriptors" ||
    $1 == "DirAuthority" ||
    $1 == "AlternateDirAuthority" ||
    $1 == "AlternateBridgeAuthority"
' "$client_torrc" >"$test_torrc"

bridge_line=$(awk '/^Bridge obfs4 / { print; exit }' "$bridge_client_torrc")
read -r bridge_directive bridge_transport bridge_address bridge_fingerprint bridge_options <<<"$bridge_line"
if [[ "$bridge_directive" != Bridge || "$bridge_transport" != obfs4 ]]; then
    echo "Chutney did not generate an obfs4 bridge line" >&2
    exit 1
fi

bridge_certificate=
for option in $bridge_options; do
    if [[ "$option" == cert=* ]]; then
        bridge_certificate=${option#cert=}
    fi
done
if [[ -z "$bridge_address" || -z "$bridge_fingerprint" || -z "$bridge_certificate" ]]; then
    echo "Chutney generated an incomplete obfs4 bridge line" >&2
    exit 1
fi

export TOR_DRIVER_PRIVATE=1
export TOR_DRIVER_TEST_TORRC_FILE="$test_torrc"
export TOR_BRIDGE_ADDRESS="$bridge_address"
export TOR_BRIDGE_FINGERPRINT="$bridge_fingerprint"
export TOR_BRIDGE_CERT="$bridge_certificate"

if ! go test -race -count=1 -tags=e2e -run '^TestTorPrivate' -v -timeout 6m .; then
    show_logs
    exit 1
fi
