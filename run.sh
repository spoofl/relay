#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

args=("$@")
key_file="api.key"
while (( $# > 0 )); do
    case "$1" in
        -h|--help)
            exec python3 "$script_dir/relay.py" "${args[@]}"
            ;;
        --api-key-file)
            if (( $# < 2 )) || [[ $2 == -* && $2 != - ]]; then
                exec python3 "$script_dir/relay.py" "${args[@]}"
            fi
            key_file="$2"
            shift
            ;;
        --api-key-file=*)
            key_file="${1#*=}"
            ;;
    esac
    shift
done

python3 - "$key_file" <<'PY'
import os
from pathlib import Path
import secrets
import sys

path = sys.argv[1]
try:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w") as output:
            output.write(secrets.token_hex(32) + "\n")
        print(f"Created API key file: {path}", file=sys.stderr)
    if os.environ.get("RELAY_PRINT_API_KEY", "1") != "0":
        print(f"API key: {Path(path).read_text().strip()}", flush=True)
except OSError as error:
    sys.exit(f"Could not prepare API key file: {error}")
PY

# Replace Bash so the relay receives signals and returns its exit status directly.
exec python3 "$script_dir/relay.py" --api-key-file "$key_file" "${args[@]}"
