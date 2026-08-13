#!/usr/bin/env bash
# Run the Objective 3 PREOF mutest. Lives next to munet.yaml.
# Usage:  sudo ./run_obj3.sh [extra mutest args]
#   -v            more verbose
#   --pause-on-error   drop to the munet CLI on the first failure (best for debugging)
#   --validate-only    parse the topology, run nothing

set -uo pipefail
cd "$(dirname "$0")" || exit 1

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; OFF=$'\e[0m'
fail=0
warn() { echo "${YEL}WARN${OFF}  $*"; }
bad()  { echo "${RED}FAIL${OFF}  $*"; fail=1; }
ok()   { echo "${GRN}ok${OFF}    $*"; }

echo "== preflight =="

# 1. root
[ "$(id -u)" -eq 0 ] || { bad "must run as root (sudo $0)"; exit 1; }
ok "running as root"

# 2. mutest -- installed in a venv on this box, so root's PATH will NOT have it.
#    Override with:  MUTEST=/path/to/mutest sudo -E ./run_obj3.sh
MUTEST="${MUTEST:-}"
if [ -z "$MUTEST" ]; then
  for c in /home/francis/lab/munet-venv/bin/mutest \
           "$HOME/lab/munet-venv/bin/mutest" \
           ../../lab/munet-venv/bin/mutest; do
    [ -x "$c" ] && { MUTEST="$c"; break; }
  done
fi
[ -z "$MUTEST" ] && MUTEST=$(command -v mutest 2>/dev/null)
if [ -n "$MUTEST" ] && [ -x "$MUTEST" ]; then ok "mutest: $MUTEST"
else bad "mutest not found -- look for it under ~/lab/munet-venv/bin, then re-run with MUTEST=<path> sudo -E ./run_obj3.sh"; fi

# 3. tools the test shells out to inside the nodes
for t in tcpdump traceroute ping ethtool ip; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t: $(command -v "$t")"
  else bad "$t not found in PATH"; fi
done

# 4. dnt binary, at the path munet.yaml hardcodes
DNT=$(grep -oE '/[^ ]*/dnt' munet.yaml | head -1)
if [ -x "$DNT" ]; then ok "dnt: $DNT"; else bad "dnt not executable at $DNT (from munet.yaml)"; fi

# 5. munet.yaml points dnt at ~/lab/preof-topo/*.ini, NOT the repo copy beside this
#    script. That is correct on the VM -- but the two drift. dnt uses the yaml's copy.
for r in routerA routerB; do
  INI=$(grep -oE "/[^ ]*/${r}\.ini" munet.yaml | head -1)
  [ -n "$INI" ] || { bad "no ${r}.ini path found in munet.yaml"; continue; }
  if [ ! -f "$INI" ]; then
    bad "$INI does not exist -- munet.yaml points dnt there. Either create it or repoint munet.yaml at ./${r}.ini"
  elif ! cmp -s "$INI" "./${r}.ini"; then
    warn "$INI differs from ./${r}.ini (repo copy). The lab will use the one in munet.yaml."
    diff -u "./${r}.ini" "$INI" | head -20
  else
    ok "$INI matches ./${r}.ini"
  fi
done

# 6. nothing left over from a previous run
if pgrep -x dnt >/dev/null 2>&1; then
  warn "dnt already running outside munet -- the 'exactly one dnt' check will fail"
  pgrep -ax dnt | head
fi
pgrep -f 'tcpdump.*obj3_' >/dev/null 2>&1 && warn "stale obj3 tcpdump still running"
ip netns list 2>/dev/null | grep -qE 'routerA|router1A' && \
  warn "munet namespaces still present from a previous run -- try: sudo munet -c 'quit' or reboot the netns"

[ "$fail" -eq 0 ] || { echo; echo "${RED}preflight failed -- fix the above before running${OFF}"; exit 1; }

echo
echo "== run =="
LOG="mutest_obj3_$(date +%Y%m%d_%H%M%S).log"
"$MUTEST" "$@" mutest_obj3_preof.py 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}

echo
if [ "$rc" -eq 0 ]; then
  echo "${GRN}PASS${OFF}  full log: $LOG"
else
  echo "${RED}FAIL (rc=$rc)${OFF}  full log: $LOG"
  echo "Re-run with --pause-on-error to land in the munet CLI at the failing step."
fi
exit "$rc"
