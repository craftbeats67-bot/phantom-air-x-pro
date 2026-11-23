#!/usr/bin/env bash
# PHANTOM AIR X PRO installer - Kali Linux, Parrot OS, Termux
cd "$(dirname "$0")" || exit 1
G=$'\033[92m'; R=$'\033[91m'; Y=$'\033[93m'; C=$'\033[96m'; X=$'\033[0m'
ok(){ echo "${G}[+]${X} $*"; }; warn(){ echo "${Y}[!]${X} $*"; }; bad(){ echo "${R}[x]${X} $*"; }; info(){ echo "${C}[*]${X} $*"; }
FAILED=0

# 1. detect platform
if [ -n "$PREFIX" ] && [ -d /data/data/com.termux ]; then OSN=termux
elif grep -qi kali /etc/os-release 2>/dev/null; then OSN=kali
elif grep -qi parrot /etc/os-release 2>/dev/null; then OSN=parrot
else OSN=other; fi
info "Platform: $OSN"
[ "$OSN" = other ] && warn "Not Kali/Parrot/Termux: continuing, but this is untested."

# 2/3. system packages
if [ "$OSN" = termux ]; then
  pkg install -y python python-pillow termux-api nmap iproute2 || { bad "pkg install failed"; FAILED=1; }
  VENV_FLAGS="--system-site-packages"
elif command -v apt >/dev/null 2>&1; then
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  $SUDO apt update && $SUDO apt install -y python3 python3-venv python3-pip iw network-manager nmap arp-scan iproute2 ieee-data pciutils usbutils \
    || { bad "apt install failed"; FAILED=1; }
  VENV_FLAGS=""
else bad "No supported package manager found. Install python3, iw, nmcli and nmap manually."; VENV_FLAGS=""; fi

PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { bad "Python not found"; exit 1; }
if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then ok "Python $("$PY" -c 'import platform;print(platform.python_version())') (3.11+ OK)"
else bad "Python 3.11+ required, found $("$PY" -V)"; FAILED=1; fi

# 4/5. virtual environment + requirements
"$PY" -m venv $VENV_FLAGS .venv && ok "Virtual environment created (.venv)" || { bad "Could not create virtual environment"; FAILED=1; }
if [ -x .venv/bin/python ]; then
  .venv/bin/python -m pip install -q --upgrade pip
  if [ "$OSN" = termux ]; then
    .venv/bin/pip install -q rich requests tabulate && ok "Core requirements installed" || { bad "pip install failed"; FAILED=1; }
    .venv/bin/pip install -q psutil 2>/dev/null || warn "psutil not installed (optional; /proc/net/dev fallback is used)"
  else
    .venv/bin/pip install -q -r requirements.txt && ok "Requirements installed" || { bad "pip install failed"; FAILED=1; }
  fi
fi

# 6. system utilities
for t in iw nmcli ip nmap arp-scan; do command -v $t >/dev/null 2>&1 && ok "tool: $t" || warn "tool missing: $t (some features will be limited)"; done
[ "$OSN" = termux ] && { command -v termux-wifi-scaninfo >/dev/null 2>&1 && ok "tool: termux-wifi-scaninfo" || warn "Install the Termux:API app from F-Droid and run: pkg install termux-api"; }

# 7. logo asset
[ -s assets/phantom_team_logo.png ] && ok "Logo asset found" || { bad "assets/phantom_team_logo.png is missing"; FAILED=1; }

# 8. basic test
if [ -x .venv/bin/python ]; then
  .venv/bin/python -m unittest discover -s tests >/tmp/phantom_test.log 2>&1 && ok "Self-test passed" || { bad "Self-test failed (see /tmp/phantom_test.log)"; FAILED=1; }
fi

# launcher
printf '#!/usr/bin/env bash\ncd "$(dirname "$0")"\nexec .venv/bin/python main.py "$@"\n' > run.sh; chmod +x run.sh main.py

# 9. status
echo
if [ $FAILED -eq 0 ]; then ok "Installation complete. Start with: ./run.sh   (Kali/Parrot: sudo ./run.sh for iw scans and full inventory)"
else bad "Installation finished with problems. Read the messages above and see README > Troubleshooting."; exit 1; fi
