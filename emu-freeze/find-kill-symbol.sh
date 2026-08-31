#!/usr/bin/env bash
# Pull the guest kernel symbol table and print the kill/exit syscall entry
# addresses. Feed the right one to freeze.sh as KILL_ADDR. kallsyms already
# reflects KASLR, so the printed address is the live one to breakpoint.
#
# Usage: ./find-kill-symbol.sh
set -uo pipefail
cd "$(dirname "$0")"
source ./common.sh

echo "[*] relaxing kptr_restrict and pulling kallsyms"
sh_root "echo 0 > /proc/sys/kernel/kptr_restrict" >/dev/null 2>&1 || true
sh_root "cat /proc/kallsyms" | tr -d '\r' > kallsyms.txt
echo "[*] $(wc -l < kallsyms.txt) symbols saved to kallsyms.txt"

echo
echo "[*] death syscall entries (freeze.sh resolves these automatically):"
grep -E ' (__x64_sys_kill|__x64_sys_tkill|__x64_sys_tgkill|__x64_sys_exit_group|__arm64_sys_kill|__arm64_sys_tkill|__arm64_sys_tgkill|__arm64_sys_exit_group)$' kallsyms.txt \
  || echo "    none found (are the addresses all zero? then kptr_restrict blocked you)"

echo
echo "freeze.sh reads kallsyms.txt directly, so you normally just run:"
echo "    APP_PID=<pid> ./freeze.sh"
