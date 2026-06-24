#!/usr/bin/env bash
# =============================================================================
# DISA STIG Ubuntu 22.04 LTS — Stage 2 Remediation: MEDIUM RISK
# LiveNX Platform
#
# Rules covered : 15 of 99 failing
# Risk          : Medium — SSH config, APT policy, /var/log perms, password expiry
# Prerequisites : Stage 1 must have been run and verified first
# Reboot needed : No (SSH reloaded in-place; sshd_config validated before reload)
# tmpfiles.d    : Used for /run/log/journal and journalctl — both are outside /var
#                 and would not persist across reboots without it
#
# VERIFY after running:
#   1. Confirm SSH session still works (open a second terminal BEFORE running)
#   2. Confirm LiveNX web UI / API is still reachable
#   3. Run stig_audit.py again to check progress
#
# Run as root:
#   sudo bash /home/admin/stig_stage2_medium_risk.sh 2>&1 | tee /home/admin/stig_stage2.log
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0

ok()      { echo -e "  ${GREEN}✓${NC} $*"; (( PASS++ )) || true; }
fail()    { echo -e "  ${RED}✗${NC} $*"; (( FAIL++ )) || true; }
info()    { echo -e "  ${CYAN}→${NC} $*"; }
warn()    { echo -e "  ${YELLOW}!${NC} $*"; (( SKIP++ )) || true; }
section() { echo -e "\n${BOLD}═══ $* ═══${NC}"; }

[[ $EUID -ne 0 ]] && { echo "ERROR: This script must be run as root."; exit 1; }

backup() {
    local f="$1"
    [[ -f "$f" && ! -f "${f}.stig_bak" ]] && { cp "$f" "${f}.stig_bak"; info "Backed up $f → ${f}.stig_bak"; }
}

set_sshd_option() {
    local key="$1" val="$2"
    if grep -qiE "^#?\s*${key}\s" /etc/ssh/sshd_config; then
        sed -i "s|^#\?\s*${key}\s.*|${key} ${val}|I" /etc/ssh/sshd_config
    else
        echo "${key} ${val}" >> /etc/ssh/sshd_config
    fi
}

echo -e "\n${BOLD}STIG Stage 2 — MEDIUM RISK (15 rules)${NC}"
echo    "Target : LiveNX Platform (Ubuntu 22.04 LTS)"
echo    "Date   : $(date '+%Y-%m-%d %H:%M:%S')"
echo    "Log    : /home/admin/stig_stage2.log"
echo    ""
echo -e "  ${YELLOW}IMPORTANT: Keep your current SSH session open.${NC}"
echo    "  Open a second SSH session now so you can reconnect if needed."
echo    "  This script validates sshd_config before reloading."

# =============================================================================
# GROUP 1 — APT configuration
# =============================================================================
section "GROUP 1: APT configuration"

# V-260476 — APT must not allow unauthenticated packages
info "V-260476: Disabling APT unauthenticated package installs"
cat > /etc/apt/apt.conf.d/00-stig-auth <<'EOF'
APT::Get::AllowUnauthenticated "false";
EOF
ok "V-260476: AllowUnauthenticated set to false in /etc/apt/apt.conf.d/00-stig-auth"

# Remove any stray AllowUnauthenticated "true" from other config files
for f in /etc/apt/apt.conf.d/*.conf /etc/apt/apt.conf; do
    [[ -f "$f" ]] && sed -i 's/AllowUnauthenticated\s*"true"/AllowUnauthenticated "false"/gI' "$f" 2>/dev/null || true
done
ok "V-260476: Scanned other APT config files for stray AllowUnauthenticated overrides"

# V-260477 — APT must remove unused/old software components
# NOTE: We do NOT enable Unattended-Upgrade — that would auto-update packages
#       on a production server without testing against LiveNX. Autoclean only.
info "V-260477: Configuring APT autoclean (removal of unused components)"
cat > /etc/apt/apt.conf.d/01-stig-autoclean <<'EOF'
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
ok "V-260477: APT autoclean configured (7-day interval, remove unused kernel/deps)"

# =============================================================================
# GROUP 2 — /var/log file permissions
# =============================================================================
section "GROUP 2: /var/log file permissions (V-260489)"

# /var/log is inside /var — permissions persist normally across reboots
info "V-260489: Setting /var/log files to 640 or more restrictive"
VLOG_FIXED=0
set +e
while IFS= read -r -d '' f; do
    chmod u=rw,g=r,o= "$f" 2>/dev/null && ((VLOG_FIXED++)) || true
done < <(find /var/log -type f -perm /137 -print0 2>/dev/null)
set -e

if [[ $VLOG_FIXED -gt 0 ]]; then
    ok "V-260489: $VLOG_FIXED files in /var/log fixed to 640"
else
    ok "V-260489: All /var/log files already 640 or more restrictive"
fi

# =============================================================================
# GROUP 3 — systemd journal permissions
# =============================================================================
section "GROUP 3: systemd journal permissions"

# /run/log/journal lives in /run (tmpfs — recreated at boot).
# systemd's own tmpfiles.d sets it to 2755. We override with 2750.
# We fix it now AND write /etc/tmpfiles.d/ to re-apply after every reboot.

TMPFILES_JOURNAL="/etc/tmpfiles.d/stig-journal-perms.conf"
cat > "$TMPFILES_JOURNAL" <<'EOF'
# STIG V-260490 — /run/log/journal must be 2750
# /run is a tmpfs recreated at boot; systemd sets this dir to 2755 by default.
# This entry overrides that and runs after systemd's own tmpfiles.d entries.
z /run/log/journal 2750 root systemd-journal -
EOF

# V-260490 — /run/log/journal must be 2750
info "V-260490: Setting /run/log/journal to 2750"
if [[ -d /run/log/journal ]]; then
    chmod 2750 /run/log/journal \
        && ok "V-260490: /run/log/journal set to 2750 (current session)" \
        || fail "V-260490: chmod failed on /run/log/journal"
else
    warn "V-260490: /run/log/journal does not exist yet"
fi
systemd-tmpfiles --create "$TMPFILES_JOURNAL" &>/dev/null || true
ok "V-260490: tmpfiles.d entry written → $TMPFILES_JOURNAL (persists across reboots)"

# V-260512 — journalctl must be 740 or more restrictive
# /usr/bin/journalctl is outside /etc, /home, /var — needs tmpfiles.d for persistence
info "V-260512: Setting journalctl permissions to 740"
JCTL=$(command -v journalctl 2>/dev/null || true)
if [[ -n "$JCTL" ]]; then
    chmod 740 "$JCTL" \
        && ok "V-260512: $JCTL set to 740 (current session)" \
        || fail "V-260512: chmod failed on $JCTL"
    # Add tmpfiles.d entry for persistence across reboots
    JCTL_MODE=$(stat -c "%a" "$JCTL" 2>/dev/null || echo "740")
    printf 'z %s %s root root -\n' "$JCTL" "$JCTL_MODE" >> "$TMPFILES_JOURNAL"
    systemd-tmpfiles --create "$TMPFILES_JOURNAL" &>/dev/null || true
    ok "V-260512: tmpfiles.d entry added → $TMPFILES_JOURNAL (persists across reboots)"
    info "  NOTE: A package update to systemd may reset journalctl permissions."
    info "        Re-run this group after any systemd upgrade."
else
    warn "V-260512: journalctl not found in PATH"
fi

# =============================================================================
# GROUP 4 — SSH configuration
# =============================================================================
section "GROUP 4: SSH configuration"

backup /etc/ssh/sshd_config
backup /etc/issue.net

# V-260525 — DoD warning banner
info "V-260525: Writing DoD consent banner to /etc/issue.net"
cat > /etc/issue.net <<'BANNER'
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent
to the following conditions:

- The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC
  monitoring, network operations and defense, personnel misconduct (PM), law
  enforcement (LE), and counterintelligence (CI) investigations.

- At any time, the USG may inspect and seize data stored on this IS.

- Communications using, or data stored on, this IS are not private, are
  subject to routine monitoring, interception, and search, and may be
  disclosed or used for any USG-authorized purpose.

- This IS includes security measures (e.g., authentication and access
  controls) to protect USG interests -- not for your personal benefit or
  privacy.

- Notwithstanding the above, using this IS does not constitute consent to PM,
  LE or CI investigative searching or monitoring of the content of privileged
  communications, or work product, related to personal representation or
  services by attorneys, psychotherapists, or clergy, and their assistants.
  Such communications and work product are private and confidential. See User
  Agreement for details.
BANNER
ok "V-260525: DoD banner written to /etc/issue.net"

set_sshd_option "Banner"               "/etc/issue.net"
ok "V-260525: SSH Banner set to /etc/issue.net"

# V-260526 — PrintLastLog yes
set_sshd_option "PrintLastLog"         "yes"
ok "V-260526: SSH PrintLastLog=yes"

# V-260527 — ClientAliveCountMax 1
set_sshd_option "ClientAliveCountMax"  "1"
ok "V-260527: SSH ClientAliveCountMax=1"

# V-260529 — RekeyLimit 512M 1h
set_sshd_option "RekeyLimit"           "512M 1h"
ok "V-260529: SSH RekeyLimit=512M 1h"

# V-260530 — X11UseLocalhost yes
set_sshd_option "X11UseLocalhost"      "yes"
ok "V-260530: SSH X11UseLocalhost=yes"

# V-260500 — IgnoreUserKnownHosts yes
set_sshd_option "IgnoreUserKnownHosts" "yes"
ok "V-260500: SSH IgnoreUserKnownHosts=yes"

# V-260504 — Compression no
set_sshd_option "Compression"          "no"
ok "V-260504: SSH Compression=no"

# Validate config before reloading — DO NOT reload if config is broken
info "Validating /etc/ssh/sshd_config"
if sshd -t &>/dev/null; then
    if systemctl reload ssh &>/dev/null || systemctl reload sshd &>/dev/null; then
        ok "sshd config valid — service reloaded successfully"
    else
        warn "sshd config valid but reload failed — try: systemctl restart ssh"
    fi
else
    fail "sshd_config has errors — service NOT reloaded. Check: sshd -t"
    info "  Backup is at /etc/ssh/sshd_config.stig_bak — restore if needed:"
    info "    cp /etc/ssh/sshd_config.stig_bak /etc/ssh/sshd_config && systemctl reload ssh"
fi

# =============================================================================
# GROUP 5 — Password and account policy
# =============================================================================
section "GROUP 5: Password and account policy"

backup /etc/login.defs

# V-260545 — PASS_MIN_DAYS >= 1
info "V-260545: Setting PASS_MIN_DAYS=1"
if grep -q '^PASS_MIN_DAYS' /etc/login.defs; then
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
else
    echo -e "PASS_MIN_DAYS\t1" >> /etc/login.defs
fi
ok "V-260545: PASS_MIN_DAYS=1 (users cannot change password on same day)"

# V-260546 — PASS_MAX_DAYS <= 60
info "V-260546: Setting PASS_MAX_DAYS=60"
if grep -q '^PASS_MAX_DAYS' /etc/login.defs; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t60/' /etc/login.defs
else
    echo -e "PASS_MAX_DAYS\t60" >> /etc/login.defs
fi
ok "V-260546: PASS_MAX_DAYS=60 (password expires every 60 days)"

# V-260547 — Default INACTIVE=35
info "V-260547: Setting default INACTIVE=35"
if useradd -D -f 35 &>/dev/null; then
    ok "V-260547: Default INACTIVE=35 (accounts locked after 35 days of non-use)"
else
    fail "V-260547: Failed to set default INACTIVE"
fi

# Apply password aging to all existing local interactive accounts.
# login.defs only applies to NEW accounts — existing accounts need chage.
# We target accounts with UID >= 1000 (non-system) that have login shells.
info "V-260545/546/547: Applying password aging to existing local user accounts"
info "  ┌─────────────────────────────────────────────────────────────────────"
info "  │ IMPORTANT: If any account's password has not been changed in >60 days,"
info "  │ it may show as expired after this change. Verify admin can still login."
info "  └─────────────────────────────────────────────────────────────────────"
CHAGE_COUNT=0
while IFS=: read -r user _ uid _ _ _ shell; do
    # Skip system accounts (UID < 1000), nologin/false shells
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    info "  Applying chage to: $user (UID=$uid)"
    chage -m 1 -M 60 -I 35 "$user" 2>/dev/null \
        && (( CHAGE_COUNT++ )) || true
    # Show resulting settings so admin can verify
    LAST_CHANGE=$(chage -l "$user" 2>/dev/null | grep 'Last password change' | cut -d: -f2 | xargs)
    EXPIRE=$(chage -l "$user" 2>/dev/null | grep 'Password expires' | cut -d: -f2 | xargs)
    info "    Last change: $LAST_CHANGE | Will expire: $EXPIRE"
done < /etc/passwd
[[ $CHAGE_COUNT -gt 0 ]] \
    && ok "V-260545/546/547: Password aging applied to $CHAGE_COUNT existing accounts" \
    || ok "V-260545/546/547: No local interactive accounts found to update"

# =============================================================================
# SUMMARY
# =============================================================================
section "STAGE 2 SUMMARY"

echo ""
echo -e "  ${GREEN}Applied successfully : ${PASS}${NC}"
echo -e "  ${RED}Failed               : ${FAIL}${NC}"
echo -e "  ${YELLOW}Warned/skipped       : ${SKIP}${NC}"
echo ""
echo "  Rules covered:"
echo "    V-260476 V-260477 (APT)"
echo "    V-260489 V-260490 V-260512 (file/journal permissions)"
echo "    V-260500 V-260504 V-260525 V-260526 V-260527 V-260529 V-260530 (SSH)"
echo "    V-260545 V-260546 V-260547 (password policy)"
echo ""
echo "  VERIFY NOW:"
echo "    1. Open a NEW terminal and confirm SSH login still works"
echo "    2. Confirm LiveNX web UI / API is reachable"
echo "    3. If anything is broken, SSH backup is at /etc/ssh/sshd_config.stig_bak"
echo ""
echo "  tmpfiles.d written: /etc/tmpfiles.d/stig-journal-perms.conf"
echo "    (Reapplies /run/log/journal and journalctl permissions on every boot)"
echo ""
echo "  If all is well, proceed with Stage 3 (HIGH RISK — take a snapshot first):"
echo "    sudo bash /home/admin/stig_stage3_high_risk.sh 2>&1 | tee /home/admin/stig_stage3.log"
echo ""
