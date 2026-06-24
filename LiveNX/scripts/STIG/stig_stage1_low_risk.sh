#!/usr/bin/env bash
# =============================================================================
# DISA STIG Ubuntu 22.04 LTS — Stage 1 Remediation: LOW / NO RISK
# LiveNX Platform
#
# Rules covered : 64 of 99 failing
# Risk          : Low to none — monitoring config, package removal, audit rules
# Prerequisites : None — safe to run on a live production server
# Reboot needed : No
#
# Run as root:
#   sudo bash /home/admin/stig_stage1_low_risk.sh 2>&1 | tee /home/admin/stig_stage1.log
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

echo -e "\n${BOLD}STIG Stage 1 — LOW / NO RISK (64 rules)${NC}"
echo    "Target : LiveNX Platform (Ubuntu 22.04 LTS)"
echo    "Date   : $(date '+%Y-%m-%d %H:%M:%S')"
echo    "Log    : /home/admin/stig_stage1.log"
echo    ""
echo    "  These changes affect only audit logging, monitoring config, and"
echo    "  package removal. No impact on LiveNX services is expected."

# =============================================================================
# GROUP 1 — System services
# =============================================================================
section "GROUP 1: System services"

# V-260469 — ctrl-alt-del.target must be masked
info "V-260469: Masking ctrl-alt-del.target"
if systemctl mask ctrl-alt-del.target &>/dev/null; then
    systemctl daemon-reload &>/dev/null || true
    ok "V-260469: ctrl-alt-del.target masked"
else
    fail "V-260469: Failed to mask ctrl-alt-del.target"
fi

# auditd will not start if /var/log/audit does not exist — create it first.
# /var/log is inside /var so this directory persists across reboots.
info "Creating /var/log/audit directory (required by auditd before it can start)"
mkdir -p /var/log/audit
chmod 750 /var/log/audit
chown root:root /var/log/audit
ok "V-260598/603: /var/log/audit directory created and owned by root:root"

# V-260588 — auditd must be enabled at boot
info "V-260588: Enabling auditd at boot"
systemctl enable auditd &>/dev/null \
    && ok "V-260588: auditd enabled at boot" \
    || fail "V-260588: Failed to enable auditd (is auditd installed?)"

# V-260591 — auditd must be running
# reset-failed clears systemd's restart counter so auditd can start even if
# it previously failed (e.g. from a missing /var/log/audit directory)
info "V-260591: Starting auditd"
systemctl reset-failed auditd &>/dev/null || true
if systemctl is-active auditd &>/dev/null; then
    ok "V-260591: auditd already running"
elif systemctl start auditd &>/dev/null; then
    ok "V-260591: auditd started"
else
    fail "V-260591: Failed to start auditd — check: journalctl -xeu auditd.service"
fi

# =============================================================================
# GROUP 2 — Remove prohibited packages
# =============================================================================
section "GROUP 2: Remove prohibited packages"

# V-260473 — telnet must not be installed
info "V-260473: Checking telnet package"
if dpkg -l telnet 2>/dev/null | grep -q '^ii'; then
    if apt-get remove -y telnet &>/dev/null; then
        ok "V-260473: telnet removed"
    else
        fail "V-260473: Failed to remove telnet"
    fi
else
    ok "V-260473: telnet not installed (already compliant)"
fi

# =============================================================================
# GROUP 3 — Session timeout
# =============================================================================
section "GROUP 3: Session timeout"

# V-260554 — shell sessions must timeout after 600 seconds of inactivity
info "V-260554: Setting TMOUT=600 in /etc/profile.d/"
cat > /etc/profile.d/99-stig-tmout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
chmod 644 /etc/profile.d/99-stig-tmout.sh
ok "V-260554: TMOUT=600 set in /etc/profile.d/99-stig-tmout.sh (takes effect on next login)"

# =============================================================================
# GROUP 4 — Password complexity (pwquality)
# =============================================================================
section "GROUP 4: Password complexity (pwquality)"

PWQUALITY="/etc/security/pwquality.conf"
backup "$PWQUALITY"

set_pwq() {
    local key="$1" val="$2"
    if grep -qE "^#?\s*${key}\s*=" "$PWQUALITY" 2>/dev/null; then
        sed -i "s|^#\?\s*${key}\s*=.*|${key} = ${val}|" "$PWQUALITY"
    else
        echo "${key} = ${val}" >> "$PWQUALITY"
    fi
}

set_pwq "dictcheck"      "1";  ok "V-260564: pwquality dictcheck=1"
set_pwq "minlen"         "15"; ok "V-260565: pwquality minlen=15"
set_pwq "difok"          "8";  ok "V-260566: pwquality difok=8"
set_pwq "enforcing"      "1";  ok "V-260567: pwquality enforcing=1"
set_pwq "maxrepeat"      "3";  ok "V-260571: pwquality maxrepeat=3"
set_pwq "maxclassrepeat" "4";  ok "V-260572: pwquality maxclassrepeat=4"

# =============================================================================
# GROUP 5 — Sticky bit on world-writable directories
# =============================================================================
section "GROUP 5: Sticky bit on world-writable directories (V-260513)"

# Directories outside /etc, /home, /var need tmpfiles.d to persist across reboots
# because LiveNX may recreate those paths from its own packaging.
TMPFILES_STICKY="/etc/tmpfiles.d/stig-sticky-dirs.conf"
printf '# STIG V-260513 — sticky bit on world-writable directories\n' > "$TMPFILES_STICKY"
printf '# Generated by stig_stage1_low_risk.sh — re-applied each boot via systemd-tmpfiles\n' >> "$TMPFILES_STICKY"

STICKY_FIXED=0
set +e
while IFS= read -r -d '' dir; do
    chmod +t "$dir" 2>/dev/null || { info "  Could not chmod +t: $dir"; continue; }
    info "  Sticky bit added: $dir"
    ((STICKY_FIXED++)) || true
    # For paths outside /etc, /home, /var the change won't persist across reboots.
    # Write a tmpfiles.d 'z' entry (adjust-existing) so systemd reapplies on each boot.
    if [[ "$dir" != /etc/* && "$dir" != /home/* && "$dir" != /var/* ]]; then
        MODE=$(stat -c "%a" "$dir" 2>/dev/null || echo "1777")
        OWNER=$(stat -c "%U" "$dir" 2>/dev/null || echo "root")
        GROUP=$(stat -c "%G" "$dir" 2>/dev/null || echo "root")
        printf 'z %s %s %s %s -\n' "$dir" "$MODE" "$OWNER" "$GROUP" >> "$TMPFILES_STICKY"
    fi
done < <(find / -xdev -type d -perm -0002 ! -perm -1000 -print0 2>/dev/null)
set -e

if [[ $STICKY_FIXED -gt 0 ]]; then
    ok "V-260513: Sticky bit applied to $STICKY_FIXED directories"
    systemd-tmpfiles --create "$TMPFILES_STICKY" &>/dev/null || true
    ok "V-260513: tmpfiles.d entry written → $TMPFILES_STICKY (persists across reboots)"
else
    ok "V-260513: No world-writable directories without sticky bit found"
fi

# =============================================================================
# GROUP 6 — AIDE file integrity
# =============================================================================
section "GROUP 6: AIDE file integrity"

# Find AIDE config — Ubuntu's 'aide' package installs the binary but the config
# file comes from 'aide-common'. If aide-common is not installed, we create a
# minimal config so V-260586 can be satisfied without installing new packages.
AIDE_CONF=""
for candidate in /etc/aide/aide.conf /etc/aide.conf; do
    [[ -f "$candidate" ]] && { AIDE_CONF="$candidate"; break; }
done

# V-260586 — AIDE must use SHA512 checksums
if [[ -n "$AIDE_CONF" ]]; then
    backup "$AIDE_CONF"
    if ! grep -qi 'sha512' "$AIDE_CONF"; then
        if grep -qE '^NORMAL\s*=' "$AIDE_CONF"; then
            sed -i 's|^NORMAL\s*=.*|NORMAL = p+i+n+u+g+s+m+S+sha512+acl+xattrs|' "$AIDE_CONF"
        else
            echo "NORMAL = p+i+n+u+g+s+m+S+sha512" >> "$AIDE_CONF"
        fi
    fi
    ok "V-260586: AIDE configured to use SHA512 at $AIDE_CONF"
elif command -v aide &>/dev/null; then
    # Binary exists but config is missing (aide-common not installed).
    # Create a minimal config — covers all system paths with SHA512.
    info "V-260586: aide binary found but no config file — creating minimal config"
    mkdir -p /etc/aide
    AIDE_CONF="/etc/aide/aide.conf"
    cat > "$AIDE_CONF" <<'AIDEEOF'
# Minimal AIDE config generated by STIG Stage 1 (aide-common not installed)
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
verbose=5
report_url=stdout

NORMAL = p+i+n+u+g+s+m+S+sha512+acl+xattrs

/boot   NORMAL
/bin    NORMAL
/sbin   NORMAL
/lib    NORMAL
/lib64  NORMAL
/usr    NORMAL
/etc    NORMAL
!/var/log
!/var/spool
!/var/cache
!/proc
!/sys
!/dev
!/run
!/tmp
AIDEEOF
    ok "V-260586: Minimal AIDE config created at $AIDE_CONF with SHA512"
else
    warn "V-260586: AIDE not installed — skipping (is aide package installed?)"
fi

# V-260587 — AIDE must run weekly via cron
info "V-260587: Creating weekly AIDE cron job"
cat > /etc/cron.weekly/aide-check <<'CRONEOF'
#!/bin/bash
/usr/bin/aide --check 2>&1 | /usr/bin/logger -t aide-weekly
CRONEOF
chmod 755 /etc/cron.weekly/aide-check
ok "V-260587: Weekly AIDE cron at /etc/cron.weekly/aide-check"

# Check if AIDE database already exists — the weekly cron and STIG check both require it
if [[ ! -f /var/lib/aide/aide.db ]] && [[ ! -f /var/lib/aide/aide.db.gz ]]; then
    warn "V-260587: AIDE database does not exist — weekly cron will fail without it"
    info "  ┌─────────────────────────────────────────────────────────────────"
    info "  │ REQUIRED MANUAL STEP (run in a screen/tmux session — takes ~20 min):"
    info "  │   screen -S aide"
    info "  │   aide --init"
    info "  │   mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    info "  │ (or .db.new.gz → .db.gz depending on AIDE version)"
    info "  └─────────────────────────────────────────────────────────────────"
else
    ok "V-260587: AIDE database already exists"
fi

# =============================================================================
# GROUP 7 — auditd configuration
# =============================================================================
section "GROUP 7: auditd configuration"

AUDITD_CONF="/etc/audit/auditd.conf"

if [[ ! -f "$AUDITD_CONF" ]]; then
    fail "auditd.conf not found — is auditd installed?"
else
    backup "$AUDITD_CONF"

    set_auditd() {
        local key="$1" val="$2"
        # Use \s*= to match exact key — prevents "space_left" matching "space_left_action"
        if grep -q "^${key}\s*=" "$AUDITD_CONF"; then
            sed -i "s|^${key}\s*=.*|${key} = ${val}|" "$AUDITD_CONF"
        else
            echo "${key} = ${val}" >> "$AUDITD_CONF"
        fi
    }

    # V-260594 — disk_full_action must not be IGNORE/SUSPEND/HALT without fallback
    set_auditd "disk_full_action"    "SYSLOG"
    set_auditd "max_log_file"        "8"
    set_auditd "max_log_file_action" "ROTATE"
    set_auditd "num_logs"            "5"
    # space_left must be > admin_space_left (default 50) — keep at 75
    set_auditd "space_left"          "75"
    set_auditd "space_left_action"   "SYSLOG"
    ok "V-260594: auditd disk_full_action=SYSLOG; log rotation reinforced"

    # reset-failed before restart so systemd's restart counter doesn't block us
    systemctl reset-failed auditd &>/dev/null || true
    info "  auditd restarted to apply config"
    if systemctl restart auditd &>/dev/null; then
        ok "V-260594: auditd restarted successfully with new config"
    else
        fail "V-260594: auditd failed to restart — check: journalctl -xeu auditd.service"
        info "  Backup config at /etc/audit/auditd.conf.stig_bak:"
        info "    cp /etc/audit/auditd.conf.stig_bak /etc/audit/auditd.conf && systemctl start auditd"
    fi
fi

# =============================================================================
# GROUP 8 — auditd log file permissions
# =============================================================================
section "GROUP 8: auditd log file permissions"

# Wait briefly for auditd to create the log file after the restart above
sleep 2

AUDIT_DIR="/var/log/audit"
AUDIT_LOG="/var/log/audit/audit.log"

# /var/log/audit was created in Group 1 before auditd started — it always exists here.
# /var/log is inside /var so permissions persist normally across reboots.
chmod 750 "$AUDIT_DIR"       && true
chown root:root "$AUDIT_DIR" && true
ok "V-260598/603: /var/log/audit → 750, owner root:root"

if [[ -f "$AUDIT_LOG" ]]; then
    chmod 600 "$AUDIT_LOG"       && true
    chown root:root "$AUDIT_LOG" && true
    ok "V-260597/601/602: audit.log → 600, owner root:root"
else
    warn "V-260597: audit.log not yet created — auditd may still be starting; run: chmod 600 /var/log/audit/audit.log after it appears"
fi

# =============================================================================
# GROUP 9 — Audit rules (V-260606 through V-260649, 44 rules)
# =============================================================================
section "GROUP 9: Audit rules (V-260606 – V-260649, 44 rules)"

RULES_DIR="/etc/audit/rules.d"
mkdir -p "$RULES_DIR"
RULES_FILE="$RULES_DIR/stig.rules"
[[ -f "$RULES_FILE" ]] && cp "$RULES_FILE" "${RULES_FILE}.stig_bak"

info "Writing audit rules to $RULES_FILE"
cat > "$RULES_FILE" <<'AUDIT_RULES'
## DISA STIG Ubuntu 22.04 LTS — Audit Rules
## V-260606 through V-260649 — generated by stig_stage1_low_risk.sh

-D
-b 8192
-f 1

## V-260606 — passwd command
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

## V-260607 — chmod/fchmod/fchmodat
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng

## V-260608 — chown/fchown/lchown/fchownat
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_chng

## V-260609 — xattr changes
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng

## V-260610 — denied file access (EPERM/EACCES)
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

## V-260611 — delete operations
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete

## V-260612 — /etc/sudoers
-w /etc/sudoers -p wa -k identity

## V-260613 — /etc/sudoers.d
-w /etc/sudoers.d -p wa -k identity

## V-260614 — sudo/su execution
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/su       -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

## V-260615 — setuid/setgid execution
-a always,exit -F arch=b64 -S execve -C uid!=euid  -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C uid!=euid  -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid  -F egid=0 -k setgid
-a always,exit -F arch=b32 -S execve -C gid!=egid  -F egid=0 -k setgid

## V-260616 — /etc/shadow
-w /etc/shadow -p wa -k identity

## V-260617 — /etc/passwd
-w /etc/passwd -p wa -k identity

## V-260618 — /etc/group
-w /etc/group -p wa -k identity

## V-260619 — /etc/gshadow
-w /etc/gshadow -p wa -k identity

## V-260620 — /etc/security/opasswd
-w /etc/security/opasswd -p wa -k identity

## V-260621 — lastlog
-w /var/log/lastlog -p wa -k logins

## V-260622 — faillog
-w /var/log/faillog -p wa -k logins

## V-260623 — btmp
-w /var/log/btmp -p wa -k logins

## V-260624 — wtmp
-w /var/log/wtmp -p wa -k logins

## V-260625 — /etc/pam.d changes
-w /etc/pam.d -p wa -k pam

## V-260626 — /etc/login.defs changes
-w /etc/login.defs -p wa -k login_policy

## V-260627 — apparmor_parser (rule required even if binary absent)
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

## V-260628 — setresuid/setresgid
-a always,exit -F arch=b64 -S setresuid,setresgid -F a0!=0xffffffff -k privileged
-a always,exit -F arch=b32 -S setresuid,setresgid -F a0!=0xffffffff -k privileged

## V-260629 — init_module
-a always,exit -F arch=b64 -S init_module -k module_chng
-a always,exit -F arch=b32 -S init_module -k module_chng

## V-260630 — delete_module
-a always,exit -F arch=b64 -S delete_module -k module_chng
-a always,exit -F arch=b32 -S delete_module -k module_chng

## V-260631 — finit_module
-a always,exit -F arch=b64 -S finit_module -k module_chng
-a always,exit -F arch=b32 -S finit_module -k module_chng

## V-260632 — insmod/rmmod/modprobe
-w /sbin/insmod   -p x -k module_chng
-w /sbin/rmmod    -p x -k module_chng
-w /sbin/modprobe -p x -k module_chng

## V-260633 — mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount

## V-260634 — umount2
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-mount

## V-260635 — kmod
-w /bin/kmod -p x -k module_chng

## V-260636 — su
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

## V-260637 — newgrp
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

## V-260638 — chsh
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

## V-260639 — usermod
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod

## V-260640 — useradd
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-useradd

## V-260641 — userdel
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-userdel

## V-260642 — groupadd
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-groupadd

## V-260643 — groupmod
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-groupmod

## V-260644 — groupdel
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-groupdel

## V-260645 — chage
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage

## V-260646 — gpasswd
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd

## V-260647 — crontab
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab

## V-260648 — iptables
-a always,exit -F path=/usr/sbin/iptables -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ip

## V-260649 — ssh-keysign
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh
AUDIT_RULES

chmod 640 "$RULES_FILE"
chown root:root "$RULES_FILE"
ok "Audit rules file written: $RULES_FILE (44 rules)"

info "Loading audit rules into kernel"
if augenrules --load &>/dev/null; then
    ok "Audit rules loaded via augenrules"
elif auditctl -R "$RULES_FILE" &>/dev/null; then
    ok "Audit rules loaded via auditctl"
else
    fail "Failed to load audit rules — review $RULES_FILE manually"
fi

# =============================================================================
# SUMMARY
# =============================================================================
section "STAGE 1 SUMMARY"

echo ""
echo -e "  ${GREEN}Applied successfully : ${PASS}${NC}"
echo -e "  ${RED}Failed               : ${FAIL}${NC}"
echo -e "  ${YELLOW}Warned/skipped       : ${SKIP}${NC}"
echo ""
echo "  Rules covered:"
echo "    V-260469 V-260473 V-260513 V-260554"
echo "    V-260564 V-260565 V-260566 V-260567 V-260571 V-260572"
echo "    V-260586 V-260587 V-260588 V-260591 V-260594"
echo "    V-260597 V-260598 V-260601 V-260602 V-260603"
echo "    V-260606 through V-260649 (44 audit rules)"
echo ""
echo "  After verifying LiveNX is still working normally, run Stage 2:"
echo "    sudo bash /home/admin/stig_stage2_medium_risk.sh 2>&1 | tee /home/admin/stig_stage2.log"
echo ""
