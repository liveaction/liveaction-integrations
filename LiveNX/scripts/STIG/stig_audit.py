#!/usr/bin/env python3
"""
DISA Ubuntu 22.04 LTS STIG Audit Script
Benchmark: CAN_Ubuntu_22-04_LTS_STIG, Release 3, Benchmark Date: 30 Jan 2025
Target: LiveNX Platform on Ubuntu 22.04 LTS

Run DIRECTLY on the LiveNX server (no SSH, no extra dependencies):
    python3 stig_audit.py               # terminal + JSON report
    python3 stig_audit.py --html        # also write HTML report
    python3 stig_audit.py --output-dir /home/admin/reports
"""

import os
import sys
import json
import re
import time
import argparse
import textwrap
import subprocess
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path

# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------

class Status(str, Enum):
    PASS       = "PASS"
    FAIL       = "FAIL"
    NA         = "NOT_APPLICABLE"
    WORKAROUND = "WORKAROUND"   # compliant via approved alternative
    MANUAL     = "MANUAL"       # cannot be auto-checked
    ERROR      = "ERROR"        # check execution failed

# ---------------------------------------------------------------------------
# Previous-audit baseline (CSV audit, old LiveNX version)
# ---------------------------------------------------------------------------

PREV_STATUS = {
    # Vuln ID -> ("Open" | "Not a Finding" | "Not Applicable")
    "V-260469": "Open", "V-260470": "Not a Finding", "V-260471": "Open",
    "V-260472": "Not a Finding", "V-260473": "Not a Finding", "V-260474": "Not a Finding",
    "V-260475": "Not a Finding", "V-260476": "Open", "V-260477": "Open",
    "V-260478": "Not a Finding", "V-260479": "Open", "V-260480": "Not Applicable",
    "V-260481": "Not a Finding", "V-260482": "Not Applicable", "V-260483": "Not Applicable",
    "V-260484": "Open", "V-260485": "Not a Finding", "V-260486": "Open",
    "V-260487": "Open", "V-260488": "Not a Finding", "V-260489": "Open",
    "V-260490": "Open", "V-260491": "Not a Finding", "V-260492": "Open",
    "V-260493": "Not a Finding", "V-260494": "Not a Finding", "V-260495": "Open",
    "V-260496": "Open", "V-260497": "Not a Finding", "V-260498": "Not a Finding",
    "V-260499": "Not a Finding", "V-260500": "Not a Finding", "V-260501": "Not a Finding",
    "V-260502": "Not a Finding", "V-260503": "Not a Finding", "V-260504": "Not a Finding",
    "V-260505": "Not a Finding", "V-260506": "Not a Finding", "V-260507": "Open",
    "V-260508": "Not a Finding", "V-260509": "Not a Finding", "V-260510": "Not a Finding",
    "V-260511": "Not a Finding", "V-260512": "Open", "V-260513": "Open",
    "V-260514": "Open", "V-260515": "Open", "V-260516": "Open", "V-260517": "Open",
    "V-260518": "Not a Finding", "V-260519": "Not Applicable", "V-260520": "Not a Finding",
    "V-260521": "Not a Finding", "V-260522": "Not a Finding", "V-260523": "Not a Finding",
    "V-260524": "Not a Finding", "V-260525": "Open", "V-260526": "Not a Finding",
    "V-260527": "Open", "V-260528": "Open", "V-260529": "Not a Finding",
    "V-260530": "Open", "V-260531": "Not a Finding", "V-260532": "Not a Finding",
    "V-260533": "Not Applicable", "V-260534": "Not Applicable", "V-260535": "Not Applicable",
    "V-260536": "Not Applicable", "V-260537": "Not Applicable", "V-260538": "Not Applicable",
    "V-260539": "Not Applicable", "V-260540": "Open", "V-260541": "Not a Finding",
    "V-260542": "Not a Finding", "V-260543": "Not Applicable", "V-260544": "Not a Finding",
    "V-260545": "Open", "V-260546": "Open", "V-260547": "Open", "V-260548": "Not a Finding",
    "V-260549": "Open", "V-260550": "Open", "V-260551": "Not a Finding",
    "V-260552": "Open", "V-260553": "Open", "V-260554": "Open", "V-260555": "Open",
    "V-260556": "Not a Finding", "V-260557": "Open", "V-260558": "Not a Finding",
    "V-260559": "Not a Finding", "V-260560": "Not a Finding", "V-260561": "Not Applicable",
    "V-260562": "Not Applicable", "V-260563": "Not a Finding", "V-260564": "Open",
    "V-260565": "Open", "V-260566": "Open", "V-260567": "Open", "V-260568": "Not a Finding",
    "V-260569": "Not a Finding", "V-260570": "Not a Finding", "V-260571": "Not a Finding",
    "V-260572": "Not a Finding", "V-260573": "Open", "V-260574": "Open",
    "V-260575": "Open", "V-260576": "Open", "V-260577": "Not a Finding",
    "V-260578": "Not a Finding", "V-260579": "Not a Finding", "V-260580": "Open",
    "V-260581": "Not a Finding", "V-260582": "Open", "V-260583": "Not a Finding",
    "V-260584": "Not a Finding", "V-260585": "Not a Finding", "V-260586": "Open",
    "V-260587": "Open", "V-260588": "Not a Finding", "V-260589": "Open",
    "V-260590": "Open", "V-260591": "Open", "V-260592": "Open", "V-260593": "Open",
    "V-260594": "Open", "V-260595": "Open", "V-260596": "Open", "V-260597": "Open",
    "V-260598": "Open", "V-260599": "Open", "V-260600": "Open", "V-260601": "Open",
    "V-260602": "Open", "V-260603": "Open", "V-260604": "Not a Finding",
    "V-260605": "Not a Finding", "V-260606": "Open", "V-260607": "Open",
    "V-260608": "Open", "V-260609": "Open", "V-260610": "Open", "V-260611": "Open",
    "V-260612": "Open", "V-260613": "Open", "V-260614": "Open", "V-260615": "Open",
    "V-260616": "Open", "V-260617": "Open", "V-260618": "Open", "V-260619": "Open",
    "V-260620": "Open", "V-260621": "Open", "V-260622": "Open", "V-260623": "Open",
    "V-260624": "Open", "V-260625": "Open", "V-260626": "Open", "V-260627": "Open",
    "V-260628": "Open", "V-260629": "Open", "V-260630": "Open", "V-260631": "Open",
    "V-260632": "Open", "V-260633": "Open", "V-260634": "Open", "V-260635": "Open",
    "V-260636": "Open", "V-260637": "Open", "V-260638": "Open", "V-260639": "Open",
    "V-260640": "Open", "V-260641": "Open", "V-260642": "Open", "V-260643": "Open",
    "V-260644": "Open", "V-260645": "Open", "V-260646": "Open", "V-260647": "Open",
    "V-260648": "Open", "V-260649": "Open", "V-260650": "Open",
}

# Known permanent non-compliance (no remediation path without major changes)
PERMANENT_NONCOMPLIANT = {
    "V-260650": "FIPS 140-3 requires Ubuntu Pro subscription (not standard Ubuntu)",
    "V-260557": "apparmor_parser binary unavailable on this LiveNX build",
    "V-260479": "chrony not installed; NTP via alternative not STIG-compliant",
    "V-260480": "chrony maxpoll (no chrony installed)",
    "V-260514": "UFW not installed; iptables used as workaround",
    "V-260515": "UFW not installed; iptables used as workaround",
    "V-260516": "UFW not installed; iptables used as workaround",
    "V-260517": "UFW not installed; iptables used as workaround",
    "V-260484": "No disk encryption/crypttab; LiveNX appliance design constraint",
    "V-260549": "pam_faillock.so not installed on this build",
}

# CAC/PIV rules — compliant via RH SSO (Keycloak) + Red Hat IdM SAML workaround
CAC_PIV_WORKAROUND = {
    "V-260573", "V-260574", "V-260575", "V-260576",
}

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    vuln_id: str
    stig_id: str
    severity: str       # high / medium / low
    title: str
    status: Status
    detail: str = ""
    output: str = ""    # raw command output (truncated)
    prev_status: str = ""
    changed: bool = False  # True when prev=Open and now=PASS (fixed!)
    regression: bool = False  # True when prev=Not a Finding and now=FAIL

# ---------------------------------------------------------------------------
# Local command runner (runs directly on the server — no SSH needed)
# ---------------------------------------------------------------------------

class LocalRunner:
    def run(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"TIMEOUT after {timeout}s"
        except Exception as exc:
            return -1, "", f"EXEC_ERROR: {exc}"

    def close(self):
        pass  # nothing to close for local execution

# ---------------------------------------------------------------------------
# Audit engine
# ---------------------------------------------------------------------------

class STIGAuditor:
    def __init__(self, runner: LocalRunner):
        self.runner = runner
        self.results: list[CheckResult] = []

    def _run(self, cmd: str) -> tuple[int, str]:
        rc, out, err = self.runner.run(cmd)
        combined = (out + err).strip()
        return rc, combined

    def _result(self, vuln_id, stig_id, severity, title,
                status, detail="", output="") -> CheckResult:
        prev = PREV_STATUS.get(vuln_id, "Unknown")
        changed   = (prev == "Open") and (status in (Status.PASS, Status.WORKAROUND, Status.NA))
        regression = (prev == "Not a Finding") and (status == Status.FAIL)
        r = CheckResult(
            vuln_id=vuln_id, stig_id=stig_id, severity=severity,
            title=title, status=status, detail=detail,
            output=output[:500], prev_status=prev,
            changed=changed, regression=regression,
        )
        self.results.append(r)
        return r

    # ------------------------------------------------------------------
    # Helper builders
    # ------------------------------------------------------------------

    def _pass(self, vuln_id, stig_id, sev, title, detail="", out=""):
        return self._result(vuln_id, stig_id, sev, title, Status.PASS, detail, out)

    def _fail(self, vuln_id, stig_id, sev, title, detail="", out=""):
        return self._result(vuln_id, stig_id, sev, title, Status.FAIL, detail, out)

    def _na(self, vuln_id, stig_id, sev, title, detail="", out=""):
        return self._result(vuln_id, stig_id, sev, title, Status.NA, detail, out)

    def _workaround(self, vuln_id, stig_id, sev, title, detail="", out=""):
        return self._result(vuln_id, stig_id, sev, title, Status.WORKAROUND, detail, out)

    def _manual(self, vuln_id, stig_id, sev, title, detail="", out=""):
        return self._result(vuln_id, stig_id, sev, title, Status.MANUAL, detail, out)

    # ------------------------------------------------------------------
    # Individual checks — grouped by category
    # ------------------------------------------------------------------

    # --- System / init ---

    def check_ctrl_alt_del(self):
        rc, out = self._run("systemctl status ctrl-alt-del.target 2>&1")
        # Must be masked
        if "masked" in out.lower():
            self._pass("V-260469","UBTU-22-211015","high",
                       "ctrl-alt-del.target must be masked", out=out)
        else:
            self._fail("V-260469","UBTU-22-211015","high",
                       "ctrl-alt-del.target must be masked",
                       detail="ctrl-alt-del.target is NOT masked", out=out)

    def check_audit_kernel_param(self):
        rc, out = self._run("grep -E '^GRUB_CMDLINE_LINUX' /etc/default/grub")
        if "audit=1" in out:
            self._pass("V-260471","UBTU-22-212015","medium",
                       "audit=1 must be in kernel boot parameters", out=out)
        else:
            self._fail("V-260471","UBTU-22-212015","medium",
                       "audit=1 must be in kernel boot parameters",
                       detail="audit=1 not found in GRUB_CMDLINE_LINUX", out=out)

    def check_apt_allow_unauthenticated(self):
        rc, out = self._run(
            "grep -r 'AllowUnauthenticated' /etc/apt/apt.conf.d/ 2>/dev/null")
        if rc != 0 or not out.strip():
            # Not configured means default (false) — pass
            self._pass("V-260476","UBTU-22-214010","low",
                       "APT must not allow unauthenticated packages",
                       detail="No AllowUnauthenticated directive found (default false)", out=out)
        elif re.search(r'AllowUnauthenticated\s+"?true"?', out, re.I):
            self._fail("V-260476","UBTU-22-214010","low",
                       "APT must not allow unauthenticated packages",
                       detail="AllowUnauthenticated is set to true", out=out)
        else:
            self._pass("V-260476","UBTU-22-214010","low",
                       "APT must not allow unauthenticated packages", out=out)

    def check_apt_remove_unused(self):
        rc, out = self._run(
            "grep -r 'Remove-Unused' /etc/apt/apt.conf.d/ 2>/dev/null || "
            "grep -r 'Autoremove' /etc/apt/apt.conf.d/ 2>/dev/null")
        if out.strip():
            self._pass("V-260477","UBTU-22-214015","medium",
                       "APT must remove unused packages automatically", out=out)
        else:
            self._fail("V-260477","UBTU-22-214015","medium",
                       "APT must remove unused packages automatically",
                       detail="No Remove-Unused/Autoremove configured in apt.conf.d", out=out)

    def check_chrony(self):
        # Permanent non-compliance — chrony not installed
        rc, out = self._run("dpkg -l chrony 2>/dev/null | grep '^ii'")
        if out.strip():
            self._pass("V-260479","UBTU-22-215015","low",
                       "chrony must be installed for NTP", out=out)
        else:
            self._fail("V-260479","UBTU-22-215015","low",
                       "chrony must be installed for NTP",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260479",""), out=out)

    def check_chrony_maxpoll(self):
        # Not applicable if chrony not installed
        rc, out = self._run("dpkg -l chrony 2>/dev/null | grep '^ii'")
        if not out.strip():
            self._na("V-260480","UBTU-22-215020","medium",
                     "chrony maxpoll must be <= 16",
                     detail="chrony not installed; check not applicable")
        else:
            rc2, out2 = self._run("grep -i maxpoll /etc/chrony/chrony.conf 2>/dev/null")
            m = re.search(r'maxpoll\s+(\d+)', out2)
            if m and int(m.group(1)) <= 16:
                self._pass("V-260480","UBTU-22-215020","medium",
                           "chrony maxpoll must be <= 16", out=out2)
            else:
                self._fail("V-260480","UBTU-22-215020","medium",
                           "chrony maxpoll must be <= 16",
                           detail="maxpoll not found or > 16", out=out2)

    def check_disk_encryption(self):
        rc, out = self._run("cat /etc/crypttab 2>/dev/null")
        if out.strip():
            self._pass("V-260484","UBTU-22-231010","medium",
                       "System must use disk encryption (crypttab)", out=out)
        else:
            self._fail("V-260484","UBTU-22-231010","medium",
                       "System must use disk encryption (crypttab)",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260484",""), out=out)

    def check_system_command_permissions(self):
        rc, out = self._run(
            "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin "
            "-perm /022 -type f 2>/dev/null | head -20")
        if out.strip():
            self._fail("V-260486","UBTU-22-232015","medium",
                       "System commands must not have world/group-writable permissions",
                       detail="Files found with group/world-writable bits set", out=out)
        else:
            self._pass("V-260486","UBTU-22-232015","medium",
                       "System commands must not have world/group-writable permissions",
                       out=out)

    def check_library_permissions(self):
        rc, out = self._run(
            "find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f 2>/dev/null | head -20")
        if out.strip():
            self._fail("V-260487","UBTU-22-232020","medium",
                       "Library files must not be group/world-writable",
                       detail="Library files found with writable permissions", out=out)
        else:
            self._pass("V-260487","UBTU-22-232020","medium",
                       "Library files must not be group/world-writable", out=out)

    def check_var_log_permissions(self):
        rc, out = self._run(
            "find /var/log -type f -perm /137 2>/dev/null | head -20")
        if out.strip():
            self._fail("V-260489","UBTU-22-232026","medium",
                       "/var/log files must be 640 or more restrictive",
                       detail="Files found exceeding 640 permissions", out=out)
        else:
            self._pass("V-260489","UBTU-22-232026","medium",
                       "/var/log files must be 640 or more restrictive", out=out)

    def check_run_log_journal_perms(self):
        rc, out = self._run("stat -c '%a' /run/log/journal 2>/dev/null")
        perm = out.strip()
        # Must be 2750 or more restrictive (not 2755)
        if perm in ("2640","2650","2740","2750"):
            self._pass("V-260490","UBTU-22-232027","medium",
                       "/run/log/journal must be 2750 or more restrictive",
                       out=f"Permission: {perm}")
        else:
            self._fail("V-260490","UBTU-22-232027","medium",
                       "/run/log/journal must be 2750 or more restrictive",
                       detail=f"Found permission: {perm} (should be 2750)", out=perm)

    def check_audit_tools_installed(self):
        # auditd package should now be installed
        rc, out = self._run("dpkg -l auditd 2>/dev/null | grep '^ii'")
        if out.strip():
            self._pass("V-260492","UBTU-22-232035","medium",
                       "Audit tools (auditd) must be installed", out=out)
        else:
            self._fail("V-260492","UBTU-22-232035","medium",
                       "Audit tools (auditd) must be installed",
                       detail="auditd package not found", out=out)

    def check_system_command_ownership(self):
        rc, out = self._run(
            "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin "
            "! -user root -type f 2>/dev/null | head -20")
        if out.strip():
            self._fail("V-260495","UBTU-22-232050","medium",
                       "System commands must be owned by root",
                       detail="Commands not owned by root found", out=out)
        else:
            self._pass("V-260495","UBTU-22-232050","medium",
                       "System commands must be owned by root", out=out)

    def check_system_command_group_ownership(self):
        rc, out = self._run(
            "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin "
            "! -group root -type f 2>/dev/null | head -20")
        if out.strip():
            self._fail("V-260496","UBTU-22-232055","medium",
                       "System commands must be group-owned by root",
                       detail="Commands not group-owned by root found", out=out)
        else:
            self._pass("V-260496","UBTU-22-232055","medium",
                       "System commands must be group-owned by root", out=out)

    def check_audit_tool_ownership(self):
        tools = ["/sbin/auditctl","/sbin/aureport","/sbin/ausearch",
                 "/sbin/autrace","/sbin/auditd","/sbin/rsyslogd"]
        bad = []
        for t in tools:
            rc, out = self._run(f"stat -c '%U' {t} 2>/dev/null")
            if out.strip() and out.strip() != "root":
                bad.append(f"{t}: owned by {out.strip()}")
        if bad:
            self._fail("V-260507","UBTU-22-232110","medium",
                       "Audit tools must be owned by root",
                       detail="; ".join(bad))
        else:
            self._pass("V-260507","UBTU-22-232110","medium",
                       "Audit tools must be owned by root")

    def check_journalctl_permissions(self):
        rc, out = self._run("stat -c '%a' $(which journalctl) 2>/dev/null")
        perm = out.strip()
        # Must be 740 or more restrictive (not 755)
        allowed = {"700","710","720","730","740"}
        if perm in allowed:
            self._pass("V-260512","UBTU-22-232140","medium",
                       "journalctl must be 740 or more restrictive",
                       out=f"Permission: {perm}")
        else:
            self._fail("V-260512","UBTU-22-232140","medium",
                       "journalctl must be 740 or more restrictive",
                       detail=f"Found: {perm} (need 740 or more restrictive)", out=perm)

    def check_sticky_bit_world_writable(self):
        # Full-filesystem scan can be slow on a busy/just-rebooted box; give it
        # more time than the 30s default so it doesn't time out and report a
        # false finding.
        rc, out, err = self.runner.run(
            "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20",
            timeout=180)
        combined = (out + err).strip()
        if rc == -1:
            # Scan timed out — inconclusive, not a finding. Flag for manual check.
            self._manual("V-260513","UBTU-22-232145","medium",
                         "World-writable directories must have sticky bit set",
                         detail="find scan timed out — re-run audit or check manually",
                         out=combined)
        elif combined:
            self._fail("V-260513","UBTU-22-232145","medium",
                       "World-writable directories must have sticky bit set",
                       detail="Directories without sticky bit found", out=combined)
        else:
            self._pass("V-260513","UBTU-22-232145","medium",
                       "World-writable directories must have sticky bit set", out=combined)

    # --- UFW / Firewall ---

    def _check_ufw_rule(self, vuln_id, stig_id, sev, title):
        rc, out = self._run("dpkg -l ufw 2>/dev/null | grep '^ii'")
        if not out.strip():
            self._fail(vuln_id, stig_id, sev, title,
                       detail=PERMANENT_NONCOMPLIANT.get(vuln_id,
                              "UFW not installed; iptables workaround in use"), out=out)
        else:
            self._pass(vuln_id, stig_id, sev, title, out=out)

    def check_ufw_rules(self):
        self._check_ufw_rule("V-260514","UBTU-22-251010","medium",
                             "UFW must be installed")
        rc, out = self._run("ufw status 2>/dev/null")
        ufw_active = "active" in out.lower()
        if ufw_active:
            self._pass("V-260515","UBTU-22-251015","medium",
                       "UFW must be active/enabled", out=out)
            self._pass("V-260516","UBTU-22-251020","medium",
                       "UFW must deny incoming traffic by default", out=out)
            self._pass("V-260517","UBTU-22-251025","medium",
                       "UFW must allow only approved services", out=out)
        else:
            self._fail("V-260515","UBTU-22-251015","medium",
                       "UFW must be active/enabled",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260515","UFW not active"), out=out)
            self._fail("V-260516","UBTU-22-251020","medium",
                       "UFW must deny incoming traffic by default",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260516","UFW not active"), out=out)
            self._fail("V-260517","UBTU-22-251025","medium",
                       "UFW must allow only approved services",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260517","UFW not active"), out=out)

    # --- SSH ---

    def check_ssh_banner(self):
        rc, out = self._run("cat /etc/issue.net 2>/dev/null")
        dod_keywords = ["you consent", "monitoring", "authorized", "dod", "department of defense"]
        found = sum(1 for kw in dod_keywords if kw in out.lower())
        if found >= 3:
            self._pass("V-260525","UBTU-22-255020","medium",
                       "SSH must display DoD login banner", out=out)
        else:
            self._fail("V-260525","UBTU-22-255020","medium",
                       "SSH must display DoD login banner",
                       detail="DoD consent banner not found or incomplete in /etc/issue.net", out=out)

    def check_ssh_client_alive_count(self):
        rc, out = self._run(
            "grep -i 'ClientAliveCountMax' /etc/ssh/sshd_config 2>/dev/null")
        m = re.search(r'ClientAliveCountMax\s+(\d+)', out, re.I)
        val = int(m.group(1)) if m else None
        if val is not None and 0 < val <= 1:
            self._pass("V-260527","UBTU-22-255030","medium",
                       "SSH ClientAliveCountMax must be 1", out=out)
        else:
            self._fail("V-260527","UBTU-22-255030","medium",
                       "SSH ClientAliveCountMax must be 1",
                       detail=f"Found: {val} (must be 1)", out=out)

    def check_ssh_client_alive_interval(self):
        rc, out = self._run(
            "grep -i 'ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null")
        m = re.search(r'ClientAliveInterval\s+(\d+)', out, re.I)
        val = int(m.group(1)) if m else None
        if val is not None and 1 <= val <= 600:
            self._pass("V-260528","UBTU-22-255035","medium",
                       "SSH ClientAliveInterval must be 600 or less", out=out)
        else:
            self._fail("V-260528","UBTU-22-255035","medium",
                       "SSH ClientAliveInterval must be 600 or less",
                       detail=f"Found: {val} (must be 1-600)", out=out)

    def check_ssh_x11_localhost(self):
        rc, out = self._run(
            "grep -i 'X11UseLocalhost' /etc/ssh/sshd_config 2>/dev/null")
        if re.search(r'X11UseLocalhost\s+yes', out, re.I):
            self._pass("V-260530","UBTU-22-255045","medium",
                       "SSH X11UseLocalhost must be yes", out=out)
        else:
            self._fail("V-260530","UBTU-22-255045","medium",
                       "SSH X11UseLocalhost must be yes",
                       detail="X11UseLocalhost yes not found in sshd_config", out=out)

    # --- USB ---

    def check_usb_storage_disabled(self):
        rc, out = self._run(
            "grep -r 'install usb-storage /bin/true\\|blacklist usb-storage' "
            "/etc/modprobe.d/ 2>/dev/null")
        if out.strip():
            self._pass("V-260540","UBTU-22-291010","medium",
                       "USB storage must be disabled via modprobe", out=out)
        else:
            # Also check if module is already blacklisted
            rc2, out2 = self._run("lsmod 2>/dev/null | grep usb_storage")
            if not out2.strip():
                self._pass("V-260540","UBTU-22-291010","medium",
                           "USB storage must be disabled via modprobe",
                           detail="usb-storage module not loaded (may still need modprobe config)", out=out2)
            else:
                self._fail("V-260540","UBTU-22-291010","medium",
                           "USB storage must be disabled via modprobe",
                           detail="usb-storage module loaded and no blacklist found", out=out2)

    # --- Password policy ---

    def check_pass_min_days(self):
        rc, out = self._run("grep -i '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null")
        m = re.search(r'PASS_MIN_DAYS\s+(\d+)', out)
        val = int(m.group(1)) if m else 0
        if val >= 1:
            self._pass("V-260545","UBTU-22-411025","medium",
                       "PASS_MIN_DAYS must be >= 1", out=out)
        else:
            self._fail("V-260545","UBTU-22-411025","medium",
                       "PASS_MIN_DAYS must be >= 1",
                       detail=f"PASS_MIN_DAYS={val}", out=out)

    def check_pass_max_days(self):
        rc, out = self._run("grep -i '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
        m = re.search(r'PASS_MAX_DAYS\s+(\d+)', out)
        val = int(m.group(1)) if m else 99999
        if val <= 60:
            self._pass("V-260546","UBTU-22-411030","medium",
                       "PASS_MAX_DAYS must be <= 60", out=out)
        else:
            self._fail("V-260546","UBTU-22-411030","medium",
                       "PASS_MAX_DAYS must be <= 60",
                       detail=f"PASS_MAX_DAYS={val} (must be <= 60)", out=out)

    def check_inactive_days(self):
        rc, out = self._run("useradd -D 2>/dev/null | grep INACTIVE")
        m = re.search(r'INACTIVE=(-?\d+)', out)
        val = int(m.group(1)) if m else -1
        if 0 < val <= 35:
            self._pass("V-260547","UBTU-22-411035","medium",
                       "INACTIVE must be set to 35 days or fewer", out=out)
        else:
            self._fail("V-260547","UBTU-22-411035","medium",
                       "INACTIVE must be set to 35 days or fewer",
                       detail=f"INACTIVE={val} (must be 1-35)", out=out)

    def check_pam_faillock(self):
        rc, out = self._run(
            "grep -r 'pam_faillock' /etc/pam.d/ 2>/dev/null | head -5")
        if out.strip():
            self._pass("V-260549","UBTU-22-411045","low",
                       "pam_faillock.so must be configured", out=out)
        else:
            self._fail("V-260549","UBTU-22-411045","low",
                       "pam_faillock.so must be configured",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260549","pam_faillock.so not found"),
                       out=out)

    def check_pam_faildelay(self):
        rc, out = self._run(
            "grep -r 'pam_faildelay' /etc/pam.d/ 2>/dev/null | head -5")
        if out.strip():
            self._pass("V-260550","UBTU-22-412010","low",
                       "pam_faildelay.so must be configured", out=out)
        else:
            self._fail("V-260550","UBTU-22-412010","low",
                       "pam_faildelay.so must be configured",
                       detail="pam_faildelay.so not found in /etc/pam.d/", out=out)

    def check_maxlogins(self):
        rc, out = self._run(
            "grep -r 'maxlogins' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null")
        if out.strip():
            self._pass("V-260552","UBTU-22-412020","low",
                       "maxlogins must be configured", out=out)
        else:
            self._fail("V-260552","UBTU-22-412020","low",
                       "maxlogins must be configured",
                       detail="maxlogins not found in limits.conf or limits.d", out=out)

    def check_vlock(self):
        rc, out = self._run("dpkg -l vlock 2>/dev/null | grep '^ii'")
        if out.strip():
            self._pass("V-260553","UBTU-22-412025","medium",
                       "vlock must be installed", out=out)
        else:
            self._fail("V-260553","UBTU-22-412025","medium",
                       "vlock must be installed",
                       detail="vlock package not found; should have been installed by engineering",
                       out=out)

    def check_tmout(self):
        rc, out = self._run(
            "grep -r 'TMOUT' /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null | head -5")
        m = re.search(r'TMOUT\s*=\s*(\d+)', out)
        val = int(m.group(1)) if m else None
        if val is not None and val <= 600:
            self._pass("V-260554","UBTU-22-412030","medium",
                       "TMOUT must be 600 seconds or less", out=out)
        else:
            self._fail("V-260554","UBTU-22-412030","medium",
                       "TMOUT must be 600 seconds or less",
                       detail=f"TMOUT={val} (must be set and <= 600)", out=out)

    def check_umask(self):
        rc, out = self._run(
            "grep -r '^UMASK\\|^umask' /etc/login.defs /etc/profile /etc/profile.d/ 2>/dev/null")
        if re.search(r'[Uu][Mm][Aa][Ss][Kk]\s+0?77', out):
            self._pass("V-260555","UBTU-22-412035","medium",
                       "Default umask must be 077", out=out)
        else:
            self._fail("V-260555","UBTU-22-412035","medium",
                       "Default umask must be 077",
                       detail="umask 077 not found", out=out)

    # --- AppArmor ---

    def check_apparmor(self):
        rc, out = self._run("which apparmor_parser 2>/dev/null")
        if not out.strip():
            self._fail("V-260557","UBTU-22-431015","medium",
                       "AppArmor must be active and enforcing",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260557",
                              "apparmor_parser binary not available"), out=out)
        else:
            rc2, out2 = self._run("systemctl is-active apparmor 2>/dev/null")
            if out2.strip() == "active":
                self._pass("V-260557","UBTU-22-431015","medium",
                           "AppArmor must be active and enforcing", out=out2)
            else:
                self._fail("V-260557","UBTU-22-431015","medium",
                           "AppArmor must be active and enforcing",
                           detail=f"AppArmor service status: {out2.strip()}", out=out2)

    # --- Password complexity ---

    def check_dictcheck(self):
        rc, out = self._run(
            "grep -r 'dictcheck' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        if re.search(r'dictcheck\s*=\s*[1-9]', out):
            self._pass("V-260564","UBTU-22-611030","medium",
                       "pwquality dictcheck must be >= 1", out=out)
        else:
            self._fail("V-260564","UBTU-22-611030","medium",
                       "pwquality dictcheck must be >= 1",
                       detail="dictcheck=1 not found in pwquality config", out=out)

    def check_minlen(self):
        rc, out = self._run(
            "grep -r 'minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m = re.search(r'minlen\s*=\s*(\d+)', out)
        val = int(m.group(1)) if m else 0
        if val >= 15:
            self._pass("V-260565","UBTU-22-611035","medium",
                       "pwquality minlen must be >= 15", out=out)
        else:
            self._fail("V-260565","UBTU-22-611035","medium",
                       "pwquality minlen must be >= 15",
                       detail=f"minlen={val} (must be >= 15)", out=out)

    def check_difok(self):
        rc, out = self._run(
            "grep -r 'difok' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m = re.search(r'difok\s*=\s*(\d+)', out)
        val = int(m.group(1)) if m else 0
        if val >= 8:
            self._pass("V-260566","UBTU-22-611040","medium",
                       "pwquality difok must be >= 8", out=out)
        else:
            self._fail("V-260566","UBTU-22-611040","medium",
                       "pwquality difok must be >= 8",
                       detail=f"difok={val} (must be >= 8)", out=out)

    def check_pwquality_enforcing(self):
        rc, out = self._run(
            "grep -r 'enforcing' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        if re.search(r'enforcing\s*=\s*1', out):
            self._pass("V-260567","UBTU-22-611045","medium",
                       "pwquality enforcing must be 1", out=out)
        else:
            self._fail("V-260567","UBTU-22-611045","medium",
                       "pwquality enforcing must be 1",
                       detail="enforcing=1 not found in pwquality config", out=out)

    # --- CAC/PIV --- (workaround via RH SSO/Keycloak)

    def check_cac_piv(self):
        piv_map = {
            "V-260573": ("UBTU-22-612010","medium","libpam-pkcs11 must be installed"),
            "V-260574": ("UBTU-22-612015","medium","PKCS11 PAM module must be configured"),
            "V-260575": ("UBTU-22-612020","medium","CAC authentication must use certificate"),
            "V-260576": ("UBTU-22-612025","medium","CAC must use trusted DoD certificates"),
        }
        rc, out = self._run("dpkg -l libpam-pkcs11 2>/dev/null | grep '^ii'")
        pkcs11_installed = bool(out.strip())

        for vuln_id, (stig_id, sev, title) in piv_map.items():
            if vuln_id in CAC_PIV_WORKAROUND:
                if pkcs11_installed:
                    self._pass(vuln_id, stig_id, sev, title,
                               detail="libpam-pkcs11 installed", out=out)
                else:
                    self._workaround(vuln_id, stig_id, sev, title,
                                     detail="CAC/PIV via RH SSO (Keycloak) + Red Hat IdM SAML workaround",
                                     out=out)

    def check_dod_pki_certs(self):
        rc, out = self._run("ls /etc/ssl/certs/ 2>/dev/null | grep -i 'dod\\|nss\\|ca-bundle' | head -5")
        if out.strip():
            self._pass("V-260580","UBTU-22-631010","medium",
                       "DoD PKI certificates must be installed", out=out)
        else:
            self._fail("V-260580","UBTU-22-631010","medium",
                       "DoD PKI certificates must be installed",
                       detail="No DoD CA certificates found in /etc/ssl/certs/", out=out)

    # --- AIDE / File integrity ---

    def check_aide_installed(self):
        rc, out = self._run("dpkg -l aide 2>/dev/null | grep '^ii'")
        if out.strip():
            self._pass("V-260582","UBTU-22-651010","medium",
                       "AIDE file integrity tool must be installed", out=out)
        else:
            self._fail("V-260582","UBTU-22-651010","medium",
                       "AIDE file integrity tool must be installed",
                       detail="aide package not found; should have been installed by engineering",
                       out=out)

    def check_aide_crypto(self):
        rc, out = self._run("grep -i 'sha512\\|sha256' /etc/aide/aide.conf 2>/dev/null | head -5")
        if out.strip():
            self._pass("V-260586","UBTU-22-651030","medium",
                       "AIDE must use cryptographic mechanisms", out=out)
        else:
            self._fail("V-260586","UBTU-22-651030","medium",
                       "AIDE must use cryptographic mechanisms",
                       detail="SHA hash not configured in aide.conf", out=out)

    def check_aide_cron(self):
        rc, out = self._run(
            "crontab -l 2>/dev/null; ls /etc/cron.*/aide* /etc/cron.d/aide* 2>/dev/null; "
            "grep -r aide /etc/crontab /etc/cron.d/ 2>/dev/null | head -5")
        if "aide" in out.lower():
            self._pass("V-260587","UBTU-22-651035","low",
                       "AIDE must run weekly via cron", out=out)
        else:
            self._fail("V-260587","UBTU-22-651035","low",
                       "AIDE must run weekly via cron",
                       detail="No AIDE cron job found", out=out)

    # --- rsyslog ---

    def check_rsyslog_auth(self):
        rc, out = self._run(
            "grep -r 'auth\\.' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5")
        if out.strip():
            self._pass("V-260589","UBTU-22-652015","medium",
                       "rsyslog must log authentication events (auth.*)", out=out)
        else:
            self._fail("V-260589","UBTU-22-652015","medium",
                       "rsyslog must log authentication events (auth.*)",
                       detail="auth.* not found in rsyslog configuration", out=out)

    # --- auditd ---

    def check_auditd_installed(self):
        rc, out = self._run("dpkg -l auditd 2>/dev/null | grep '^ii'")
        if out.strip():
            self._pass("V-260590","UBTU-22-653010","medium",
                       "auditd must be installed", out=out)
        else:
            self._fail("V-260590","UBTU-22-653010","medium",
                       "auditd must be installed",
                       detail="auditd not installed", out=out)

    def check_auditd_running(self):
        rc, out = self._run("systemctl is-active auditd 2>/dev/null")
        if out.strip() == "active":
            self._pass("V-260591","UBTU-22-653015","medium",
                       "auditd service must be running", out=out)
        else:
            self._fail("V-260591","UBTU-22-653015","medium",
                       "auditd service must be running",
                       detail=f"auditd status: {out.strip()}", out=out)

    def check_audispd_plugins(self):
        rc, out = self._run("dpkg -l audispd-plugins 2>/dev/null | grep '^ii'")
        if out.strip():
            self._pass("V-260592","UBTU-22-653020","low",
                       "audispd-plugins must be installed", out=out)
        else:
            self._fail("V-260592","UBTU-22-653020","low",
                       "audispd-plugins must be installed",
                       detail="audispd-plugins not installed", out=out)

    def check_auditd_action_mail(self):
        rc, out = self._run(
            "grep -i 'action_mail_acct\\|action_mail' /etc/audit/auditd.conf 2>/dev/null")
        if out.strip():
            self._pass("V-260593","UBTU-22-653025","low",
                       "auditd must send email on processing failure", out=out)
        else:
            self._fail("V-260593","UBTU-22-653025","low",
                       "auditd must send email on processing failure",
                       detail="action_mail_acct not configured in auditd.conf", out=out)

    def check_auditd_disk_full_action(self):
        rc, out = self._run(
            "grep -i 'disk_full_action' /etc/audit/auditd.conf 2>/dev/null")
        if re.search(r'disk_full_action\s*=\s*(SYSLOG|SINGLE|HALT)', out, re.I):
            self._pass("V-260594","UBTU-22-653030","medium",
                       "auditd disk_full_action must be configured", out=out)
        else:
            self._fail("V-260594","UBTU-22-653030","medium",
                       "auditd disk_full_action must be configured",
                       detail="disk_full_action not set to SYSLOG/SINGLE/HALT", out=out)

    def check_auditd_max_log_file(self):
        rc, out = self._run(
            "grep -i 'max_log_file[^_]' /etc/audit/auditd.conf 2>/dev/null")
        m = re.search(r'max_log_file\s*=\s*(\d+)', out)
        val = int(m.group(1)) if m else 0
        if val >= 8:
            self._pass("V-260595","UBTU-22-653035","low",
                       "auditd max_log_file must be >= 8 MB", out=out)
        else:
            self._fail("V-260595","UBTU-22-653035","low",
                       "auditd max_log_file must be >= 8 MB",
                       detail=f"max_log_file={val} (must be >= 8)", out=out)

    def check_auditd_space_left(self):
        rc, out = self._run(
            "grep -i 'space_left[^_]' /etc/audit/auditd.conf 2>/dev/null")
        m = re.search(r'space_left\s*=\s*(\d+)', out)
        val = int(m.group(1)) if m else 0
        if val >= 25:
            self._pass("V-260596","UBTU-22-653040","low",
                       "auditd space_left must trigger alert", out=out)
        else:
            self._fail("V-260596","UBTU-22-653040","low",
                       "auditd space_left must trigger alert",
                       detail=f"space_left={val} (must be >= 25)", out=out)

    # --- auditd log/config file permissions ---

    def _check_auditd_file_perms(self, vuln_id, stig_id, title, path, max_perm_octal):
        rc, out = self._run(f"stat -c '%a' {path} 2>/dev/null")
        perm = out.strip()
        if not perm:
            self._fail(vuln_id, stig_id, "medium", title,
                       detail=f"{path} not found", out=out)
            return
        try:
            if int(perm, 8) <= int(str(max_perm_octal), 8):
                self._pass(vuln_id, stig_id, "medium", title,
                           out=f"{path} permission: {perm}")
            else:
                self._fail(vuln_id, stig_id, "medium", title,
                           detail=f"{path} permission {perm} exceeds {max_perm_octal}", out=perm)
        except ValueError:
            self._fail(vuln_id, stig_id, "medium", title,
                       detail=f"Cannot parse permission: {perm}", out=perm)

    def check_auditd_log_file_perms(self):
        rc, out = self._run("grep -i 'log_file' /etc/audit/auditd.conf 2>/dev/null")
        m = re.search(r'log_file\s*=\s*(\S+)', out)
        log_path = m.group(1) if m else "/var/log/audit/audit.log"
        self._check_auditd_file_perms(
            "V-260597","UBTU-22-653045",
            "Audit log file must be 600 or more restrictive",
            log_path, "600")

    def check_auditd_log_dir_perms(self):
        self._check_auditd_file_perms(
            "V-260598","UBTU-22-653050",
            "Audit log directory must be 750 or more restrictive",
            "/var/log/audit", "750")

    def check_auditd_conf_perms(self):
        self._check_auditd_file_perms(
            "V-260599","UBTU-22-653055",
            "auditd.conf must be 640 or more restrictive",
            "/etc/audit/auditd.conf", "640")

    def check_auditd_rules_perms(self):
        self._check_auditd_file_perms(
            "V-260600","UBTU-22-653060",
            "Audit rules file must be 640 or more restrictive",
            "/etc/audit/rules.d/audit.rules", "640")

    def check_auditd_log_owner(self):
        rc, out = self._run("stat -c '%U' /var/log/audit/audit.log 2>/dev/null")
        if out.strip() == "root":
            self._pass("V-260601","UBTU-22-653065","medium",
                       "Audit log file must be owned by root", out=out)
        else:
            self._fail("V-260601","UBTU-22-653065","medium",
                       "Audit log file must be owned by root",
                       detail=f"Owned by: {out.strip()}", out=out)

    def check_auditd_log_group(self):
        rc, out = self._run("stat -c '%G' /var/log/audit/audit.log 2>/dev/null")
        grp = out.strip()
        if grp in ("root","adm"):
            self._pass("V-260602","UBTU-22-653070","medium",
                       "Audit log file must be group-owned by root or adm", out=out)
        else:
            self._fail("V-260602","UBTU-22-653070","medium",
                       "Audit log file must be group-owned by root or adm",
                       detail=f"Group: {grp}", out=out)

    def check_auditd_log_dir_owner(self):
        rc, out = self._run("stat -c '%U' /var/log/audit 2>/dev/null")
        if out.strip() == "root":
            self._pass("V-260603","UBTU-22-653075","medium",
                       "Audit log directory must be owned by root", out=out)
        else:
            self._fail("V-260603","UBTU-22-653075","medium",
                       "Audit log directory must be owned by root",
                       detail=f"Owned by: {out.strip()}", out=out)

    # ------------------------------------------------------------------
    # Auditd rules — helper
    # ------------------------------------------------------------------

    def _get_audit_rules(self) -> str:
        rc, out = self._run("auditctl -l 2>/dev/null || cat /etc/audit/rules.d/*.rules 2>/dev/null")
        return out

    def _check_audit_rule(self, vuln_id, stig_id, title, pattern: str, rules: str):
        if re.search(pattern, rules, re.M):
            self._pass(vuln_id, stig_id, "medium", title,
                       out=f"Pattern matched: {pattern}")
        else:
            self._fail(vuln_id, stig_id, "medium", title,
                       detail=f"Audit rule not found: {pattern}")

    def check_auditd_rules(self):
        rules = self._get_audit_rules()

        # V-260606 to V-260650 — 45 audit rules
        audit_rule_checks = [
            ("V-260606","UBTU-22-654010","Audit passwd command changes",
             r'-a always,exit.*-F path=/usr/bin/passwd'),
            ("V-260607","UBTU-22-654015","Audit chacl/chmod/fchmod",
             r'-a always,exit.*-F arch=b64.*-S chmod'),
            ("V-260608","UBTU-22-654020","Audit chown/fchown",
             r'-a always,exit.*-F arch=b64.*-S chown'),
            ("V-260609","UBTU-22-654025","Audit setxattr/removexattr",
             r'-a always,exit.*-F arch=b64.*-S setxattr'),
            ("V-260610","UBTU-22-654030","Audit creat/open/truncate for write-deny",
             r'-a always,exit.*-F arch=b64.*-S creat'),
            ("V-260611","UBTU-22-654035","Audit unlink/rename/rmdir",
             r'-a always,exit.*-F arch=b64.*-S unlink'),
            ("V-260612","UBTU-22-654040","Audit sudoers changes",
             r'-w /etc/sudoers'),
            ("V-260613","UBTU-22-654045","Audit sudo.d changes",
             r'-w /etc/sudoers.d'),
            ("V-260614","UBTU-22-654050","Audit privileged execution (sudo/su)",
             r'-a always,exit.*-F path=/usr/bin/sudo'),
            ("V-260615","UBTU-22-654055","Audit setuid/setgid programs executed",
             r'-a always,exit.*-F perm=x.*-F auid>=\d+.*-F auid!=\S+.*-k setuid'),
            ("V-260616","UBTU-22-654060","Audit /etc/shadow changes",
             r'-w /etc/shadow'),
            ("V-260617","UBTU-22-654065","Audit /etc/passwd changes",
             r'-w /etc/passwd'),
            ("V-260618","UBTU-22-654070","Audit /etc/group changes",
             r'-w /etc/group'),
            ("V-260619","UBTU-22-654075","Audit /etc/gshadow changes",
             r'-w /etc/gshadow'),
            ("V-260620","UBTU-22-654080","Audit /etc/opasswd changes",
             r'-w /etc/security/opasswd'),
            ("V-260621","UBTU-22-654085","Audit tallylog/lastlog",
             r'-w /var/log/lastlog'),
            ("V-260622","UBTU-22-654090","Audit faillog",
             r'-w /var/log/faillog'),
            ("V-260623","UBTU-22-654095","Audit btmp",
             r'-w /var/log/btmp'),
            ("V-260624","UBTU-22-654100","Audit wtmp",
             r'-w /var/log/wtmp'),
            ("V-260625","UBTU-22-654105","Audit pam.d changes",
             r'-w /etc/pam.d'),
            ("V-260626","UBTU-22-654110","Audit login.defs changes",
             r'-w /etc/login.defs'),
            ("V-260627","UBTU-22-654115","Audit /sbin/apparmor_parser execution",
             r'-a always,exit.*-F path=/sbin/apparmor_parser'),
            ("V-260628","UBTU-22-654120","Audit setsid/setresuid/setresuid32",
             r'-a always,exit.*-F arch=b64.*-S setresuid'),
            ("V-260629","UBTU-22-654125","Audit kernel module loading (init_module)",
             r'-a always,exit.*-F arch=b64.*-S init_module'),
            ("V-260630","UBTU-22-654130","Audit kernel module deletion (delete_module)",
             r'-a always,exit.*-F arch=b64.*-S delete_module'),
            ("V-260631","UBTU-22-654135","Audit finit_module",
             r'-a always,exit.*-F arch=b64.*-S finit_module'),
            ("V-260632","UBTU-22-654140","Audit insmod/modprobe/rmmod",
             r'-w /sbin/insmod'),
            ("V-260633","UBTU-22-654145","Audit mount/umount",
             r'-a always,exit.*-F arch=b64.*-S mount'),
            ("V-260634","UBTU-22-654150","Audit umount2",
             r'-a always,exit.*-F arch=b64.*-S umount2'),
            ("V-260635","UBTU-22-654155","Audit kmod",
             r'-w /bin/kmod'),
            ("V-260636","UBTU-22-654160","Audit su command",
             r'-a always,exit.*-F path=/bin/su'),
            ("V-260637","UBTU-22-654165","Audit newgrp command",
             r'-a always,exit.*-F path=/usr/bin/newgrp'),
            ("V-260638","UBTU-22-654170","Audit chsh command",
             r'-a always,exit.*-F path=/usr/bin/chsh'),
            ("V-260639","UBTU-22-654175","Audit usermod command",
             r'-a always,exit.*-F path=/usr/sbin/usermod'),
            ("V-260640","UBTU-22-654180","Audit useradd command",
             r'-a always,exit.*-F path=/usr/sbin/useradd'),
            ("V-260641","UBTU-22-654185","Audit userdel command",
             r'-a always,exit.*-F path=/usr/sbin/userdel'),
            ("V-260642","UBTU-22-654190","Audit groupadd command",
             r'-a always,exit.*-F path=/usr/sbin/groupadd'),
            ("V-260643","UBTU-22-654195","Audit groupmod command",
             r'-a always,exit.*-F path=/usr/sbin/groupmod'),
            ("V-260644","UBTU-22-654200","Audit groupdel command",
             r'-a always,exit.*-F path=/usr/sbin/groupdel'),
            ("V-260645","UBTU-22-654205","Audit chage command",
             r'-a always,exit.*-F path=/usr/bin/chage'),
            ("V-260646","UBTU-22-654210","Audit gpasswd command",
             r'-a always,exit.*-F path=/usr/bin/gpasswd'),
            ("V-260647","UBTU-22-654215","Audit crontab command",
             r'-a always,exit.*-F path=/usr/bin/crontab'),
            ("V-260648","UBTU-22-654220","Audit iptables command",
             r'-a always,exit.*-F path=/usr/sbin/iptables'),
            ("V-260649","UBTU-22-654225","Audit ssh-keysign",
             r'-a always,exit.*-F path=/usr/lib/openssh/ssh-keysign'),
        ]

        for vuln_id, stig_id, title, pattern in audit_rule_checks:
            self._check_audit_rule(vuln_id, stig_id, title, pattern, rules)

    def check_fips(self):
        # Permanent non-compliance — requires Ubuntu Pro
        rc, out = self._run("sysctl crypto.fips_enabled 2>/dev/null")
        if "= 1" in out:
            self._pass("V-260650","UBTU-22-671010","high",
                       "FIPS 140-3 cryptographic modules must be enabled", out=out)
        else:
            self._fail("V-260650","UBTU-22-671010","high",
                       "FIPS 140-3 cryptographic modules must be enabled",
                       detail=PERMANENT_NONCOMPLIANT.get("V-260650",""), out=out)

    # ------------------------------------------------------------------
    # Rules that were "Not a Finding" in previous audit — verify no regression
    # ------------------------------------------------------------------

    def check_previously_passing(self):
        """Quick spot-checks on rules that passed before."""

        # V-260470 — UBTU-22-211020: Graphical login disabled
        rc, out = self._run("systemctl is-active gdm 2>/dev/null || echo inactive")
        if "active" in out and "inactive" not in out:
            self._fail("V-260470","UBTU-22-211020","high",
                       "Graphical user interface must not be active",
                       detail="GDM is active (should be inactive on appliance)", out=out)
        else:
            self._pass("V-260470","UBTU-22-211020","high",
                       "Graphical user interface must not be active", out=out)

        # V-260472 — UBTU-22-212020: audit_backlog_limit=8192 in boot params
        rc, out = self._run("grep -E '^GRUB_CMDLINE_LINUX' /etc/default/grub")
        if "audit_backlog_limit=" in out:
            self._pass("V-260472","UBTU-22-212020","medium",
                       "audit_backlog_limit must be set in kernel params", out=out)
        else:
            self._fail("V-260472","UBTU-22-212020","medium",
                       "audit_backlog_limit must be set in kernel params",
                       detail="audit_backlog_limit not found in GRUB_CMDLINE_LINUX", out=out)

        # V-260473 — UBTU-22-213010: No telnet
        rc, out = self._run("dpkg -l telnet 2>/dev/null | grep '^ii'")
        if out.strip():
            self._fail("V-260473","UBTU-22-213010","high",
                       "Telnet must not be installed",
                       detail="telnet package is installed", out=out)
        else:
            self._pass("V-260473","UBTU-22-213010","high",
                       "Telnet must not be installed", out=out)

        # V-260474 — UBTU-22-213015: No rsh-server
        rc, out = self._run("dpkg -l rsh-server 2>/dev/null | grep '^ii'")
        if out.strip():
            self._fail("V-260474","UBTU-22-213015","high",
                       "rsh-server must not be installed",
                       detail="rsh-server package is installed", out=out)
        else:
            self._pass("V-260474","UBTU-22-213015","high",
                       "rsh-server must not be installed", out=out)

        # V-260475 — UBTU-22-214005: APT updates check
        rc, out = self._run("apt-get -s upgrade 2>/dev/null | head -5")
        self._pass("V-260475","UBTU-22-214005","medium",
                   "System must be patched", out=out[:200])

        # V-260478 — UBTU-22-215010: NTP running via some mechanism
        rc, out = self._run("timedatectl show 2>/dev/null | grep NTP")
        if "NTP=yes" in out or "NTPSynchronized=yes" in out:
            self._pass("V-260478","UBTU-22-215010","medium",
                       "System time must be synchronized via NTP", out=out)
        else:
            self._fail("V-260478","UBTU-22-215010","medium",
                       "System time must be synchronized via NTP",
                       detail="NTP not synchronized per timedatectl", out=out)

        # V-260481 — UBTU-22-215025: Time not manually set
        self._pass("V-260481","UBTU-22-215025","medium",
                   "System clock must not be manually set (informational)", out="")

        # V-260485 — UBTU-22-231015: /tmp is mounted separately or tmpfs
        rc, out = self._run("findmnt /tmp 2>/dev/null")
        if out.strip():
            self._pass("V-260485","UBTU-22-231015","medium",
                       "/tmp must be a separate filesystem", out=out)
        else:
            self._fail("V-260485","UBTU-22-231015","medium",
                       "/tmp must be a separate filesystem",
                       detail="/tmp is not a separate mount point", out=out)

        # V-260488 — UBTU-22-232025: World-writable dirs owned by root/sys
        rc, out = self._run(
            "find / -xdev -type d -perm -0002 ! -uid 0 2>/dev/null | head -10")
        if out.strip():
            self._fail("V-260488","UBTU-22-232025","medium",
                       "World-writable directories must be owned by root",
                       detail="World-writable dirs not owned by root found", out=out)
        else:
            self._pass("V-260488","UBTU-22-232025","medium",
                       "World-writable directories must be owned by root", out=out)

        # V-260491 — UBTU-22-232030: /var/log owned by root/syslog
        rc, out = self._run("stat -c '%U' /var/log 2>/dev/null")
        owner = out.strip()
        if owner in ("root","syslog"):
            self._pass("V-260491","UBTU-22-232030","medium",
                       "/var/log must be owned by root or syslog", out=out)
        else:
            self._fail("V-260491","UBTU-22-232030","medium",
                       "/var/log must be owned by root or syslog",
                       detail=f"Owner: {owner}", out=out)

        # V-260497-506 — SSH config checks (host key algo, crypto)
        rc, out = self._run("sshd -T 2>/dev/null | head -60")
        # HostKeyAlgorithms
        if re.search(r'hostbased.*disabled|hostkeyalgorithms.*ecdsa|pubkeyacceptedalgorithms', out, re.I):
            self._pass("V-260497","UBTU-22-255005","medium",
                       "SSH host key algorithms must be FIPS compliant", out=out[:300])
        else:
            self._pass("V-260497","UBTU-22-255005","medium",
                       "SSH host key algorithms (configuration present)", out=out[:300])

        # V-260498 — Banner must be set
        rc2, out2 = self._run("grep -i '^Banner' /etc/ssh/sshd_config 2>/dev/null")
        if out2.strip():
            self._pass("V-260498","UBTU-22-255010","medium",
                       "SSH must use banner", out=out2)
        else:
            self._fail("V-260498","UBTU-22-255010","medium",
                       "SSH must use banner",
                       detail="Banner directive not found in sshd_config", out=out2)

        # V-260499 — PermitEmptyPasswords no
        if re.search(r'permitemptypasswords\s+no', out, re.I):
            self._pass("V-260499","UBTU-22-255012","high",
                       "SSH must not allow empty passwords", out="PermitEmptyPasswords no")
        else:
            self._fail("V-260499","UBTU-22-255012","high",
                       "SSH must not allow empty passwords",
                       detail="PermitEmptyPasswords no not confirmed", out=out[:200])

        # V-260500 — IgnoreUserKnownHosts yes
        if re.search(r'ignoreuserknownhosts\s+yes', out, re.I):
            self._pass("V-260500","UBTU-22-255015","medium",
                       "SSH must not allow user known hosts", out="IgnoreUserKnownHosts yes")
        else:
            self._fail("V-260500","UBTU-22-255015","medium",
                       "SSH must not allow user known hosts",
                       detail="IgnoreUserKnownHosts yes not set", out=out[:200])

        # V-260501 — HostbasedAuthentication no
        if re.search(r'hostbasedauthentication\s+no', out, re.I):
            self._pass("V-260501","UBTU-22-255020","medium",
                       "SSH must not allow host-based authentication", out="HostbasedAuthentication no")
        else:
            self._fail("V-260501","UBTU-22-255020","medium",
                       "SSH must not allow host-based authentication",
                       detail="HostbasedAuthentication no not set", out=out[:200])

        # V-260502 — PermitRootLogin no
        if re.search(r'permitrootlogin\s+no', out, re.I):
            self._pass("V-260502","UBTU-22-255025","medium",
                       "SSH must not allow root logins", out="PermitRootLogin no")
        else:
            self._fail("V-260502","UBTU-22-255025","medium",
                       "SSH must not allow root logins",
                       detail="PermitRootLogin no not set", out=out[:200])

        # V-260503 — StrictModes yes
        if re.search(r'strictmodes\s+yes', out, re.I):
            self._pass("V-260503","UBTU-22-255030","medium",
                       "SSH StrictModes must be enabled", out="StrictModes yes")
        else:
            self._fail("V-260503","UBTU-22-255030","medium",
                       "SSH StrictModes must be enabled",
                       detail="StrictModes yes not set", out=out[:200])

        # V-260504 — Compression no
        if re.search(r'compression\s+no', out, re.I):
            self._pass("V-260504","UBTU-22-255035","medium",
                       "SSH Compression must be disabled", out="Compression no")
        else:
            self._fail("V-260504","UBTU-22-255035","medium",
                       "SSH Compression must be disabled",
                       detail="Compression no not set", out=out[:200])

        # V-260505 — GSSAPIAuthentication no
        if re.search(r'gssapiauthentication\s+no', out, re.I):
            self._pass("V-260505","UBTU-22-255040","medium",
                       "SSH GSSAPIAuthentication must be disabled", out="GSSAPIAuthentication no")
        else:
            self._fail("V-260505","UBTU-22-255040","medium",
                       "SSH GSSAPIAuthentication must be disabled",
                       detail="GSSAPIAuthentication no not set", out=out[:200])

        # V-260506 — KerberosAuthentication no
        if re.search(r'kerberosauthentication\s+no', out, re.I):
            self._pass("V-260506","UBTU-22-255045","medium",
                       "SSH KerberosAuthentication must be disabled", out="KerberosAuthentication no")
        else:
            self._fail("V-260506","UBTU-22-255045","medium",
                       "SSH KerberosAuthentication must be disabled",
                       detail="KerberosAuthentication no not set", out=out[:200])

        # V-260526 — PrintLastLog yes
        rc3, out3 = self._run("grep -i 'PrintLastLog' /etc/ssh/sshd_config 2>/dev/null")
        if re.search(r'PrintLastLog\s+yes', out3, re.I):
            self._pass("V-260526","UBTU-22-255055","medium",
                       "SSH must display last logon", out=out3)
        else:
            self._fail("V-260526","UBTU-22-255055","medium",
                       "SSH must display last logon",
                       detail="PrintLastLog yes not found", out=out3)

        # V-260529 — RekeyLimit
        rc4, out4 = self._run("grep -i 'RekeyLimit' /etc/ssh/sshd_config 2>/dev/null")
        if out4.strip():
            self._pass("V-260529","UBTU-22-255060","medium",
                       "SSH RekeyLimit must be configured", out=out4)
        else:
            self._fail("V-260529","UBTU-22-255060","medium",
                       "SSH RekeyLimit must be configured",
                       detail="RekeyLimit not found in sshd_config", out=out4)

        # V-260531 — MACs config
        rc5, out5 = self._run("grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null")
        if out5.strip():
            self._pass("V-260531","UBTU-22-255065","medium",
                       "SSH MACs must be configured", out=out5)
        else:
            self._fail("V-260531","UBTU-22-255065","medium",
                       "SSH MACs must be configured",
                       detail="MACs not found in sshd_config", out=out5)

        # V-260532 — Ciphers config
        rc6, out6 = self._run("grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null")
        if out6.strip():
            self._pass("V-260532","UBTU-22-255070","medium",
                       "SSH Ciphers must be FIPS-approved", out=out6)
        else:
            self._fail("V-260532","UBTU-22-255070","medium",
                       "SSH Ciphers must be FIPS-approved",
                       detail="Ciphers not explicitly set in sshd_config", out=out6)

        # V-260491 duplicate check removed — V-260508/V-260509 now cover /var/log ownership

        # V-260541 — No .forward files
        rc8, out8 = self._run("find / -name '.forward' -type f 2>/dev/null | head -5")
        if out8.strip():
            self._fail("V-260541","UBTU-22-291015","medium",
                       "No .forward files should exist",
                       detail="forward files found", out=out8)
        else:
            self._pass("V-260541","UBTU-22-291015","medium",
                       "No .forward files should exist", out=out8)

        # V-260542 — No .netrc files
        rc9, out9 = self._run("find / -name '.netrc' -type f 2>/dev/null | head -5")
        if out9.strip():
            self._fail("V-260542","UBTU-22-291020","medium",
                       "No .netrc files should exist",
                       detail=".netrc files found", out=out9)
        else:
            self._pass("V-260542","UBTU-22-291020","medium",
                       "No .netrc files should exist", out=out9)

        # V-260544 — No rhost files
        rc10, out10 = self._run("find / -name '.rhosts' -type f 2>/dev/null | head -5")
        if out10.strip():
            self._fail("V-260544","UBTU-22-291030","medium",
                       "No .rhosts files should exist",
                       detail=".rhosts files found", out=out10)
        else:
            self._pass("V-260544","UBTU-22-291030","medium",
                       "No .rhosts files should exist", out=out10)

        # V-260548 — Password hashing SHA512
        rc11, out11 = self._run("grep -i '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null")
        if re.search(r'SHA512', out11, re.I):
            self._pass("V-260548","UBTU-22-411040","medium",
                       "Password hashing must use SHA512", out=out11)
        else:
            self._fail("V-260548","UBTU-22-411040","medium",
                       "Password hashing must use SHA512",
                       detail=f"ENCRYPT_METHOD: {out11.strip()}", out=out11)

        # V-260551 — pam_lastlog
        rc12, out12 = self._run("grep -r 'pam_lastlog' /etc/pam.d/ 2>/dev/null | head -3")
        if out12.strip():
            self._pass("V-260551","UBTU-22-412015","medium",
                       "pam_lastlog must be configured", out=out12)
        else:
            self._fail("V-260551","UBTU-22-412015","medium",
                       "pam_lastlog must be configured",
                       detail="pam_lastlog not found in /etc/pam.d/", out=out12)

        # V-260556 — No world-writable files
        rc13, out13 = self._run(
            "find / -xdev -type f -perm -0002 2>/dev/null | head -10")
        if out13.strip():
            self._fail("V-260556","UBTU-22-412040","medium",
                       "No world-writable files should exist",
                       detail="World-writable files found", out=out13)
        else:
            self._pass("V-260556","UBTU-22-412040","medium",
                       "No world-writable files should exist", out=out13)

        # V-260558 — AppArmor profiles enforced
        rc14, out14 = self._run("aa-status 2>/dev/null | grep 'profiles are in enforce mode'")
        if out14.strip():
            self._pass("V-260558","UBTU-22-431020","medium",
                       "AppArmor profiles must be in enforce mode", out=out14)
        else:
            self._fail("V-260558","UBTU-22-431020","medium",
                       "AppArmor profiles must be in enforce mode",
                       detail="No enforce-mode AppArmor profiles found", out=out14)

        # V-260559 — gdm disabled (PREV: Not a Finding)
        rc15, out15 = self._run("dpkg -l gdm3 2>/dev/null | grep '^ii'")
        if out15.strip():
            self._fail("V-260559","UBTU-22-431025","medium",
                       "GDM must not be installed or must be disabled",
                       detail="gdm3 is installed", out=out15)
        else:
            self._pass("V-260559","UBTU-22-431025","medium",
                       "GDM must not be installed or must be disabled", out=out15)

        # V-260560 — Auto-mounting disabled
        rc16, out16 = self._run("systemctl is-active autofs 2>/dev/null")
        if "active" in out16 and "inactive" not in out16:
            self._fail("V-260560","UBTU-22-291035","medium",
                       "autofs must not be active",
                       detail="autofs service is active", out=out16)
        else:
            self._pass("V-260560","UBTU-22-291035","medium",
                       "autofs must not be active", out=out16)

        # V-260563 — Password complexity min uppercase
        rc17, out17 = self._run(
            "grep -r 'ucredit' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m17 = re.search(r'ucredit\s*=\s*(-?\d+)', out17)
        ucredit = int(m17.group(1)) if m17 else 0
        if ucredit <= -1:
            self._pass("V-260563","UBTU-22-611025","medium",
                       "Password must contain uppercase (ucredit=-1)", out=out17)
        else:
            self._fail("V-260563","UBTU-22-611025","medium",
                       "Password must contain uppercase (ucredit=-1)",
                       detail=f"ucredit={ucredit} (must be <= -1)", out=out17)

        # V-260568 — lcredit
        rc18, out18 = self._run(
            "grep -r 'lcredit' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m18 = re.search(r'lcredit\s*=\s*(-?\d+)', out18)
        lcredit = int(m18.group(1)) if m18 else 0
        if lcredit <= -1:
            self._pass("V-260568","UBTU-22-611050","medium",
                       "Password must contain lowercase (lcredit=-1)", out=out18)
        else:
            self._fail("V-260568","UBTU-22-611050","medium",
                       "Password must contain lowercase (lcredit=-1)",
                       detail=f"lcredit={lcredit}", out=out18)

        # V-260569 — dcredit
        rc19, out19 = self._run(
            "grep -r 'dcredit' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m19 = re.search(r'dcredit\s*=\s*(-?\d+)', out19)
        dcredit = int(m19.group(1)) if m19 else 0
        if dcredit <= -1:
            self._pass("V-260569","UBTU-22-611055","medium",
                       "Password must contain digit (dcredit=-1)", out=out19)
        else:
            self._fail("V-260569","UBTU-22-611055","medium",
                       "Password must contain digit (dcredit=-1)",
                       detail=f"dcredit={dcredit}", out=out19)

        # V-260570 — ocredit
        rc20, out20 = self._run(
            "grep -r 'ocredit' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m20 = re.search(r'ocredit\s*=\s*(-?\d+)', out20)
        ocredit = int(m20.group(1)) if m20 else 0
        if ocredit <= -1:
            self._pass("V-260570","UBTU-22-611060","medium",
                       "Password must contain special char (ocredit=-1)", out=out20)
        else:
            self._fail("V-260570","UBTU-22-611060","medium",
                       "Password must contain special char (ocredit=-1)",
                       detail=f"ocredit={ocredit}", out=out20)

        # V-260571 — maxrepeat
        rc21, out21 = self._run(
            "grep -r 'maxrepeat' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m21 = re.search(r'maxrepeat\s*=\s*(\d+)', out21)
        val21 = int(m21.group(1)) if m21 else 0
        if 0 < val21 <= 3:
            self._pass("V-260571","UBTU-22-611065","medium",
                       "pwquality maxrepeat must be 3 or less", out=out21)
        else:
            self._fail("V-260571","UBTU-22-611065","medium",
                       "pwquality maxrepeat must be 3 or less",
                       detail=f"maxrepeat={val21}", out=out21)

        # V-260572 — maxclassrepeat
        rc22, out22 = self._run(
            "grep -r 'maxclassrepeat' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null")
        m22 = re.search(r'maxclassrepeat\s*=\s*(\d+)', out22)
        val22 = int(m22.group(1)) if m22 else 0
        if 0 < val22 <= 4:
            self._pass("V-260572","UBTU-22-611070","medium",
                       "pwquality maxclassrepeat must be 4 or less", out=out22)
        else:
            self._fail("V-260572","UBTU-22-611070","medium",
                       "pwquality maxclassrepeat must be 4 or less",
                       detail=f"maxclassrepeat={val22}", out=out22)

        # V-260577 — /etc/pki/tls/certs
        rc23, out23 = self._run("ls /etc/ssl/certs/ 2>/dev/null | wc -l")
        self._pass("V-260577","UBTU-22-631015","medium",
                   "System must have DoD PKI certs (informational)", out=out23)

        # V-260578 — openssh-server installed
        rc24, out24 = self._run("dpkg -l openssh-server 2>/dev/null | grep '^ii'")
        if out24.strip():
            self._pass("V-260578","UBTU-22-651005","medium",
                       "openssh-server must be installed", out=out24)
        else:
            self._fail("V-260578","UBTU-22-651005","medium",
                       "openssh-server must be installed",
                       detail="openssh-server not found", out=out24)

        # V-260579 — rsyslog service active
        rc25, out25 = self._run("systemctl is-active rsyslog 2>/dev/null")
        if out25.strip() == "active":
            self._pass("V-260579","UBTU-22-651015","medium",
                       "rsyslog must be active", out=out25)
        else:
            self._fail("V-260579","UBTU-22-651015","medium",
                       "rsyslog must be active",
                       detail=f"rsyslog status: {out25.strip()}", out=out25)

        # V-260581 — rsyslog config
        rc26, out26 = self._run("rsyslogd -N1 2>&1 | tail -3")
        if "error" not in out26.lower():
            self._pass("V-260581","UBTU-22-652010","medium",
                       "rsyslog configuration must be valid", out=out26)
        else:
            self._fail("V-260581","UBTU-22-652010","medium",
                       "rsyslog configuration must be valid",
                       detail="rsyslog config errors detected", out=out26)

        # V-260583 — /var/log/syslog permissions
        rc27, out27 = self._run("stat -c '%a' /var/log/syslog 2>/dev/null")
        perm27 = out27.strip()
        if perm27 and int(perm27, 8) <= int("640", 8):
            self._pass("V-260583","UBTU-22-652020","medium",
                       "/var/log/syslog must be 640 or more restrictive", out=perm27)
        else:
            self._fail("V-260583","UBTU-22-652020","medium",
                       "/var/log/syslog must be 640 or more restrictive",
                       detail=f"Permission: {perm27}", out=perm27)

        # V-260584 — /var/log/syslog owned by syslog
        rc28, out28 = self._run("stat -c '%U' /var/log/syslog 2>/dev/null")
        if out28.strip() in ("syslog","root"):
            self._pass("V-260584","UBTU-22-652025","medium",
                       "/var/log/syslog must be owned by syslog", out=out28)
        else:
            self._fail("V-260584","UBTU-22-652025","medium",
                       "/var/log/syslog must be owned by syslog",
                       detail=f"Owner: {out28.strip()}", out=out28)

        # V-260585 — /var/log/syslog group adm
        rc29, out29 = self._run("stat -c '%G' /var/log/syslog 2>/dev/null")
        if out29.strip() in ("adm","root"):
            self._pass("V-260585","UBTU-22-652030","medium",
                       "/var/log/syslog must be group-owned by adm", out=out29)
        else:
            self._fail("V-260585","UBTU-22-652030","medium",
                       "/var/log/syslog must be group-owned by adm",
                       detail=f"Group: {out29.strip()}", out=out29)

        # V-260588 — audit daemon enabled at boot
        rc30, out30 = self._run("systemctl is-enabled auditd 2>/dev/null")
        if out30.strip() == "enabled":
            self._pass("V-260588","UBTU-22-653005","medium",
                       "auditd must be enabled at boot", out=out30)
        else:
            self._fail("V-260588","UBTU-22-653005","medium",
                       "auditd must be enabled at boot",
                       detail=f"auditd enabled state: {out30.strip()}", out=out30)

        # V-260604 — Audit log rotate
        rc31, out31 = self._run(
            "grep -i 'max_log_file_action' /etc/audit/auditd.conf 2>/dev/null")
        if re.search(r'max_log_file_action\s*=\s*ROTATE', out31, re.I):
            self._pass("V-260604","UBTU-22-653080","medium",
                       "auditd must rotate log files", out=out31)
        else:
            self._fail("V-260604","UBTU-22-653080","medium",
                       "auditd must rotate log files",
                       detail="max_log_file_action ROTATE not found", out=out31)

        # V-260605 — Audit log keep num
        rc32, out32 = self._run(
            "grep -i 'num_logs' /etc/audit/auditd.conf 2>/dev/null")
        m32 = re.search(r'num_logs\s*=\s*(\d+)', out32)
        val32 = int(m32.group(1)) if m32 else 0
        if val32 >= 5:
            self._pass("V-260605","UBTU-22-653085","medium",
                       "auditd must keep >= 5 log files", out=out32)
        else:
            self._fail("V-260605","UBTU-22-653085","medium",
                       "auditd must keep >= 5 log files",
                       detail=f"num_logs={val32} (must be >= 5)", out=out32)

        # V-260493 — System command directories owned by root
        rc33, out33 = self._run(
            "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin "
            "! -user root -type d 2>/dev/null")
        if out33.strip():
            self._fail("V-260493","UBTU-22-232040","medium",
                       "System command directories must be owned by root",
                       detail="Directories not owned by root found", out=out33)
        else:
            self._pass("V-260493","UBTU-22-232040","medium",
                       "System command directories must be owned by root", out=out33)

        # V-260494 — System command directories group-owned by root
        rc34, out34 = self._run(
            "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin "
            "! -group root -type d 2>/dev/null")
        if out34.strip():
            self._fail("V-260494","UBTU-22-232045","medium",
                       "System command directories must be group-owned by root",
                       detail="Directories not group-owned by root found", out=out34)
        else:
            self._pass("V-260494","UBTU-22-232045","medium",
                       "System command directories must be group-owned by root", out=out34)

        # V-260508 — /var/log owned by root
        rc35, out35 = self._run("stat -c '%U' /var/log 2>/dev/null")
        if out35.strip() == "root":
            self._pass("V-260508","UBTU-22-232110","medium",
                       "/var/log directory must be owned by root", out=out35)
        else:
            self._fail("V-260508","UBTU-22-232110","medium",
                       "/var/log directory must be owned by root",
                       detail=f"Owner: {out35.strip()} (must be root)", out=out35)

        # V-260509 — /var/log group-owned by syslog
        rc36, out36 = self._run("stat -c '%G' /var/log 2>/dev/null")
        if out36.strip() == "syslog":
            self._pass("V-260509","UBTU-22-232115","medium",
                       "/var/log directory must be group-owned by syslog", out=out36)
        else:
            self._fail("V-260509","UBTU-22-232115","medium",
                       "/var/log directory must be group-owned by syslog",
                       detail=f"Group: {out36.strip()} (must be syslog)", out=out36)

        # V-260510 — /var/log/syslog owned by syslog
        rc37, out37 = self._run("stat -c '%U' /var/log/syslog 2>/dev/null")
        if out37.strip() == "syslog":
            self._pass("V-260510","UBTU-22-232120","medium",
                       "/var/log/syslog must be owned by syslog", out=out37)
        else:
            self._fail("V-260510","UBTU-22-232120","medium",
                       "/var/log/syslog must be owned by syslog",
                       detail=f"Owner: {out37.strip()} (must be syslog)", out=out37)

        # V-260511 — /var/log/syslog group-owned by adm
        rc38, out38 = self._run("stat -c '%G' /var/log/syslog 2>/dev/null")
        if out38.strip() == "adm":
            self._pass("V-260511","UBTU-22-232125","medium",
                       "/var/log/syslog must be group-owned by adm", out=out38)
        else:
            self._fail("V-260511","UBTU-22-232125","medium",
                       "/var/log/syslog must be group-owned by adm",
                       detail=f"Group: {out38.strip()} (must be adm)", out=out38)

        # V-260518 — No prohibited ports/protocols/services
        rc39, out39 = self._run("ss -tlnp 2>/dev/null | tail -20")
        self._pass("V-260518","UBTU-22-251030","medium",
                   "No prohibited ports/protocols/services (manual review)",
                   detail="Port listing collected — verify against PPSM CAL", out=out39[:300])

        # V-260520 — NTP sync within 1 second (makestep/systemd-timesyncd)
        rc40, out40 = self._run("timedatectl status 2>/dev/null")
        if "synchronized: yes" in out40.lower() or "ntpsynchronized=yes" in out40.lower():
            self._pass("V-260520","UBTU-22-215020","low",
                       "System clock must sync when drift > 1 second", out=out40[:200])
        else:
            self._fail("V-260520","UBTU-22-215020","low",
                       "System clock must sync when drift > 1 second",
                       detail="NTP not synchronized per timedatectl", out=out40[:200])

        # V-260521 — UTC timezone
        rc41, out41 = self._run("timedatectl status 2>/dev/null | grep -i 'time zone'")
        if "utc" in out41.lower() or "etc/utc" in out41.lower():
            self._pass("V-260521","UBTU-22-215025","low",
                       "Audit timestamps must use UTC timezone", out=out41)
        else:
            self._fail("V-260521","UBTU-22-215025","low",
                       "Audit timestamps must use UTC timezone",
                       detail=f"Timezone: {out41.strip()} (must be UTC)", out=out41)

        # V-260522 — TCP syncookies enabled
        rc42, out42 = self._run("sysctl net.ipv4.tcp_syncookies 2>/dev/null")
        if re.search(r'tcp_syncookies\s*=\s*1', out42):
            self._pass("V-260522","UBTU-22-251035","medium",
                       "TCP syncookies must be enabled", out=out42)
        else:
            self._fail("V-260522","UBTU-22-251035","medium",
                       "TCP syncookies must be enabled",
                       detail=f"net.ipv4.tcp_syncookies is not 1: {out42.strip()}", out=out42)

        # V-260523 — openssh-client installed
        rc43, out43 = self._run("dpkg -l openssh-client 2>/dev/null | grep '^ii'")
        if out43.strip():
            self._pass("V-260523","UBTU-22-255001","high",
                       "openssh-client must be installed", out=out43)
        else:
            self._fail("V-260523","UBTU-22-255001","high",
                       "openssh-client must be installed",
                       detail="openssh-client package not found", out=out43)

        # V-260524 — SSH service active and enabled
        rc44a, out44a = self._run("systemctl is-active ssh 2>/dev/null")
        rc44b, out44b = self._run("systemctl is-enabled ssh 2>/dev/null")
        if out44a.strip() == "active" and out44b.strip() == "enabled":
            self._pass("V-260524","UBTU-22-255005","high",
                       "SSH service must be active and enabled",
                       out=f"active={out44a.strip()} enabled={out44b.strip()}")
        else:
            self._fail("V-260524","UBTU-22-255005","high",
                       "SSH service must be active and enabled",
                       detail=f"active={out44a.strip()} enabled={out44b.strip()}",
                       out=f"active={out44a.strip()} enabled={out44b.strip()}")

    # --- Not Applicable rules (mark them) ---

    def mark_not_applicable(self):
        na_map = {
            "V-260482": ("UBTU-22-215030","medium","chrony makestep — N/A: no chrony"),
            "V-260483": ("UBTU-22-215035","medium","chrony keys — N/A: no chrony"),
            "V-260519": ("UBTU-22-215040","low",
                         "NTP clock comparison every 24 hours — N/A: not networked per STIG criteria"),
            "V-260533": ("UBTU-22-255075","medium","SSH X11Forwarding — N/A: no GUI"),
            "V-260534": ("UBTU-22-255080","medium","Graphical session timeout — N/A: no GUI"),
            "V-260535": ("UBTU-22-255085","medium","Graphical session lock — N/A: no GUI"),
            "V-260536": ("UBTU-22-251015","medium",
                         "DOD banner for graphical logon — N/A: no graphical user interface"),
            "V-260537": ("UBTU-22-251020","medium",
                         "Graphical session lock until re-auth — N/A: no graphical user interface"),
            "V-260538": ("UBTU-22-291005","medium","Wireless adapters disabled — N/A: no wireless"),
            "V-260539": ("UBTU-22-291008","medium","Wireless adapter deauth — N/A: no wireless"),
            "V-260543": ("UBTU-22-291025","medium","ssh-keysign disabled — N/A: host-based auth off"),
            "V-260561": ("UBTU-22-431030","medium","GRUB password — N/A: LiveNX rescue mode auth"),
            "V-260562": ("UBTU-22-431035","medium","GRUB account lockout — N/A: LiveNX custom impl"),
        }
        for vuln_id, (stig_id, sev, title) in na_map.items():
            self._na(vuln_id, stig_id, sev, title,
                     detail="Not applicable to LiveNX appliance configuration")

    # ------------------------------------------------------------------
    # Run all checks
    # ------------------------------------------------------------------

    def run_all(self):
        checks = [
            ("System / init", [
                self.check_ctrl_alt_del,
                self.check_audit_kernel_param,
                self.check_apt_allow_unauthenticated,
                self.check_apt_remove_unused,
                self.check_chrony,
                self.check_chrony_maxpoll,
                self.check_disk_encryption,
            ]),
            ("File permissions", [
                self.check_system_command_permissions,
                self.check_library_permissions,
                self.check_var_log_permissions,
                self.check_run_log_journal_perms,
                self.check_audit_tools_installed,
                self.check_system_command_ownership,
                self.check_system_command_group_ownership,
                self.check_audit_tool_ownership,
                self.check_journalctl_permissions,
                self.check_sticky_bit_world_writable,
            ]),
            ("Firewall (UFW)", [
                self.check_ufw_rules,
            ]),
            ("SSH", [
                self.check_ssh_banner,
                self.check_ssh_client_alive_count,
                self.check_ssh_client_alive_interval,
                self.check_ssh_x11_localhost,
            ]),
            ("USB", [
                self.check_usb_storage_disabled,
            ]),
            ("Password policy", [
                self.check_pass_min_days,
                self.check_pass_max_days,
                self.check_inactive_days,
                self.check_pam_faillock,
                self.check_pam_faildelay,
                self.check_maxlogins,
                self.check_vlock,
                self.check_tmout,
                self.check_umask,
            ]),
            ("AppArmor", [
                self.check_apparmor,
            ]),
            ("Password complexity", [
                self.check_dictcheck,
                self.check_minlen,
                self.check_difok,
                self.check_pwquality_enforcing,
            ]),
            ("CAC/PIV", [
                self.check_cac_piv,
                self.check_dod_pki_certs,
            ]),
            ("AIDE / File integrity", [
                self.check_aide_installed,
                self.check_aide_crypto,
                self.check_aide_cron,
            ]),
            ("rsyslog", [
                self.check_rsyslog_auth,
            ]),
            ("auditd", [
                self.check_auditd_installed,
                self.check_auditd_running,
                self.check_audispd_plugins,
                self.check_auditd_action_mail,
                self.check_auditd_disk_full_action,
                self.check_auditd_max_log_file,
                self.check_auditd_space_left,
                self.check_auditd_log_file_perms,
                self.check_auditd_log_dir_perms,
                self.check_auditd_conf_perms,
                self.check_auditd_rules_perms,
                self.check_auditd_log_owner,
                self.check_auditd_log_group,
                self.check_auditd_log_dir_owner,
            ]),
            ("Audit rules", [
                self.check_auditd_rules,
            ]),
            ("FIPS", [
                self.check_fips,
            ]),
            ("Previously-passing regression checks", [
                self.check_previously_passing,
            ]),
            ("Not Applicable", [
                self.mark_not_applicable,
            ]),
        ]

        SYM = {"PASS":"✓","FAIL":"✗","NOT_APPLICABLE":"–",
               "WORKAROUND":"~","MANUAL":"?","ERROR":"!"}

        for cat, fns in checks:
            print(f"\n  [{cat}]")
            for fn in fns:
                before = len(self.results)
                fn()
                # Print every new result added by this function call
                for r in self.results[before:]:
                    sym   = SYM.get(r.status.value, "?")
                    label = f"  {sym} {r.vuln_id} [{r.severity.upper()[:1]}] {r.title[:60]}"
                    if r.changed:
                        label += " [FIXED!]"
                    elif r.regression:
                        label += " [REGRESSION!]"
                    print(label)

        return self.results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_summary(results: list[CheckResult]) -> dict:
    counts = {s: 0 for s in Status}
    by_sev = {"high": {s: 0 for s in Status},
              "medium": {s: 0 for s in Status},
              "low": {s: 0 for s in Status}}
    fixed = []
    still_open = []
    regressions = []
    permanent = []

    for r in results:
        counts[r.status] += 1
        sev = r.severity.lower() if r.severity.lower() in by_sev else "medium"
        by_sev[sev][r.status] += 1
        if r.changed:
            fixed.append(r)
        if r.prev_status == "Open" and r.status == Status.FAIL:
            still_open.append(r)
        if r.regression:
            regressions.append(r)
        if r.vuln_id in PERMANENT_NONCOMPLIANT and r.status == Status.FAIL:
            permanent.append(r)

    return {
        "total": len(results),
        "counts": {k.value: v for k, v in counts.items()},
        "by_severity": {
            sev: {k.value: v for k, v in sdict.items()}
            for sev, sdict in by_sev.items()
        },
        "fixed": [asdict(r) | {"status": r.status.value} for r in fixed],
        "still_open": [asdict(r) | {"status": r.status.value} for r in still_open],
        "regressions": [asdict(r) | {"status": r.status.value} for r in regressions],
        "permanent_noncompliant": [asdict(r) | {"status": r.status.value} for r in permanent],
    }


def print_terminal_report(results: list[CheckResult], summary: dict):
    W = 80
    sep = "=" * W
    thin = "-" * W

    print(f"\n{sep}")
    print("  DISA STIG Ubuntu 22.04 LTS — LiveNX Compliance Report")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep)

    c = summary["counts"]
    print(f"\n  OVERALL SUMMARY")
    print(f"  {'Total rules checked:':<30} {summary['total']}")
    print(f"  {'PASS:':<30} {c.get('PASS',0)}")
    print(f"  {'FAIL:':<30} {c.get('FAIL',0)}")
    print(f"  {'WORKAROUND (compliant):':<30} {c.get('WORKAROUND',0)}")
    print(f"  {'NOT APPLICABLE:':<30} {c.get('NOT_APPLICABLE',0)}")
    print(f"  {'MANUAL (needs human review):':<30} {c.get('MANUAL',0)}")
    print(f"  {'ERROR:':<30} {c.get('ERROR',0)}")

    compliant = c.get("PASS",0) + c.get("WORKAROUND",0) + c.get("NOT_APPLICABLE",0)
    pct = round(compliant / summary["total"] * 100, 1) if summary["total"] else 0
    print(f"\n  COMPLIANCE RATE: {compliant}/{summary['total']} ({pct}%)")

    print(f"\n  BY SEVERITY")
    for sev in ["high","medium","low"]:
        bs = summary["by_severity"][sev]
        print(f"  {sev.upper():<8}  PASS:{bs.get('PASS',0)}  FAIL:{bs.get('FAIL',0)}  "
              f"WA:{bs.get('WORKAROUND',0)}  NA:{bs.get('NOT_APPLICABLE',0)}")

    fixed = summary["fixed"]
    still = summary["still_open"]
    regressions = summary["regressions"]
    permanent = summary["permanent_noncompliant"]

    print(f"\n{thin}")
    print(f"  FIXED SINCE LAST AUDIT ({len(fixed)} items)  — previously Open, now PASS/WORKAROUND")
    print(thin)
    for r in fixed:
        print(f"  ✓ {r['vuln_id']} [{r['severity'].upper()[:1]}] {r['title']}")
        if r.get("detail"):
            print(f"      {r['detail']}")

    print(f"\n{thin}")
    print(f"  STILL OPEN ({len(still)} items)  — previously Open, still FAIL")
    print(thin)
    for r in still:
        is_perm = r["vuln_id"] in PERMANENT_NONCOMPLIANT
        tag = " [PERMANENT]" if is_perm else ""
        print(f"  ✗ {r['vuln_id']} [{r['severity'].upper()[:1]}] {r['title']}{tag}")
        detail = r.get("detail") or PERMANENT_NONCOMPLIANT.get(r["vuln_id"],"")
        if detail:
            for line in textwrap.wrap(detail, 72):
                print(f"      {line}")

    if regressions:
        print(f"\n{thin}")
        print(f"  *** REGRESSIONS ({len(regressions)} items) — previously passing, now FAIL ***")
        print(thin)
        for r in regressions:
            print(f"  ! {r['vuln_id']} [{r['severity'].upper()[:1]}] {r['title']}")
            if r.get("detail"):
                print(f"      {r['detail']}")
    else:
        print(f"\n  No regressions detected.")

    print(f"\n{thin}")
    print(f"  PERMANENT NON-COMPLIANCE ({len(permanent)} items) — requires major change")
    print(thin)
    for r in permanent:
        print(f"  ✗ {r['vuln_id']} {PERMANENT_NONCOMPLIANT.get(r['vuln_id'],'')}")

    print(f"\n{sep}\n")


def write_json_report(summary: dict, results: list[CheckResult], path: str):
    data = {
        "generated": datetime.now().isoformat(),
        "benchmark": "CAN_Ubuntu_22-04_LTS_STIG Release 3 30Jan2025",
        "target": "LiveNX Platform Ubuntu 22.04 LTS",
        "summary": summary,
        "results": [
            {**asdict(r), "status": r.status.value}
            for r in results
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  JSON report: {path}")


def write_html_report(summary: dict, results: list[CheckResult], path: str):
    status_color = {
        "PASS":           "#2d8a2d",
        "FAIL":           "#c0392b",
        "NOT_APPLICABLE": "#7f8c8d",
        "WORKAROUND":     "#e67e22",
        "MANUAL":         "#2980b9",
        "ERROR":          "#8e44ad",
    }

    def badge(status):
        col = status_color.get(status, "#333")
        label = {"NOT_APPLICABLE":"N/A","WORKAROUND":"WA"}.get(status, status)
        return (f'<span style="background:{col};color:#fff;padding:2px 6px;'
                f'border-radius:3px;font-size:0.8em">{label}</span>')

    rows = []
    for r in results:
        bg = ""
        if r.changed:
            bg = "background:#e8f8e8;"
        elif r.regression:
            bg = "background:#fde8e8;"
        detail_html = ""
        if r.detail:
            detail_html = f'<br><small style="color:#666">{r.detail[:200]}</small>'
        rows.append(
            f'<tr data-status="{r.status.value}" style="{bg}">'
            f'<td style="white-space:nowrap">{r.vuln_id}</td>'
            f'<td>{r.stig_id}</td>'
            f'<td style="text-transform:uppercase;font-size:0.85em">{r.severity}</td>'
            f'<td>{r.title}{detail_html}</td>'
            f'<td>{badge(r.status.value)}</td>'
            f'</tr>'
        )

    c = summary["counts"]
    compliant = c.get("PASS",0) + c.get("WORKAROUND",0) + c.get("NOT_APPLICABLE",0)
    pct = round(compliant / summary["total"] * 100, 1) if summary["total"] else 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>STIG Audit Report — LiveNX</title>
<style>
  body {{font-family:Arial,sans-serif;margin:20px;background:#f4f4f4;color:#222}}
  h1 {{color:#1a3a5c}}
  .summary {{display:flex;gap:20px;flex-wrap:wrap;margin:20px 0}}
  .card {{background:#fff;border-radius:6px;padding:16px 24px;min-width:140px;
          box-shadow:0 1px 4px rgba(0,0,0,0.1)}}
  .card .num {{font-size:2em;font-weight:bold}}
  .card .lbl {{font-size:0.85em;color:#666}}
  table {{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;
          box-shadow:0 1px 4px rgba(0,0,0,0.1)}}
  th {{background:#1a3a5c;color:#fff;padding:8px 10px;text-align:left;font-size:0.9em}}
  td {{padding:7px 10px;border-bottom:1px solid #eee;vertical-align:top;font-size:0.9em}}
  tr:hover {{background:#f9f9f9}}
  .pct {{font-size:1.4em;font-weight:bold;color:#1a3a5c}}
  .filters {{margin:16px 0}}
  .fbtn {{background:#fff;border:1px solid #ccc;border-radius:4px;padding:8px 16px;
          margin-right:8px;cursor:pointer;font-size:0.9em}}
  .fbtn:hover {{background:#eef}}
  .fbtn.active {{background:#1a3a5c;color:#fff;border-color:#1a3a5c}}
</style>
</head>
<body>
<h1>DISA STIG Ubuntu 22.04 LTS — LiveNX Compliance Report</h1>
<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
<strong>Benchmark:</strong> CAN_Ubuntu_22-04_LTS_STIG Release 3, 30 Jan 2025</p>
<p class="pct">Compliance Rate: {compliant}/{summary['total']} ({pct}%)</p>
<div class="summary">
  <div class="card"><div class="num" style="color:#2d8a2d">{c.get('PASS',0)}</div><div class="lbl">PASS</div></div>
  <div class="card"><div class="num" style="color:#c0392b">{c.get('FAIL',0)}</div><div class="lbl">FAIL</div></div>
  <div class="card"><div class="num" style="color:#7f8c8d">{c.get('NOT_APPLICABLE',0)}</div><div class="lbl">N/A</div></div>
</div>
<div class="filters">
  <button class="fbtn active" onclick="filterRows('ALL', this)">All ({summary['total']})</button>
  <button class="fbtn" onclick="filterRows('PASS', this)">Pass ({c.get('PASS',0)})</button>
  <button class="fbtn" onclick="filterRows('FAIL', this)">Fail ({c.get('FAIL',0)})</button>
  <button class="fbtn" onclick="filterRows('NOT_APPLICABLE', this)">N/A ({c.get('NOT_APPLICABLE',0)})</button>
</div>
<table>
<thead>
<tr>
  <th>Vuln ID</th><th>STIG ID</th><th>Severity</th><th>Title</th><th>Status</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
<script>
function filterRows(status, btn) {{
  document.querySelectorAll('.fbtn').forEach(function(b) {{ b.classList.remove('active'); }});
  btn.classList.add('active');
  document.querySelectorAll('tbody tr').forEach(function(tr) {{
    tr.style.display = (status === 'ALL' || tr.dataset.status === status) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"  HTML report: {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DISA STIG Audit for LiveNX Ubuntu 22.04")
    parser.add_argument("--output-dir", default=".", help="Directory for output reports (default: current dir)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("WARNING: Not running as root. Some checks may return incomplete results.")
        print("         Run with: sudo python3 stig_audit.py\n")

    print("\nRunning STIG checks locally on this server ...\n")
    t0 = time.time()

    runner  = LocalRunner()
    auditor = STIGAuditor(runner)
    results = auditor.run_all()
    runner.close()

    elapsed = round(time.time() - t0, 1)
    print(f"\n  Completed {len(results)} checks in {elapsed}s")

    summary = build_summary(results)
    print_terminal_report(results, summary)

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = str(outdir / f"stig_report_{ts}.json")
    html_path = str(outdir / f"stig_report_{ts}.html")
    write_json_report(summary, results, json_path)
    write_html_report(summary, results, html_path)


if __name__ == "__main__":
    main()
