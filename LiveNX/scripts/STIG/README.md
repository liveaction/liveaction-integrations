# DISA STIG Compliance — LiveNX Platform (Ubuntu 22.04 LTS)

Audit and tiered remediation tooling to bring the **LiveNX** appliance into
compliance with the DISA Ubuntu 22.04 LTS Security Technical Implementation
Guide (STIG).

- **Benchmark:** `CAN_Ubuntu_22-04_LTS_STIG`, Release 3, Benchmark Date 30 Jan 2025
- **Scope:** Vuln IDs **V-260469 – V-260650** (~180 rules)
- **Target host:** LiveNX appliance running Ubuntu 22.04 LTS

> ⚠️ **All scripts run *locally on the LiveNX server* as root.** They are not
> run from a workstation — the appliance cannot be reached over SSH from outside
> its network. Copy the scripts onto the box (e.g. into `/home/admin/`) and run
> them there.

---

## Important: LiveNX is a live-boot (read-only rootfs) appliance

The LiveNX appliance boots from a **read-only squashfs image**. Only `/etc`,
`/home`, and `/var` are on persistent writable storage — **everything else
reverts to the image on every reboot.**

Consequences that affect these scripts:

- Permission/ownership fixes applied to paths **outside `/etc`, `/home`, `/var`**
  do **not** persist across reboot. The remediation scripts re-apply them on each
  boot using `systemd-tmpfiles` entries written to `/etc/tmpfiles.d/` (which
  *does* persist).
- There is **no GRUB** on the running system (no `/etc/default/grub`,
  no `/boot/grub/`). Kernel command-line rules **V-260471** (`audit=1`) and
  **V-260472** (`audit_backlog_limit=8192`) **cannot be fixed at runtime** — they
  must be baked into the live-build boot append by engineering ("fix in release").
- A LiveNX version upgrade may reset permissions. **After any upgrade, re-run the
  audit and, if needed, re-run the remediation scripts.**

---

## The four scripts

| # | Script | Type | Purpose | Reboot |
|---|--------|------|---------|--------|
| 1 | `stig_audit.py` | Python 3 | Audit / scan — checks ~180 rules, writes JSON + HTML reports | No |
| 2 | `stig_stage1_low_risk.sh` | Bash | Remediate **low / no-risk** rules (64) | No |
| 3 | `stig_stage2_medium_risk.sh` | Bash | Remediate **medium-risk** rules (15) | No |
| 4 | `stig_stage3_high_risk.sh` | Bash | Remediate **high-risk** rules (9) | **Yes** |

Run them in order: **audit → stage 1 → stage 2 → stage 3 → audit again.**

### 1. `stig_audit.py` — compliance audit / scanner

Self-contained Python script (standard library only — no pip installs). It runs
all STIG checks locally, prints a colored terminal summary, and writes both a
**JSON** and an **HTML** report. Each rule is tagged `PASS`, `FAIL`,
`NOT_APPLICABLE`, `WORKAROUND`, `MANUAL`, or `ERROR`, and the report overlays a
delta against the previous manual audit (showing newly **FIXED** and newly
**REGRESSED** rules).

Use it to establish a baseline, to verify progress between remediation stages,
and to re-validate after a reboot or LiveNX upgrade.

### 2. `stig_stage1_low_risk.sh` — low / no-risk remediation

Safe to run on a live production server. Covers audit logging, monitoring
configuration, auditd setup (creates `/var/log/audit`, fixes AIDE config, clears
failed systemd state), package removal, and audit rules. No service impact
expected; no reboot required.

### 3. `stig_stage2_medium_risk.sh` — medium-risk remediation

Covers SSH hardening, APT policy, `/var/log` permissions, and password-expiry
settings. **The SSH config is validated before sshd is reloaded in place** (no
reboot), but a misconfiguration could still disrupt remote access — keep a second
SSH session open while running. Run only after Stage 1 has been run and verified.

### 4. `stig_stage3_high_risk.sh` — high-risk remediation

Covers GRUB kernel parameters, `UMASK`, and system binary/library
permissions/ownership. **High risk** because bad changes here can prevent boot or
break LiveNX services. Writes `tmpfiles.d` entries so permission fixes re-apply on
each boot. **Requires a reboot** for the audit kernel parameters to take effect.

> 🛑 **Take a VM snapshot before running Stage 3.** The script prompts you to
> confirm a snapshot was taken before it proceeds.

---

## How to run

Copy the scripts onto the LiveNX server first, then run each as root.

### Audit

```bash
# Run from the directory you want the reports written into, or pass --output-dir
sudo python3 stig_audit.py

# Write reports to a specific directory
sudo python3 stig_audit.py --output-dir /home/admin/reports
```

Outputs (timestamped) in the chosen directory:

- `stig_report_YYYYMMDD_HHMMSS.json`
- `stig_report_YYYYMMDD_HHMMSS.html`

> Note: `stig_audit.py` always writes **both** JSON and HTML. Its only flag is
> `--output-dir` (default: current directory).

### Remediation (run in order, each piped to a log)

```bash
# Stage 1 — low / no risk (no reboot)
sudo bash stig_stage1_low_risk.sh 2>&1 | tee /home/admin/stig_stage1.log

# Re-audit to confirm, then:
# Stage 2 — medium risk (no reboot; keep a second SSH session open)
sudo bash stig_stage2_medium_risk.sh 2>&1 | tee /home/admin/stig_stage2.log

# Re-audit to confirm, then:
# Stage 3 — high risk (TAKE A VM SNAPSHOT FIRST; requires reboot)
sudo bash stig_stage3_high_risk.sh 2>&1 | tee /home/admin/stig_stage3.log
sudo reboot

# After reboot, re-audit one final time
sudo python3 stig_audit.py --output-dir /home/admin/reports
```

The remediation scripts back up every file they modify to `<file>.stig_bak`
(created once, on first run) before changing it.

---

## Permissions & ownership requirements

| Requirement | Detail |
|-------------|--------|
| **User** | Run everything as **root** (use `sudo`). The audit script warns and gives incomplete results if not root; the remediation scripts **exit immediately** with an error if `EUID != 0`. |
| **Interpreters** | `python3` (Python 3.x, standard library only) for the audit; `bash` for the remediation scripts. |
| **Script file permissions** | The scripts are invoked explicitly via `python3 …` / `bash …`, so they do **not** need the execute bit. If you prefer to run them directly (`./stig_stageN.sh`), make them executable: `chmod +x stig_stage*.sh stig_audit.py`. |
| **Writable locations** | Reports are written to `--output-dir` (default: current dir). Logs default to `/home/admin/stig_stageN.log`. Backups (`*.stig_bak`) are written next to each modified file. The account/path must be writable by root (it is). |
| **Persistence** | Remediation scripts write to `/etc/tmpfiles.d/` so fixes outside `/etc`, `/home`, `/var` survive reboot. These paths require root to write. |
| **Filesystem note** | Because the rootfs is read-only squashfs, some targets live on the read-only image; the scripts apply the change at runtime and register a `tmpfiles.d` rule to re-apply it each boot. |

---

## Recommended run order

1. `sudo python3 stig_audit.py` — baseline.
2. `sudo bash stig_stage1_low_risk.sh` — low risk.
3. Re-audit, confirm Stage 1 fixes landed.
4. `sudo bash stig_stage2_medium_risk.sh` — medium risk (second SSH session open).
5. Re-audit, confirm; verify SSH and the LiveNX web UI/API still work.
6. **Snapshot the VM.**
7. `sudo bash stig_stage3_high_risk.sh` — high risk.
8. `sudo reboot`.
9. Re-audit to confirm final state.

---

## Repository contents

**Scripts**
- `stig_audit.py` — audit / scanner (the four scripts, #1)
- `stig_stage1_low_risk.sh` — Stage 1 remediation (#2)
- `stig_stage2_medium_risk.sh` — Stage 2 remediation (#3)
- `stig_stage3_high_risk.sh` — Stage 3 remediation (#4)







