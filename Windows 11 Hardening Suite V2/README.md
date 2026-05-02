# Windows 11 Security Hardening Suite v1.0

**CIS Benchmark L1 + Microsoft Security Baseline (November 2023)**

A complete, integrated security hardening toolkit for Windows 11 workstations, featuring automated controls, interactive reporting, and full technical documentation.

---

## 📦 Package Contents

```
Windows11-Hardening-Suite/
├── START_HARDENING_SUITE.bat              [Main launcher — run this first!]
├── Harden-Windows11.ps1                   [PowerShell hardening script]
├── Win11-Hardening-Report-Dashboard.html  [Interactive report viewer]
├── Windows11_Hardening_Documentation.docx [Technical reference]
└── README.md                              [This file]
```

---

## 🚀 Quick Start

### Step 1: Extract the Suite
1. Download the entire `Windows11-Hardening-Suite` folder to your desktop or a shared location.
2. Ensure all 4 files above are in the same directory.

### Step 2: Launch the Main Menu
1. **Right-click** `START_HARDENING_SUITE.bat`
2. Select **"Run as Administrator"**
3. Wait for the menu to appear

### Step 3: Choose Your Action
The menu offers:
- **[1] Run Hardening Script** — Apply controls to this PC
- **[2] View Report Dashboard** — Visualize results from previous runs
- **[3] View Documentation** — Technical details and control reference
- **[4] Open PowerShell ISE** — Edit the script before running
- **[5] Exit** — Close the suite

---

## 📋 Prerequisites

✅ **Operating System**
- Windows 11 Pro, Enterprise, or Education
- Build 22H2 or 23H2

✅ **Permissions**
- Local Administrator or Domain Admin rights
- Can be run via SCCM, Intune, or directly

✅ **Hardware** (for full feature set)
- TPM 2.0 chip (for BitLocker and Credential Guard)
- UEFI with Secure Boot enabled

✅ **Software**
- PowerShell 5.1 or later (built-in)
- Microsoft Defender antivirus (not third-party AV)
- Microsoft Word (optional, for documentation)

---

## 🔒 What Gets Hardened

The script applies **300+ security controls** across 12 sections:

| Section | Controls | Reference |
|---------|----------|-----------|
| **1. Account Policies** | Password complexity, lockout, Guest/Admin rename | CIS 1.x, 2.3.1.x |
| **2. Windows Defender** | Real-time protection, 15 ASR rules, MAPS, PUA, Network Protection | CIS 18.9.47.x |
| **3. Firewall** | Block-inbound on all profiles, logging, NetBIOS off | CIS 9.x |
| **4. Audit Policy** | 20 subcategories, command-line logging | CIS 17.x |
| **5. User Rights** | Debug disabled, network access restricted, Guest denied | CIS 2.2.x |
| **6. Registry Security** | LSA PPL, NTLMv2, SMB signing, UAC, WinRM, DoH, telemetry off | CIS 2.3.x, 18.x |
| **7. Services** | 23 unnecessary services disabled | CIS 5.x |
| **8. Windows Update** | Defer features 180 days, immediate security patches | CIS 18.9.101.x |
| **9. PowerShell** | Script block logging, transcription, module logging | CIS 18.9.97.x |
| **10. BitLocker** | TPM detection and status check | MS Baseline |
| **11. OS Hardening** | SEHOP, Safe DLL search, LLMNR off, HVCI | MS Baseline |
| **12. Reporting** | Timestamped logs and CSV export for dashboard | Internal |

**Estimated runtime:** 5–10 minutes per machine

---

## ⚠️ Important Warnings

### Before You Run

🔴 **TEST IN NON-PRODUCTION FIRST**
- Deploy to 5–10 pilot machines before rolling out organization-wide.
- Test in a staging environment if this is for a large rollout.

🔴 **DOMAIN-JOINED MACHINES**
- Group Policy Objects (GPOs) will override local policy settings.
- Review your existing GPO configuration against the hardening controls.
- Disabled services may be re-enabled by GPO — coordinate with your network admin.

🔴 **THIRD-PARTY ANTIVIRUS**
- Attack Surface Reduction (ASR) rules only work with Microsoft Defender.
- If you use Norton, McAfee, Kaspersky, etc., disable them before running.

🔴 **LEGACY APPLICATIONS**
- Some settings (NTLMv2 only, SMB signing, UAC) may break old or custom LOB apps.
- Document any exceptions in your Risk Register.

🔴 **RESTART REQUIRED**
- After running, you **must restart** the machine to activate all settings.
- LSA Protection, SEHOP, and Credential Guard require a reboot.

---

## 🎯 Running the Hardening Script

### Scenario 1: Standalone PC (Home / Small Office)

```
1. Run START_HARDENING_SUITE.bat as Administrator
2. Select [1] Run Hardening Script
3. Review the warnings and confirm (Y)
4. Wait 5–10 minutes
5. Restart the PC
```

**Log locations:**
- Text log: `C:\HardeningLog_YYYYMMDD_HHMMSS.txt`
- CSV results: `C:\HardeningLog_YYYYMMDD_HHMMSS.csv`

### Scenario 2: Microsoft Intune (Cloud-Managed)

1. In **Intune Admin Center**, go to **Devices > Scripts and Remediation > Platform Scripts**
2. Click **Create script**
3. Upload `Harden-Windows11.ps1`
4. Set:
   - Run this script using the logged on credentials: **No** (runs as SYSTEM)
   - Run script in 64-bit PowerShell: **Yes**
5. Assign to a device group
6. Monitor via **Scripts > Monitor > Script status**

⚠️ *Intune scripts run as SYSTEM. Ensure SYSTEM has local admin rights via device compliance policy.*

### Scenario 3: SCCM / Configuration Manager

1. Go to **Software Library > Scripts**
2. Create new script, paste contents of `Harden-Windows11.ps1`
3. Approve with secondary admin (if required)
4. Deploy as **Run Script** from a device collection
5. Select **Run as Administrator**
6. Monitor in **Run Scripts** status node

### Scenario 4: Group Policy / Domain Push

If your IT uses domain-based management:
1. Copy the script to a shared network location: `\\corp-deploy\scripts\`
2. Create a Group Policy logon script or scheduled task
3. Deploy via GPO to your target OU
4. Validate no conflicts with existing domain policy

---

## 📊 Viewing the Report Dashboard

After the hardening script runs:

### Step 1: Locate Your CSV
```
C:\HardeningLog_20260502_143015.csv
```

### Step 2: Open the Dashboard
1. Run the launcher: `START_HARDENING_SUITE.bat`
2. Select **[2] View Report Dashboard**
3. Or manually open: `Win11-Hardening-Report-Dashboard.html` in your browser

### Step 3: Upload Your CSV
- **Drag and drop** the CSV onto the upload zone, or
- Click **Upload CSV** and browse to the file, or
- Click **Demo data** to see a sample report

### Dashboard Features

**Summary Stats**
- Total controls processed
- Applied / Active count (% compliant)
- Warnings (manual review needed)
- Failed (remediation required)

**Donut Chart**
- Visual pass/warn/fail breakdown
- Hover for counts

**Bar Chart by Section**
- Stacked results for each hardening section
- Identify which areas need attention

**Filterable Control Table**
- Search by control name or registry key
- Filter by section or status
- Shows applied status and detail

**Example:** Filter by "Warnings" to see controls flagged for manual action (e.g., BitLocker not active, service not found).

---

## ✅ Post-Hardening Verification

### Essential Steps (after restart)

1. **Verify LSA Protection**
   ```powershell
   (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RunAsPPL
   # Expected: 1
   ```

2. **Check NTLM Level**
   ```powershell
   (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).LmCompatibilityLevel
   # Expected: 5
   ```

3. **Confirm SMBv1 Disabled**
   ```powershell
   Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select State
   # Expected: Disabled
   ```

4. **Verify ASR Rules Active**
   ```powershell
   (Get-MpPreference).AttackSurfaceReductionRules_Ids | Measure-Object
   # Expected: 15 rules
   ```

5. **Check Firewall Status**
   ```powershell
   Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction
   # Expected: Enabled=True, DefaultInboundAction=Block (all 3 profiles)
   ```

6. **Enable BitLocker** (if TPM detected)
   ```powershell
   manage-bde -on C: -SkipHardwareTest
   # Save recovery key to Active Directory, Azure, or secure vault
   ```

7. **Check Credential Guard**
   ```
   msinfo32.exe > System Summary
   Look for "Virtualization-based security: Running"
   ```

8. **Verify Secure Boot**
   ```
   msinfo32.exe > System Summary
   Look for "Secure Boot State: On"
   ```

---

## 🛠️ Troubleshooting

### Issue: "Administrator privileges required"
**Solution:** Right-click the batch file → Run as Administrator

### Issue: PowerShell script blocked by execution policy
**Solution:** The launcher handles this. If running manually:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Harden-Windows11.ps1
```

### Issue: BitLocker warning after hardening
**Solution:** BitLocker requires manual activation:
```powershell
manage-bde -on C: -SkipHardwareTest
manage-bde -protectors -adbackup C:  # Back up key to AD
```

### Issue: Service not found in log
**Solution:** Some services (Fax, IIS) don't exist on all systems. This is expected.

### Issue: RDP or WinRM disabled after hardening
**Solution:** These are disabled by default for security. Re-enable if needed:
```powershell
# Enable RDP (allow only admins)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
  -Name 'fDenyTSConnections' -Value 0

# Enable WinRM (Kerberos only, no basic auth)
Enable-PSRemoting -Force
```

### Issue: Domain-joined machine ignores some settings
**Solution:** This is expected — domain GPO takes precedence. Compare your GPO against the hardening controls. Update your GPO if stricter settings are needed.

---

## 📖 Documentation

All technical details are in:
```
Windows11_Hardening_Documentation.docx
```

Sections:
1. **Overview** — Purpose, benchmark alignment, prerequisites
2. **Architecture** — 12-section breakdown, helper functions
3. **Detailed Controls** — Full reference tables for every control
4. **Deployment** — Standalone, Intune, SCCM, GPO guidance
5. **Post-Hardening** — 9-step manual action checklist
6. **Exceptions** — Known deviations and risk acceptances
7. **Change Log** — Version history
8. **References** — CIS, MS, NIST, OWASP sources

Open in Word:
```
START_HARDENING_SUITE.bat → [3] View Documentation
```

---

## 🔄 Deployment at Scale

### For IT Teams / MSPs

1. **Pilot Phase (Week 1–2)**
   - Deploy to 5–10 diverse test machines
   - Document any app/GPO conflicts
   - Collect feedback

2. **Staging Phase (Week 3–4)**
   - Deploy to 20–50% of fleet
   - Monitor logs and user reports
   - Refine exception list

3. **Production Phase (Week 5+)**
   - Full rollout via Intune/SCCM
   - Monitor dashboard results
   - Schedule restarts during maintenance windows

### Recommended Intune Configuration

**Device Compliance Policy:**
- Firewall enabled: Yes
- Antivirus enabled: Yes
- Real-time protection: Yes
- System protection: Yes

**Scripts & Remediation:**
- Run the PS script weekly or on-demand
- Generate reports for audit trail

**Endpoint Analytics:**
- Monitor ASR rule block events
- Track BitLocker encryption progress
- Alert on script failures

---

## 📝 Support & Feedback

### Issues?
1. **Check the log:** `C:\HardeningLog_*.txt`
2. **Review documentation:** `Windows11_Hardening_Documentation.docx`
3. **Verify prerequisites:** Is Defender enabled? TPM detected? Admin rights?

### Questions?
- Refer to **Section 4–6 of the documentation** for detailed control reference
- CIS Benchmark: https://www.cisecurity.org/benchmark/microsoft_windows_desktop
- Microsoft Security Baseline: https://www.microsoft.com/en-us/download/details.aspx?id=55319

### Feedback / Contributions
This suite is maintained by **Digital Services & Information Security (LLSG)**.
For updates, customization, or issues, contact your IT governance team.

---

## 📜 Compliance & Governance

### Alignment
- ✅ **CIS Microsoft Windows 11 Benchmark v3.0** — Level 1 (Corporate)
- ✅ **Microsoft Windows 11 Security Baseline** — November 2023
- ✅ **ISO/IEC 27001:2013** — Control A.12.6.1 (Management of Technical Vulnerabilities)
- ✅ **NIST SP 800-171** — Informative reference (recommended, not required)

### Documentation for Audits
- Keep the CSV reports: `C:\HardeningLog_*.csv`
- Archive logs for compliance periods (typically 1–3 years)
- Reference this README and the technical documentation in your audit trail

---

## 🔐 Security Warnings

This script is designed for **authorized IT personnel only**. Misuse could cause denial of service, data loss, or security breaches. Always:

- ✅ Run on authorized systems only
- ✅ Test before production deployment
- ✅ Document exceptions in your Risk Register
- ✅ Keep audit logs of all runs
- ✅ Verify no conflicts with existing security policy

---

## 📅 Version & Updates

**Current Version:** 1.0
**Release Date:** May 2026
**Last Reviewed:** May 2026
**Next Review Due:** May 2027 or upon CIS/MS baseline update

To check for updates:
1. Contact your IT governance team
2. Visit the CIS website for new benchmark versions
3. Check Microsoft for new security baseline releases

---

## 📞 Quick Reference

| Action | Command |
|--------|---------|
| **Launch suite** | Run `START_HARDENING_SUITE.bat` as Administrator |
| **Run script only** | `powershell -NoProfile -ExecutionPolicy Bypass -File Harden-Windows11.ps1` |
| **View logs** | Open `C:\HardeningLog_*.txt` in Notepad |
| **View results CSV** | Open `C:\HardeningLog_*.csv` in Excel or the dashboard |
| **Edit script** | Right-click → Edit, or use PowerShell ISE |
| **Reset a setting** | Registry: use `regedit`, Service: use `services.msc`, Policy: use `gpedit.msc` |

---

**Ready to harden? Run `START_HARDENING_SUITE.bat` as Administrator and select option [1].**

Good luck! 🚀
