# The rule catalogue. Each entry says which event ids matter, which payload
# fields make it interesting, and which ATT&CK technique the behaviour maps to.
# Command line patterns are grouped here so the process and PowerShell rules can
# share them.

from .rules import Rule, SEVERITY_ORDER, matches_any, regex_any

# command line fragments that are worth a finding on their own, paired with the
# severity the pattern deserves
COMMAND_PATTERNS = (
    (r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}", "base64 encoded command line", "high"),
    (r"downloadstring|downloadfile|invoke-webrequest|bitsadmin\s+/transfer|certutil\s+-urlcache", "remote payload download", "high"),
    (r"invoke-mimikatz|sekurlsa|lsadump|kerberos::golden|dcsync", "credential dumping tooling", "critical"),
    (r"vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog", "shadow copy deletion", "critical"),
    (r"ntdsutil|csvde|esentutl\s+\S*ntds", "ntds database extraction", "critical"),
    (r"comsvcs\.dll.*minidump|procdump\S*\s+.*lsass|rundll32\S*\s+.*lsass", "process memory dump", "critical"),
    (r"reg\s+add\s+\S*\\run|new-itemproperty\s+\S*\\run", "run key persistence", "high"),
    (r"schtasks\s+/create|register-scheduledtask", "scheduled task creation", "high"),
    (r"sc(\.exe)?\s+(create|config)\s|new-service\s", "service creation or reconfiguration", "high"),
    (r"net\s+(localgroup\s+administrators|group\s+\S+\s+/add)|add-adgroupmember", "privileged group change", "high"),
    (r"net\s+user\s+\S+\s+/add|new-localuser", "local account creation", "high"),
    (r"netsh\s+advfirewall\s+set\s+\S+\s+state\s+off|set-mppreference|disable-windowsoptionalfeature", "defence evasion", "high"),
    (r"wevtutil\s+cl|clear-eventlog|remove-eventlog", "event log clearing attempt", "critical"),
    (r"wmic\s+process\s+call\s+create|invoke-wmimethod|win32_process", "remote process creation", "high"),
    (r"psexec|paexec|winexe|smbexec|atexec", "remote execution tooling", "high"),
    (r"mimikatz|rubeus|sharphound|bloodhound|seatbelt|sharpup", "attacker tooling by name", "critical"),
    (r"whoami|net\s+(user|group|share)\b|systeminfo|ipconfig\s+/all|query\s+user|nltest", "discovery command", "medium"),
    (r"takeown|icacls\s+\S+\s+/grant|attrib\s+-s\s+-h", "permission manipulation", "medium"),
)

# channel names, short forms are matched too so a rule does not depend on the
# exact provider path a given windows build writes
SYSTEM_CHANNEL = ("System",)
SECURITY_CHANNEL = ("Security",)
POWERSHELL_CHANNEL = ("Microsoft-Windows-PowerShell/Operational", "PowerShell")
DEFENDER_CHANNEL = ("Microsoft-Windows-Windows Defender/Operational", "Windows Defender")
TASKS_CHANNEL = ("Microsoft-Windows-TaskScheduler/Operational", "TaskScheduler")
BITS_CHANNEL = ("Microsoft-Windows-Bits-Client/Operational", "Bits-Client")
WMI_CHANNEL = ("Microsoft-Windows-WMI-Activity/Operational", "WMI-Activity")
TERMINAL_CHANNEL = ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "LocalSessionManager")

# logon types windows records, used to tell an interactive logon from a service one
LOGON_TYPES = {
    "0": "system",
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network cleartext",
    "9": "new credentials",
    "10": "remote interactive",
    "11": "cached interactive",
}

PRIVILEGED_GROUPS = ("administrators", "domain admins", "enterprise admins", "remote desktop users", "backup operators", "account operators", "schema admins", "group policy creator owners")

PRIVILEGED_PRIVILEGES = ("SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege")


def command_line_of(event):
    return event.payload.get("CommandLine") or event.payload.get("ProcessCommandLine") or event.payload.get("ScriptBlockText") or ""


def worst_command_pattern(event):
    # the most severe pattern in the command line, or None
    text = command_line_of(event)
    if not text:
        return None
    best = None
    for pattern, label, severity in COMMAND_PATTERNS:
        if regex_any(text, (pattern,)):
            if best is None or SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(best[2], 0):
                best = (pattern, label, severity)
    return best


def has_suspicious_command(event):
    return worst_command_pattern(event) is not None


def command_severity(event):
    hit = worst_command_pattern(event)
    return hit[2] if hit else "medium"


def command_label(event):
    hit = worst_command_pattern(event)
    return hit[1] if hit else ""


def is_privileged_group(event):
    return matches_any(event.payload.get("MemberName", "") + " " + event.payload.get("GroupName", ""), PRIVILEGED_GROUPS)


def uses_privileged_token(event):
    return matches_any(event.payload.get("PrivilegeList", ""), tuple(item.lower() for item in PRIVILEGED_PRIVILEGES))


def is_admin_share(event):
    share = event.payload.get("ShareName", "")
    if matches_any(share, ("admin$", "c$", "ipc$", "print$")):
        return True
    return matches_any(event.payload.get("ShareLocalPath", ""), ("\\windows", "\\users"))


def logon_type_of(event):
    return LOGON_TYPES.get((event.payload.get("LogonType") or "").strip(), (event.payload.get("LogonType") or "").strip())


def remote_logon(event):
    return logon_type_of(event) in ("network", "remote interactive", "network cleartext")


def kerberos_rc4(event):
    # the encryption type arrives as a hex string such as 0x00000017, so it is
    # compared as a number rather than as text
    raw = (event.payload.get("TicketEncryptionType") or "").strip().lower()
    if raw in ("rc4-hmac", "0x17 (rc4-hmac)"):
        return True
    try:
        return int(raw, 0) == 0x17
    except ValueError:
        return False


def service_binary(event):
    return event.payload.get("ImagePath") or event.payload.get("ServiceFileName") or ""


RULES = [
    Rule("EVT-LOG-CLEARED", "Event log cleared", "critical", "T1070.001", (1102, 104), SECURITY_CHANNEL + SYSTEM_CHANNEL,
         detail_fields=("SubjectUserName", "param1"), description="Audit or system log was cleared, an anti forensics step that hides earlier activity", tags=("antiforensics",)),
    Rule("EVT-LOG-SERVICE-STOP", "Event log service stopped", "high", "T1562.002", (1100,), SECURITY_CHANNEL,
         detail_fields=("param1", "param2"), description="The Windows event log service was shut down, logging stops here"),
    Rule("EVT-AUDIT-POLICY", "Audit policy changed", "medium", "T1562.002", (4719,), SECURITY_CHANNEL,
         detail_fields=("CategoryId", "SubcategoryId", "AuditPolicyChanges"), description="Audit policy modified, often to blind logging"),
    Rule("EVT-ACCOUNT-CREATED", "Account created or enabled", "high", "T1136.001", (4720, 4722, 4723, 4724), SECURITY_CHANNEL,
         detail_fields=("TargetUserName", "SubjectUserName", "TargetDomainName")),
    Rule("EVT-ACCOUNT-DELETED", "Account deleted or disabled", "medium", "T1531", (4726, 4725), SECURITY_CHANNEL,
         detail_fields=("TargetUserName", "SubjectUserName")),
    Rule("EVT-GROUP-ADD", "Privileged group membership change", "high", "T1098", (4728, 4732, 4756), SECURITY_CHANNEL,
         predicate=is_privileged_group, detail_fields=("MemberName", "GroupName", "SubjectUserName")),
    Rule("EVT-PRIV-TOKEN", "Sensitive privileges assigned", "low", "T1078", (4672,), SECURITY_CHANNEL,
         predicate=uses_privileged_token, detail_fields=("SubjectUserName",), score=8),
    Rule("EVT-EXPLICIT-CREDENTIAL", "Explicit credential use", "medium", "T1078", (4648,), SECURITY_CHANNEL,
         detail_fields=("SubjectUserName", "TargetUserName", "TargetServerName")),
    Rule("EVT-SERVICE-INSTALL", "Service installed", "high", "T1543.003", (7045, 4697), SYSTEM_CHANNEL + SECURITY_CHANNEL,
         detail_fields=("ServiceName", "ImagePath", "ServiceFileName", "ServiceType", "StartType"), tags=("persistence",)),
    Rule("EVT-SCHEDULED-TASK", "Scheduled task created or modified", "high", "T1053.005", (4698, 4699, 4700, 4701, 4702, 106, 140, 141), SECURITY_CHANNEL + TASKS_CHANNEL,
         detail_fields=("TaskName", "SubjectUserName"), tags=("persistence",)),
    Rule("EVT-PROCESS-SUSPICIOUS", "Suspicious process creation", "high", "T1059", (4688,), SECURITY_CHANNEL,
         predicate=has_suspicious_command, detail_fields=("NewProcessName", "CommandLine", "ParentProcessName", "SubjectUserName"), tags=("execution",)),
    Rule("EVT-POWERSHELL-SCRIPT", "PowerShell script block matches attack tooling", "medium", "T1059.001", (4104,), POWERSHELL_CHANNEL,
         predicate=has_suspicious_command, detail_fields=("ScriptBlockText", "Path")),
    Rule("EVT-KERBEROAST", "Kerberos service ticket with weak encryption", "high", "T1558.003", (4769,), SECURITY_CHANNEL,
         predicate=kerberos_rc4, detail_fields=("TargetUserName", "ServiceName", "TicketEncryptionType", "IpAddress"), tags=("credential access",)),
    Rule("EVT-KERBEROS-NOPREAUTH", "Kerberos pre authentication disabled for an account", "high", "T1558.004", (4768,), SECURITY_CHANNEL,
         predicate=lambda event: (event.payload.get("PreAuthType") or "").strip() == "0", detail_fields=("TargetUserName", "PreAuthType", "IpAddress")),
    Rule("EVT-FIREWALL-CHANGE", "Firewall rule changed", "medium", "T1562.004", (4946, 4947, 4948), SECURITY_CHANNEL,
         detail_fields=("RuleName", "RuleId", "SubjectUserName")),
    Rule("EVT-DEFENDER-DETECTION", "Defender reported a threat", "high", "T1204", (1116, 1117, 1006, 1015), DEFENDER_CHANNEL,
         detail_fields=("ThreatName", "Path", "ActionName")),
    Rule("EVT-DEFENDER-TAMPER", "Defender protection changed", "critical", "T1562.001", (5001, 5010, 5012), DEFENDER_CHANNEL,
         detail_fields=("ProductName", "Setting")),
    Rule("EVT-SHARE-ACCESS", "Administrative share accessed", "medium", "T1021.002", (5140, 5145), SECURITY_CHANNEL,
         predicate=is_admin_share, detail_fields=("ShareName", "SubjectUserName", "IpAddress")),
    Rule("EVT-WMI-ACTIVITY", "WMI remote activity", "medium", "T1047", (5860, 5861, 5857), WMI_CHANNEL,
         detail_fields=("Operation", "User", "ClientProcessId", "Query")),
    Rule("EVT-BITS-JOB", "BITS transfer job", "medium", "T1197", (3, 59, 60), BITS_CHANNEL,
         detail_fields=("jobTitle", "url", "owner")),
    Rule("EVT-SAM-ACCESS", "Registry hive object accessed", "high", "T1003.002", (4656, 4663), SECURITY_CHANNEL,
         predicate=lambda event: matches_any(event.payload.get("ObjectName", ""), ("\\sam", "\\security", "\\system", "ntds.dit")),
         detail_fields=("ObjectName", "SubjectUserName", "AccessMask")),
    Rule("EVT-ACCOUNT-LOCKOUT", "Account locked out", "medium", "T1110", (4740,), SECURITY_CHANNEL,
         detail_fields=("TargetUserName", "SubjectUserName", "TargetDomainName")),
    Rule("EVT-DOMAIN-TRUST", "Domain trust created or modified", "high", "T1098", (4706, 4707), SECURITY_CHANNEL,
         detail_fields=("DomainName", "SubjectUserName")),
    Rule("EVT-SYSTEM-TIME", "System time changed", "medium", "T1099", (4616, 1), SECURITY_CHANNEL + SYSTEM_CHANNEL,
         detail_fields=("SubjectUserName", "ProcessName", "NewTime", "OldTime")),
    Rule("EVT-RDP-SESSION", "Remote desktop session opened or closed", "low", "T1021.001", (4778, 4779, 25, 24), SECURITY_CHANNEL + TERMINAL_CHANNEL,
         detail_fields=("AccountName", "UserName", "Address", "SessionName"), score=6),
    Rule("EVT-KERBEROS-FAILURE", "Kerberos authentication failure", "low", "T1110", (4771,), SECURITY_CHANNEL,
         detail_fields=("TargetUserName", "IpAddress", "Status"), score=5),
    Rule("EVT-STARTUP-RUN", "Program added to a startup location", "high", "T1547.001", (4657,), SECURITY_CHANNEL,
         predicate=lambda event: matches_any(event.payload.get("ObjectName", ""), ("\\run", "\\runonce", "\\winlogon")),
         detail_fields=("ObjectName", "SubjectUserName", "NewValue")),
    Rule("EVT-DRIVER-LOAD", "Kernel driver loaded", "medium", "T1543.003", (6, 219), SYSTEM_CHANNEL,
         detail_fields=("ImagePath", "param1")),
    Rule("EVT-REMOVABLE-MEDIA", "Removable media inserted", "low", "T1052.001", (2003, 2100, 2102), SYSTEM_CHANNEL,
         detail_fields=("DeviceDescription", "param1", "param2"), score=3),
    Rule("EVT-SERVICE-CRASH", "Service terminated unexpectedly", "info", "T1489", (7031, 7034), SYSTEM_CHANNEL,
         detail_fields=("param1", "param2"), score=2),
]

RULE_INDEX = dict((rule.rule_id, rule) for rule in RULES)
