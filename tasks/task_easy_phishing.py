# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Easy: Phishing Email
# BSD-3-Clause License

"""
Task 1: EASY - Phishing Email with Malicious Attachment

A phishing email with macro-enabled Excel dropper. Email gateway flags
suspicious attachment. Agent must determine if payload executed and
contain the threat.
"""

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
    from .base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory
    from tasks.base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile


SCENARIO_EASY_PHISHING = Scenario(
    scenario_id="phishing_malware_001",
    task_id="easy",
    difficulty="easy",
    alert_summary=(
        "ALERT [SEG-4012]: Email gateway flagged inbound email to jsmith@acmecorp.com "
        "from 'hr-benefits@acme-corp-hr.com' (spoofed domain) containing attachment "
        "'Q1_Benefits_Update.xlsm' with embedded macro. Attachment SHA256: "
        "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1. "
        "User jsmith opened the email at 09:14 UTC."
    ),
    alert_source="Secure Email Gateway (Proofpoint)",
    alert_timestamp="2026-03-25T09:15:00Z",
    initial_observation=(
        "Email security alert triggered. A suspicious email with a macro-enabled "
        "Excel attachment was delivered to a user. The sender domain closely mimics "
        "the legitimate corporate HR domain. Investigation is needed to determine "
        "if the attachment was executed and whether the endpoint is compromised."
    ),
    true_severity=Severity.HIGH,
    true_category=ThreatCategory.PHISHING,
    required_containment=[
        ContainmentAction.QUARANTINE_FILE,
        ContainmentAction.ISOLATE_HOST,
    ],
    containment_targets={
        "quarantine_file": "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        "isolate_host": "WS-JSMITH-PC",
    },
    correct_escalation=None,
    max_steps=20,
    log_entries=[
        LogEntry(
            source="email",
            content=(
                "[09:14:03Z] DELIVERED: From=hr-benefits@acme-corp-hr.com "
                "To=jsmith@acmecorp.com Subject='Q1 Benefits Update - Action Required' "
                "Attachment=Q1_Benefits_Update.xlsm Size=847KB "
                "SPF=FAIL DKIM=FAIL DMARC=FAIL X-Spam-Score=7.2"
            ),
            is_critical=True,
            keywords=["email", "phishing", "attachment", "macro", "xlsm", "spf", "dkim", "dmarc"],
        ),
        LogEntry(
            source="email",
            content=(
                "[09:14:05Z] ATTACHMENT_SCAN: File=Q1_Benefits_Update.xlsm "
                "SHA256=a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1 "
                "Result=SUSPICIOUS Reason='VBA macro detected, obfuscated PowerShell invocation' "
                "Macro_Functions=['AutoOpen', 'Document_Open'] "
                "Suspicious_Strings=['powershell.exe', '-enc', 'IEX', 'DownloadString']"
            ),
            is_critical=True,
            keywords=["attachment", "macro", "powershell", "obfuscated", "vba", "sha256"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[09:17:22Z] PROCESS_CREATE: Host=WS-JSMITH-PC User=jsmith "
                "Parent=EXCEL.EXE PID=4812 -> Child=powershell.exe PID=5901 "
                "CmdLine='powershell.exe -WindowStyle Hidden -enc aQBlAHgAIAAoAG4AZQB3...' "
                "Signature=UNSIGNED Risk=CRITICAL"
            ),
            is_critical=True,
            keywords=["edr", "process", "powershell", "excel", "encoded", "macro", "endpoint"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[09:17:45Z] NETWORK_CONN: Host=WS-JSMITH-PC PID=5901(powershell.exe) "
                "Dest=185.220.101.42:443 Protocol=HTTPS Bytes_Out=2.3KB Bytes_In=156KB "
                "Domain=cdn-update.acme-corp-hr.com DNS_Resolved=185.220.101.42 "
                "Cert_Issuer='Let\\'s Encrypt' Cert_Age=2days"
            ),
            is_critical=True,
            keywords=["edr", "network", "c2", "connection", "outbound", "powershell", "endpoint"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[09:17:46Z] HTTPS_CONN: Src=10.1.50.22(WS-JSMITH-PC) "
                "Dst=185.220.101.42 Host=cdn-update.acme-corp-hr.com "
                "Category=UNCATEGORIZED Action=ALLOWED User=ACMECORP\\jsmith "
                "Bytes=158KB UserAgent='PowerShell/5.1'"
            ),
            is_critical=False,
            keywords=["proxy", "network", "powershell", "connection"],
        ),
        LogEntry(
            source="dns",
            content=(
                "[09:17:44Z] QUERY: Client=10.1.50.22 Query=cdn-update.acme-corp-hr.com "
                "Type=A Response=185.220.101.42 TTL=300 "
                "NOTE: Domain registered 3 days ago via Namecheap"
            ),
            is_critical=False,
            keywords=["dns", "domain", "resolution", "newly_registered"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[09:18:10Z] FILE_CREATE: Host=WS-JSMITH-PC User=jsmith "
                "Process=powershell.exe(5901) Path=C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost_update.exe "
                "SHA256=b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5 "
                "Size=312KB Signed=NO"
            ),
            is_critical=True,
            keywords=["edr", "file", "dropped", "executable", "suspicious", "endpoint"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[09:13:45Z] LOGIN_SUCCESS: User=jsmith Host=WS-JSMITH-PC "
                "IP=10.1.50.22 Method=Kerberos Location=Building-A-Floor3 "
                "Previous_Login=2026-03-24T17:30:00Z"
            ),
            is_critical=False,
            keywords=["auth", "login", "user", "jsmith"],
        ),
        LogEntry(
            source="firewall",
            content=(
                "[09:17:47Z] ALLOW: Src=10.1.50.22 Dst=185.220.101.42 Port=443 "
                "Proto=TCP Action=ALLOW Rule=Default-Outbound-HTTPS "
                "Bytes=158240 Duration=12s"
            ),
            is_critical=False,
            keywords=["firewall", "network", "outbound", "allowed"],
        ),
    ],
    threat_intel=[
        ThreatIntelEntry(
            ioc="185.220.101.42",
            ioc_type="ip",
            description=(
                "Known C2 server associated with Emotet/TrickBot infrastructure. "
                "First seen: 2026-03-20. Last seen: 2026-03-25. "
                "Confidence: HIGH. Reported by: AbuseIPDB (96% confidence), "
                "AlienVault OTX, CrowdStrike Falcon X."
            ),
            severity="critical",
            source="Multi-source TI aggregation",
            keywords=["185.220.101.42", "ip", "c2", "emotet", "trickbot"],
        ),
        ThreatIntelEntry(
            ioc="acme-corp-hr.com",
            ioc_type="domain",
            description=(
                "Typosquatting domain mimicking acmecorp.com. Registered 2026-03-22 "
                "via Namecheap with privacy protection. Hosting on bulletproof provider. "
                "Associated with phishing campaign targeting corporate employees."
            ),
            severity="high",
            source="DomainTools / URLScan.io",
            keywords=["acme-corp-hr.com", "domain", "typosquat", "phishing"],
        ),
        ThreatIntelEntry(
            ioc="a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
            ioc_type="hash",
            description=(
                "Macro-enabled Excel dropper. VT Score: 38/72. "
                "Drops encoded PowerShell payload that fetches second-stage from C2. "
                "Family: Emotet variant. First submission: 2026-03-24."
            ),
            severity="critical",
            source="VirusTotal / Hybrid Analysis",
            keywords=["hash", "malware", "emotet", "macro", "dropper"],
        ),
    ],
    endpoints=[
        EndpointInfo(
            endpoint_id="EP-001",
            hostname="WS-JSMITH-PC",
            os="Windows 11 Enterprise 23H2",
            ip="10.1.50.22",
            status="ONLINE - SUSPICIOUS ACTIVITY DETECTED",
            processes=[
                "EXCEL.EXE (PID:4812) -> powershell.exe (PID:5901) [SUSPICIOUS]",
                "svchost_update.exe (PID:6102) [UNSIGNED, NEWLY CREATED]",
                "Normal system processes...",
            ],
            connections=[
                "powershell.exe -> 185.220.101.42:443 (ACTIVE)",
                "svchost_update.exe -> 185.220.101.42:8443 (ACTIVE)",
            ],
            files_modified=[
                "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost_update.exe (CREATED)",
                "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk (CREATED)",
            ],
            is_compromised=True,
        ),
    ],
    users=[
        UserProfile(
            user_id="jsmith",
            display_name="John Smith",
            department="Engineering",
            role="Senior Software Developer",
            recent_logins=[
                "2026-03-25 09:13 - WS-JSMITH-PC (Normal)",
                "2026-03-24 08:45 - WS-JSMITH-PC (Normal)",
                "2026-03-23 09:02 - WS-JSMITH-PC (Normal)",
            ],
            risk_score=0.15,
            notes="Standard user, no prior security incidents. Phishing training completed 2026-01-15.",
        ),
    ],
    correlation_findings=[
        (
            "CORRELATION: 3 other employees received similar emails from acme-corp-hr.com "
            "domain in the past 2 hours. Recipients: mwilson@acmecorp.com, "
            "jdoe@acmecorp.com, alee@acmecorp.com. Only jsmith appears to have opened the attachment."
        ),
        (
            "CORRELATION: The C2 IP 185.220.101.42 has been seen in 2 other incidents "
            "in the past week targeting companies in the technology sector. "
            "Pattern consistent with targeted phishing campaigns."
        ),
    ],
    critical_evidence={
        "email_spf_dkim_fail",
        "macro_execution",
        "powershell_spawned_from_excel",
        "c2_connection_185.220.101.42",
        "dropped_executable",
    },
    critical_iocs={
        "185.220.101.42",
        "acme-corp-hr.com",
        "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        "svchost_update.exe",
    },
    report_keywords=[
        "phishing", "macro", "powershell", "c2", "emotet",
        "isolate", "quarantine", "high",
    ],
)

TASK_DEFINITION = {
    "name": "Phishing Email Triage",
    "description": (
        "Investigate a phishing email alert with a malicious macro attachment. "
        "Determine if the payload executed, identify IOCs, classify severity, "
        "and take appropriate containment actions."
    ),
    "difficulty": "easy",
    "expected_steps": "8-15",
    "key_skills": "Email analysis, IOC identification, endpoint triage",
}
