# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Scenario Definitions
# BSD-3-Clause License

"""
Scenario definitions for the Incident Response Triage Environment.

Each scenario is a self-contained cybersecurity incident with:
- Alert metadata and initial observations
- Hidden ground truth (correct severity, category, containment)
- Layered evidence that investigation actions reveal
- A grading rubric for the agent's performance

Scenarios are designed with realistic forensic artifacts drawn from
common SOC analyst workflows and real-world threat patterns.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

try:
    from .models import ContainmentAction, Severity, ThreatCategory
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory


@dataclass
class LogEntry:
    """A single log entry that can be discovered during investigation."""
    source: str  # firewall, edr, proxy, auth, dns, email
    content: str
    is_critical: bool = False  # Whether this is key evidence
    keywords: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelEntry:
    """Threat intelligence data linked to an IOC."""
    ioc: str
    ioc_type: str  # ip, domain, hash, email
    description: str
    severity: str
    source: str
    keywords: List[str] = field(default_factory=list)


@dataclass
class EndpointInfo:
    """Information about an endpoint in the network."""
    endpoint_id: str
    hostname: str
    os: str
    ip: str
    status: str
    processes: List[str] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    is_compromised: bool = False


@dataclass
class UserProfile:
    """User profile information for investigation."""
    user_id: str
    display_name: str
    department: str
    role: str
    recent_logins: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    notes: str = ""


@dataclass
class Scenario:
    """Complete incident scenario definition."""
    # Identification
    scenario_id: str
    task_id: str  # easy, medium, hard
    difficulty: str

    # Alert metadata
    alert_summary: str
    alert_source: str
    alert_timestamp: str
    initial_observation: str

    # Ground truth
    true_severity: Severity
    true_category: ThreatCategory
    required_containment: List[ContainmentAction]
    containment_targets: Dict[str, str]  # action -> target
    is_false_positive: bool = False
    correct_escalation: Optional[str] = None  # None if no escalation needed

    # Evidence layers
    log_entries: List[LogEntry] = field(default_factory=list)
    threat_intel: List[ThreatIntelEntry] = field(default_factory=list)
    endpoints: List[EndpointInfo] = field(default_factory=list)
    users: List[UserProfile] = field(default_factory=list)
    correlation_findings: List[str] = field(default_factory=list)

    # Critical evidence items the agent should find
    critical_evidence: Set[str] = field(default_factory=set)
    critical_iocs: Set[str] = field(default_factory=set)

    # Episode parameters
    max_steps: int = 20
    report_keywords: List[str] = field(default_factory=list)


# =============================================================================
# TASK 1: EASY - Phishing Email with Malicious Attachment
# =============================================================================

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


# =============================================================================
# TASK 2: MEDIUM - Brute Force Leading to Lateral Movement
# =============================================================================

SCENARIO_MEDIUM_LATERAL = Scenario(
    scenario_id="lateral_movement_001",
    task_id="medium",
    difficulty="medium",
    alert_summary=(
        "ALERT [SIEM-7823]: Multiple failed authentication attempts detected against "
        "VPN gateway (vpn.acmecorp.com) from IP 91.134.205.17, followed by a successful "
        "login using credentials of 'admin_backup' service account at 02:47 UTC. "
        "Subsequent RDP sessions observed to 3 internal servers within 15 minutes."
    ),
    alert_source="SIEM Correlation Rule (Splunk)",
    alert_timestamp="2026-03-25T03:02:00Z",
    initial_observation=(
        "SIEM correlation rule triggered: Brute-force pattern against VPN followed by "
        "successful authentication and rapid internal lateral movement. The compromised "
        "account 'admin_backup' is a service account with elevated privileges. "
        "Multiple internal servers show new RDP connections from an unusual source. "
        "This requires thorough investigation to map the full attack chain and scope of compromise."
    ),
    true_severity=Severity.CRITICAL,
    true_category=ThreatCategory.LATERAL_MOVEMENT,
    required_containment=[
        ContainmentAction.DISABLE_ACCOUNT,
        ContainmentAction.BLOCK_IP,
        ContainmentAction.REVOKE_SESSIONS,
        ContainmentAction.ISOLATE_HOST,
    ],
    containment_targets={
        "disable_account": "admin_backup",
        "block_ip": "91.134.205.17",
        "revoke_sessions": "admin_backup",
        "isolate_host": "DC-BACKUP-01",
    },
    correct_escalation="tier3",
    max_steps=25,
    log_entries=[
        LogEntry(
            source="auth",
            content=(
                "[02:15:00Z-02:46:58Z] BRUTE_FORCE_PATTERN: 847 failed login attempts "
                "against VPN gateway from IP=91.134.205.17 over 32 minutes. "
                "Targeted accounts: admin, administrator, svc_admin, admin_backup, root, "
                "backup_admin (rotating). Authentication method: RADIUS. "
                "Rate: ~26 attempts/min. No lockout triggered (service accounts exempt)."
            ),
            is_critical=True,
            keywords=["auth", "brute_force", "vpn", "failed", "login", "91.134.205.17"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[02:47:03Z] VPN_LOGIN_SUCCESS: User=admin_backup IP=91.134.205.17 "
                "Method=RADIUS MFA=BYPASSED(service_account_exception) "
                "VPN_Pool_IP_Assigned=10.0.100.55 Session_ID=VPN-88291 "
                "NOTE: Service account 'admin_backup' has MFA exemption per IT policy exception #2019-034"
            ),
            is_critical=True,
            keywords=["auth", "vpn", "login", "success", "admin_backup", "mfa", "bypass"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[02:49:15Z] RDP_LOGIN: User=admin_backup Src=10.0.100.55 "
                "Dst=10.1.10.5(DB-PROD-01) Status=SUCCESS "
                "NOTE: First RDP from VPN pool to this server in 90 days"
            ),
            is_critical=True,
            keywords=["auth", "rdp", "login", "lateral", "database", "server"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[02:52:33Z] RDP_LOGIN: User=admin_backup Src=10.0.100.55 "
                "Dst=10.1.10.8(FILE-SRV-02) Status=SUCCESS "
                "[02:55:47Z] RDP_LOGIN: User=admin_backup Src=10.0.100.55 "
                "Dst=10.1.10.3(DC-BACKUP-01) Status=SUCCESS "
                "NOTE: Domain Controller access - CRITICAL"
            ),
            is_critical=True,
            keywords=["auth", "rdp", "lateral_movement", "domain_controller", "file_server"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[02:53:01Z] PROCESS_CREATE: Host=DB-PROD-01 User=admin_backup "
                "Process=cmd.exe -> whoami.exe, ipconfig.exe, net.exe "
                "CmdLine='net user /domain' 'net group \"Domain Admins\" /domain' "
                "Risk=HIGH Tactic=DISCOVERY(T1087)"
            ),
            is_critical=True,
            keywords=["edr", "discovery", "enumeration", "reconnaissance", "domain"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[02:56:12Z] PROCESS_CREATE: Host=DC-BACKUP-01 User=admin_backup "
                "Process=cmd.exe -> ntdsutil.exe "
                "CmdLine='ntdsutil \"activate instance ntds\" ifm \"create full C:\\temp\\backup\"' "
                "Risk=CRITICAL Tactic=CREDENTIAL_ACCESS(T1003.003) "
                "NOTE: NTDS.dit extraction attempt - Active Directory database dump"
            ),
            is_critical=True,
            keywords=["edr", "ntdsutil", "credential", "dump", "ntds", "domain_controller", "ad"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[03:01:30Z] FILE_CREATE: Host=DC-BACKUP-01 User=admin_backup "
                "Path=C:\\temp\\backup\\ntds.dit Size=1.2GB "
                "Path=C:\\temp\\backup\\SYSTEM Size=16MB "
                "NOTE: AD database and registry hive copied - contains all domain credentials"
            ),
            is_critical=True,
            keywords=["edr", "file", "ntds", "credentials", "exfiltration"],
        ),
        LogEntry(
            source="firewall",
            content=(
                "[02:14:58Z] ALLOW: Src=91.134.205.17 Dst=vpn.acmecorp.com(203.0.113.10) "
                "Port=443 Proto=TCP Rule=VPN-Inbound Bytes=2.8MB Duration=48min "
                "GeoIP=Russia(Moscow) ASN=AS16276(OVH)"
            ),
            is_critical=True,
            keywords=["firewall", "vpn", "russia", "external", "geoip"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[03:02:15Z] UPLOAD: Src=10.1.10.3(DC-BACKUP-01) "
                "Dst=transfer.sh:443 User=admin_backup "
                "Method=PUT Size=1.2GB Duration=180s "
                "NOTE: Large file upload to file sharing service"
            ),
            is_critical=True,
            keywords=["proxy", "upload", "exfiltration", "transfer.sh", "data"],
        ),
        LogEntry(
            source="dns",
            content=(
                "[03:02:10Z] QUERY: Client=10.1.10.3 Query=transfer.sh "
                "Type=A Response=144.76.136.153 TTL=3600"
            ),
            is_critical=False,
            keywords=["dns", "transfer.sh", "exfiltration"],
        ),
    ],
    threat_intel=[
        ThreatIntelEntry(
            ioc="91.134.205.17",
            ioc_type="ip",
            description=(
                "Known brute-force attack source. Associated with credential stuffing "
                "campaigns. Listed on AbuseIPDB (99% confidence, 1247 reports). "
                "GeoIP: Russia, Moscow. ASN: OVH SAS. "
                "Previously linked to APT28/Fancy Bear infrastructure."
            ),
            severity="critical",
            source="AbuseIPDB / CrowdStrike",
            keywords=["91.134.205.17", "brute_force", "russia", "apt28"],
        ),
    ],
    endpoints=[
        EndpointInfo(
            endpoint_id="EP-DB01",
            hostname="DB-PROD-01",
            os="Windows Server 2022",
            ip="10.1.10.5",
            status="ONLINE - SUSPICIOUS ACTIVITY",
            processes=[
                "cmd.exe -> whoami.exe, ipconfig.exe, net.exe [DISCOVERY]",
                "sqlservr.exe (normal database process)",
            ],
            connections=[
                "RDP from 10.0.100.55 (VPN pool - admin_backup)",
            ],
            files_modified=[],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-FS02",
            hostname="FILE-SRV-02",
            os="Windows Server 2022",
            ip="10.1.10.8",
            status="ONLINE - RDP SESSION ACTIVE",
            processes=["Normal file server processes"],
            connections=["RDP from 10.0.100.55 (VPN pool - admin_backup)"],
            files_modified=[],
            is_compromised=False,
        ),
        EndpointInfo(
            endpoint_id="EP-DC01",
            hostname="DC-BACKUP-01",
            os="Windows Server 2022 (Domain Controller)",
            ip="10.1.10.3",
            status="ONLINE - CRITICAL ALERT",
            processes=[
                "ntdsutil.exe [CREDENTIAL ACCESS - T1003.003]",
                "cmd.exe -> curl.exe (uploading to transfer.sh)",
            ],
            connections=[
                "RDP from 10.0.100.55 (VPN pool - admin_backup)",
                "HTTPS to transfer.sh:443 (FILE UPLOAD 1.2GB)",
            ],
            files_modified=[
                "C:\\temp\\backup\\ntds.dit (1.2GB - AD DATABASE)",
                "C:\\temp\\backup\\SYSTEM (16MB - REGISTRY HIVE)",
            ],
            is_compromised=True,
        ),
    ],
    users=[
        UserProfile(
            user_id="admin_backup",
            display_name="Backup Admin (Service Account)",
            department="IT Infrastructure",
            role="Service Account - Backup Operations",
            recent_logins=[
                "2026-03-25 02:47 - VPN from 91.134.205.17 [ANOMALOUS]",
                "2026-02-15 03:00 - Scheduled backup task (automated)",
                "2026-01-15 03:00 - Scheduled backup task (automated)",
            ],
            risk_score=0.95,
            notes=(
                "Service account with Domain Admin privileges. MFA exempted per "
                "IT exception #2019-034 (filed 2019, never reviewed). "
                "Password last changed: 2024-06-01. Password policy: exempt from rotation. "
                "Normally only used by automated backup scripts running from BACKUP-SRV-01."
            ),
        ),
    ],
    correlation_findings=[
        (
            "CORRELATION: The IP 91.134.205.17 attempted brute-force against 5 other "
            "organizations' VPN endpoints this week (per FS-ISAC feed). "
            "Success rate: ~2% when service accounts lack MFA."
        ),
        (
            "CORRELATION: admin_backup account has NEVER logged in from VPN before. "
            "All previous authentications were from internal BACKUP-SRV-01 (10.1.10.20). "
            "This is a FIRST-TIME VPN login for this service account."
        ),
        (
            "CORRELATION: NTDS.dit exfiltration to transfer.sh detected. "
            "If successful, attacker has complete credential dump for the entire domain. "
            "Immediate forced password reset for all domain accounts recommended."
        ),
    ],
    critical_evidence={
        "brute_force_from_91.134.205.17",
        "vpn_login_without_mfa",
        "lateral_movement_rdp",
        "domain_controller_access",
        "ntdsdit_extraction",
        "data_exfiltration_transfer_sh",
    },
    critical_iocs={
        "91.134.205.17",
        "admin_backup",
        "ntds.dit",
        "transfer.sh",
    },
    report_keywords=[
        "brute_force", "lateral_movement", "credential", "ntds",
        "domain_controller", "exfiltration", "critical", "mfa",
    ],
)


# =============================================================================
# TASK 3: HARD - Insider Threat Disguised as Normal Activity
# =============================================================================

SCENARIO_HARD_INSIDER = Scenario(
    scenario_id="insider_threat_001",
    task_id="hard",
    difficulty="hard",
    alert_summary=(
        "ALERT [DLP-1156]: Data Loss Prevention rule triggered: User rchen@acmecorp.com "
        "uploaded 340MB to personal Google Drive from workstation WS-RCHEN-PC at 23:45 UTC. "
        "Content classification: 'CONFIDENTIAL - Product Roadmap'. User has authorized "
        "Google Drive access for work collaboration per IT policy."
    ),
    alert_source="DLP System (Symantec)",
    alert_timestamp="2026-03-24T23:47:00Z",
    initial_observation=(
        "A Data Loss Prevention alert was triggered for a large file upload to a personal "
        "cloud storage account. The user has legitimate access to the uploaded files and "
        "authorized cloud storage access. This could be normal work activity or "
        "potential data exfiltration. Careful investigation is required to determine "
        "intent and whether this constitutes a policy violation or insider threat."
    ),
    true_severity=Severity.CRITICAL,
    true_category=ThreatCategory.INSIDER_THREAT,
    required_containment=[
        ContainmentAction.DISABLE_ACCOUNT,
        ContainmentAction.REVOKE_SESSIONS,
    ],
    containment_targets={
        "disable_account": "rchen",
        "revoke_sessions": "rchen",
    },
    correct_escalation="management",
    max_steps=30,
    log_entries=[
        LogEntry(
            source="proxy",
            content=(
                "[23:44:30Z] UPLOAD: Src=10.1.50.45(WS-RCHEN-PC) "
                "Dst=drive.google.com User=rchen@acmecorp.com "
                "Files_Uploaded=12 Total_Size=340MB Duration=240s "
                "Google_Account=rachel.chen.personal@gmail.com "
                "Classification=CONFIDENTIAL"
            ),
            is_critical=True,
            keywords=["proxy", "upload", "google_drive", "personal", "confidential"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[23:30:00Z-23:44:00Z] BROWSING: User=rchen Sites_Visited: "
                "linkedin.com/jobs (14 min), glassdoor.com/salaries (8 min), "
                "indeed.com/companies/competitor-tech-corp (5 min) "
                "NOTE: Job search activity on corporate network during off-hours"
            ),
            is_critical=True,
            keywords=["proxy", "browsing", "job_search", "linkedin", "glassdoor", "intent"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[22:15:00Z-23:40:00Z] FILE_ACCESS_PATTERN: Host=WS-RCHEN-PC User=rchen "
                "Accessed 47 files across 8 SharePoint directories in 85 minutes. "
                "Directories accessed: /Product/Roadmap2027/, /Engineering/Architecture/, "
                "/Sales/Pipeline/, /Finance/Projections/, /HR/CompStructure/ "
                "NOTE: User normally accesses only /Product/ and /Engineering/ directories. "
                "Access to /Sales/, /Finance/, /HR/ is ANOMALOUS for this user's role."
            ),
            is_critical=True,
            keywords=["edr", "file_access", "anomalous", "bulk_download", "sharepoint"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[23:41:00Z] FILE_OPERATION: Host=WS-RCHEN-PC User=rchen "
                "Operation=ARCHIVE_CREATE Tool=7-Zip "
                "Output=C:\\Users\\rchen\\Documents\\Q1_Project_Backup.7z "
                "Source_Files=47 Password_Protected=YES Size=340MB"
            ),
            is_critical=True,
            keywords=["edr", "archive", "7zip", "password", "encrypted", "exfiltration"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[22:10:00Z] LOGIN: User=rchen Host=WS-RCHEN-PC IP=10.1.50.45 "
                "Method=Badge+Password Time=22:10 UTC (after hours) "
                "NOTE: User's normal hours are 09:00-18:00 UTC. "
                "After-hours access 3 times this week (unusual - previously 0 in 6 months)."
            ),
            is_critical=True,
            keywords=["auth", "login", "after_hours", "anomalous", "pattern"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[22:14:00Z] SHAREPOINT_AUTH: User=rchen "
                "Accessed_Sites=['Product-Internal', 'Engineering-Docs', "
                "'Sales-Pipeline', 'Finance-Reports', 'HR-Compensation'] "
                "NOTE: First-time access to Sales-Pipeline, Finance-Reports, HR-Compensation"
            ),
            is_critical=True,
            keywords=["auth", "sharepoint", "access", "first_time", "anomalous"],
        ),
        LogEntry(
            source="email",
            content=(
                "[18:30:00Z] SENT: From=rchen@acmecorp.com To=rchen.personal@gmail.com "
                "Subject='Updated Resume' Attachment=Resume_RChen_2026.pdf Size=245KB "
                "[18:45:00Z] SENT: From=rchen@acmecorp.com To=recruiter@competitor-tech.com "
                "Subject='Re: Senior Director Position - Confidential' "
                "Body_Preview='...excited about the opportunity... can start by April 15...'"
            ),
            is_critical=True,
            keywords=["email", "resume", "recruiter", "competitor", "resignation", "intent"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[23:42:00Z] BROWSER_HISTORY: Host=WS-RCHEN-PC User=rchen "
                "Recent_Downloads: 'how to transfer large files securely', "
                "'best encrypted file sharing services 2026', "
                "'does company monitor google drive uploads' "
                "NOTE: Searches related to evading corporate monitoring"
            ),
            is_critical=True,
            keywords=["edr", "browser", "search", "evasion", "monitoring", "intent"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[23:48:00Z] UPLOAD: Src=10.1.50.45(WS-RCHEN-PC) "
                "Dst=drive.google.com User=rchen@acmecorp.com "
                "Google_Account=rachel.chen.personal@gmail.com "
                "Files=Architecture_Diagrams_2027.pdf, Sales_Pipeline_Q2.xlsx, "
                "Compensation_Bands_2026.xlsx, Product_Roadmap_2027_FULL.pptx "
                "Total_Size=340MB Classification=CONFIDENTIAL/RESTRICTED"
            ),
            is_critical=True,
            keywords=["proxy", "upload", "specific_files", "confidential", "restricted"],
        ),
        LogEntry(
            source="firewall",
            content=(
                "[22:10:00Z-23:50:00Z] SESSION: Src=10.1.50.45 "
                "Total_Outbound=485MB (Normal daily average for user: 12MB) "
                "Peak_Upload=340MB to drive.google.com "
                "NOTE: 40x normal data transfer volume"
            ),
            is_critical=False,
            keywords=["firewall", "volume", "anomalous", "data_transfer"],
        ),
    ],
    threat_intel=[
        ThreatIntelEntry(
            ioc="rachel.chen.personal@gmail.com",
            ioc_type="email",
            description=(
                "Personal email address of employee Rachel Chen (rchen). "
                "No external threat indicators. This is an insider threat investigation - "
                "standard TI feeds do not flag personal employee accounts."
            ),
            severity="informational",
            source="Internal HR records",
            keywords=["email", "personal", "employee", "rachel_chen"],
        ),
    ],
    endpoints=[
        EndpointInfo(
            endpoint_id="EP-RCHEN",
            hostname="WS-RCHEN-PC",
            os="Windows 11 Enterprise 23H2",
            ip="10.1.50.45",
            status="ONLINE",
            processes=[
                "chrome.exe (Google Drive upload session)",
                "7z.exe (recently completed archiving operation)",
                "EXCEL.EXE (Sales_Pipeline_Q2.xlsx)",
                "POWERPNT.EXE (Product_Roadmap_2027_FULL.pptx)",
                "Normal system processes",
            ],
            connections=[
                "HTTPS to drive.google.com (upload complete)",
                "HTTPS to linkedin.com",
            ],
            files_modified=[
                "C:\\Users\\rchen\\Documents\\Q1_Project_Backup.7z (340MB, password-protected)",
                "C:\\Users\\rchen\\Downloads\\ (47 files from SharePoint)",
            ],
            is_compromised=False,
        ),
    ],
    users=[
        UserProfile(
            user_id="rchen",
            display_name="Rachel Chen",
            department="Product Management",
            role="Director of Product Strategy",
            recent_logins=[
                "2026-03-24 22:10 - WS-RCHEN-PC (AFTER HOURS)",
                "2026-03-23 21:30 - WS-RCHEN-PC (AFTER HOURS)",
                "2026-03-22 20:45 - WS-RCHEN-PC (AFTER HOURS)",
                "2026-03-21 09:15 - WS-RCHEN-PC (Normal)",
                "2026-03-20 09:00 - WS-RCHEN-PC (Normal)",
            ],
            risk_score=0.72,
            notes=(
                "Director-level employee, 4 years at company. Has legitimate access to "
                "Product and Engineering documents. Recently passed over for VP promotion "
                "(announced 2026-03-15). Performance reviews: consistently 'Exceeds Expectations'. "
                "Badge access logs show increasing after-hours presence since March 16. "
                "HR note: Employee requested PTO for April 14-18 (Monday-Friday) on March 20."
            ),
        ),
    ],
    correlation_findings=[
        (
            "CORRELATION: rchen accessed 5 SharePoint sites in one session. "
            "Normal behavior for this user is 1-2 sites per session (Product, Engineering). "
            "Access to Sales, Finance, and HR directories is outside normal scope. "
            "User's role does grant read access to these via Director-level permissions."
        ),
        (
            "CORRELATION: Data transfer volume (485MB) is 40x the user's daily average. "
            "Time of activity (22:10-23:50 UTC) is outside normal working hours. "
            "After-hours access increased from 0 sessions/month to 3 sessions/week "
            "starting March 16 (day after VP promotion announcement)."
        ),
        (
            "CORRELATION: HR records indicate rchen was passed over for VP promotion on "
            "March 15. Email analysis shows communication with a recruiter at "
            "competitor-tech.com discussing a 'Senior Director Position' with start date "
            "around April 15. PTO request filed for April 14-18. Pattern consistent with "
            "planned departure with data exfiltration."
        ),
    ],
    critical_evidence={
        "dlp_alert_confidential_upload",
        "after_hours_access_pattern",
        "anomalous_file_access_scope",
        "password_protected_archive",
        "job_search_and_recruiter_contact",
        "promotion_passed_over_motive",
        "search_queries_monitoring_evasion",
        "data_volume_anomaly",
    },
    critical_iocs={
        "rachel.chen.personal@gmail.com",
        "Q1_Project_Backup.7z",
        "competitor-tech.com",
        "rchen",
    },
    report_keywords=[
        "insider_threat", "data_exfiltration", "confidential", "competitor",
        "resignation", "after_hours", "anomalous", "critical", "dlp",
    ],
)


# =============================================================================
# Scenario Registry
# =============================================================================

SCENARIOS = {
    "easy": SCENARIO_EASY_PHISHING,
    "medium": SCENARIO_MEDIUM_LATERAL,
    "hard": SCENARIO_HARD_INSIDER,
}

TASK_DEFINITIONS = {
    "easy": {
        "name": "Phishing Email Triage",
        "description": (
            "Investigate a phishing email alert with a malicious macro attachment. "
            "Determine if the payload executed, identify IOCs, classify severity, "
            "and take appropriate containment actions."
        ),
        "difficulty": "easy",
        "expected_steps": "8-15",
        "key_skills": "Email analysis, IOC identification, endpoint triage",
    },
    "medium": {
        "name": "Brute Force & Lateral Movement",
        "description": (
            "Investigate a multi-stage attack: VPN brute-force, credential compromise, "
            "lateral movement to domain controller, and credential dump exfiltration. "
            "Map the full attack chain, scope the compromise, and execute multi-target containment."
        ),
        "difficulty": "medium",
        "expected_steps": "12-20",
        "key_skills": "Attack chain reconstruction, lateral movement detection, credential theft analysis",
    },
    "hard": {
        "name": "Insider Threat Investigation",
        "description": (
            "Investigate a DLP alert that appears to be normal activity but conceals "
            "an insider threat. The user has legitimate access and authorized tools. "
            "Distinguish malicious intent from routine work by correlating behavioral "
            "anomalies, HR context, and timing patterns. Requires nuanced judgment."
        ),
        "difficulty": "hard",
        "expected_steps": "15-25",
        "key_skills": "Behavioral analysis, intent determination, contextual correlation, nuanced judgment",
    },
}
