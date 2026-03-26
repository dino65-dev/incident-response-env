# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Medium: Lateral Movement
# BSD-3-Clause License

"""
Task 2: MEDIUM - Brute Force Leading to Lateral Movement

VPN brute-force from external IP succeeds against an MFA-exempt service
account. Attacker performs lateral movement to domain controller and
exfiltrates NTDS.dit.
"""

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
    from .base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory
    from tasks.base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile


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

TASK_DEFINITION = {
    "name": "Brute Force & Lateral Movement",
    "description": (
        "Investigate a multi-stage attack: VPN brute-force, credential compromise, "
        "lateral movement to domain controller, and credential dump exfiltration. "
        "Map the full attack chain, scope the compromise, and execute multi-target containment."
    ),
    "difficulty": "medium",
    "expected_steps": "12-20",
    "key_skills": "Attack chain reconstruction, lateral movement detection, credential theft analysis",
}
