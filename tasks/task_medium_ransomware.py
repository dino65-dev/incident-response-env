# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Medium-Hard: Ransomware
# BSD-3-Clause License

"""
Task 4: MEDIUM-HARD - Ransomware Deployment & Encryption

Ransomware attack on ACME Corp. EDR alert: multiple hosts encrypting
files simultaneously after hours. Entry via compromised RDP credentials.
Cobalt Strike beacon deployed, lateral movement via PsExec, then LockBit
variant deployed to 3 servers.
"""

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
    from .base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory
    from tasks.base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile


SCENARIO_MEDIUM_RANSOMWARE = Scenario(
    scenario_id="ransomware_deploy_001",
    task_id="medium_hard",
    difficulty="medium_hard",
    alert_summary=(
        "ALERT [EDR-9201]: Multiple hosts reporting rapid file encryption "
        "(extension changed to .locked) starting at 03:22 UTC. Affected hosts: "
        "SRV-FILE-01, SRV-APP-02, SRV-DB-03. Ransom note 'README_RESTORE.txt' "
        "created on each host. EDR process tree shows PsExec execution from WS-ADMIN-PC."
    ),
    alert_source="EDR Platform (CrowdStrike Falcon)",
    alert_timestamp="2026-03-26T03:25:00Z",
    initial_observation=(
        "EDR alert triggered for coordinated file encryption across multiple servers. "
        "Ransom notes have been deployed. Process tree analysis shows lateral movement "
        "from an administrative workstation using PsExec. This appears to be an active "
        "ransomware deployment. Immediate investigation and containment are required to "
        "determine the full scope, identify the initial access vector, and stop further "
        "encryption."
    ),
    true_severity=Severity.CRITICAL,
    true_category=ThreatCategory.RANSOMWARE,
    required_containment=[
        ContainmentAction.ISOLATE_HOST,
        ContainmentAction.ISOLATE_HOST,
        ContainmentAction.BLOCK_IP,
        ContainmentAction.BLOCK_IP,
        ContainmentAction.DISABLE_ACCOUNT,
        ContainmentAction.REVOKE_SESSIONS,
    ],
    containment_targets={
        "isolate_host": "WS-ADMIN-PC",
        "block_ip": "45.33.32.100",
        "disable_account": "admin_svc",
        "revoke_sessions": "admin_svc",
    },
    correct_escalation="tier3",
    max_steps=25,
    # Multi-target containment pairs for advanced grading
    required_containment_pairs=[
        ("isolate_host", "WS-ADMIN-PC"),
        ("isolate_host", "SRV-FILE-01"),
        ("block_ip", "45.33.32.100"),
        ("block_ip", "198.51.100.77"),
        ("disable_account", "admin_svc"),
        ("revoke_sessions", "admin_svc"),
    ],
    log_entries=[
        LogEntry(
            source="auth",
            content=(
                "[02:50:00Z-03:04:59Z] RDP_BRUTE_FORCE: 312 failed RDP login attempts "
                "from external IP 45.33.32.100 targeting WS-ADMIN-PC:3389. "
                "Targeted accounts: admin, administrator, admin_svc. "
                "[03:05:12Z] RDP_LOGIN_SUCCESS: User=admin_svc IP=45.33.32.100 "
                "Dst=WS-ADMIN-PC Method=NLA MFA=DISABLED(legacy_exception) "
                "NOTE: admin_svc has never logged in from external IP. "
                "Normal login source: internal IT-ADMIN-WS-01."
            ),
            is_critical=True,
            keywords=["auth", "rdp", "brute_force", "rdp_bruteforce_external", "admin_svc", "mfa"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[03:08:14Z] PROCESS_CREATE: Host=WS-ADMIN-PC User=admin_svc "
                "Process=rundll32.exe Loading=C:\\temp\\update.dll "
                "NOTE: Cobalt Strike beacon DLL loaded via rundll32. "
                "[03:08:30Z] NETWORK_CONN: Host=WS-ADMIN-PC PID=rundll32.exe "
                "Dest=198.51.100.77:443 Protocol=HTTPS "
                "NOTE: Cobalt Strike C2 beacon callback. Process injection into svchost.exe detected. "
                "[03:12:00Z] PROCESS_CREATE: Host=WS-ADMIN-PC User=admin_svc "
                "Process=ADFind.exe CmdLine='ADFind.exe -f objectclass=computer' "
                "Risk=HIGH Tactic=DISCOVERY(T1018) "
                "NOTE: Active Directory reconnaissance tool."
            ),
            is_critical=True,
            keywords=["edr", "cobalt_strike", "cobalt_strike_beacon", "c2", "rundll32", "adfind", "discovery"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[03:15:00Z] LATERAL_MOVEMENT: Host=WS-ADMIN-PC User=admin_svc "
                "Tool=PsExec.exe Targets=[SRV-FILE-01(10.1.10.11), SRV-APP-02(10.1.10.12), "
                "SRV-DB-03(10.1.10.13)] via SMB/445 "
                "NOTE: PsExec deploying payloads to 3 servers simultaneously. "
                "Tactic=LATERAL_MOVEMENT(T1570) "
                "[03:22:01Z] FILE_MODIFY: Host=SRV-FILE-01 Process=locker.exe "
                "Files_Modified=12847 Extension_Changed=.locked "
                "Ransom_Note=README_RESTORE.txt Bitcoin_Wallet=bc1q... "
                "[03:22:03Z] FILE_MODIFY: Host=SRV-APP-02 Process=locker.exe "
                "Files_Modified=8391 Extension_Changed=.locked "
                "[03:22:05Z] FILE_MODIFY: Host=SRV-DB-03 Process=locker.exe "
                "Files_Modified=5672 Extension_Changed=.locked "
                "NOTE: Coordinated ransomware deployment in 7-minute window."
            ),
            is_critical=True,
            keywords=["edr", "lateral_movement_psexec", "psexec", "ransomware_encryption", "locker", "lateral_movement"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[03:08:16Z] HTTPS_CONN: Src=WS-ADMIN-PC(10.1.20.5) "
                "Dst=198.51.100.77:443 Host=c2.update-svc.net "
                "Category=UNCATEGORIZED Action=ALLOWED "
                "Bytes_Out=4.2KB Bytes_In=89KB "
                "NOTE: Cobalt Strike C2 channel. "
                "[03:25:30Z] HTTPS_CONN: Src=WS-ADMIN-PC(10.1.20.5) "
                "Dst=lockbit-payment.onion-proxy.com:443 "
                "NOTE: Ransomware payment portal accessed."
            ),
            is_critical=True,
            keywords=["proxy", "c2_communication", "cobalt_strike", "ransomware", "c2"],
        ),
        LogEntry(
            source="firewall",
            content=(
                "[02:50:00Z-03:05:00Z] ALLOW: Src=45.33.32.100 Dst=WS-ADMIN-PC(10.1.20.5) "
                "Port=3389 Proto=TCP Rule=RDP-Admin-Allow "
                "Bytes=1.8MB Duration=15min GeoIP=Romania "
                "NOTE: External RDP connection attempts from known brute-force source. "
                "[03:15:00Z-03:22:00Z] ALLOW: Src=WS-ADMIN-PC(10.1.20.5) "
                "Dst=10.1.10.11,10.1.10.12,10.1.10.13 Port=445 Proto=TCP "
                "Rule=Internal-SMB-Allow "
                "NOTE: SMB/PsExec lateral movement traffic."
            ),
            is_critical=True,
            keywords=["firewall", "rdp", "external", "smb", "lateral_movement"],
        ),
        LogEntry(
            source="dns",
            content=(
                "[03:07:55Z] QUERY: Client=WS-ADMIN-PC(10.1.20.5) "
                "Query=c2.update-svc.net Type=A Response=198.51.100.77 TTL=60 "
                "NOTE: Domain registered 5 days ago via bulletproof registrar. "
                "WHOIS privacy enabled. "
                "[03:25:28Z] QUERY: Client=WS-ADMIN-PC(10.1.20.5) "
                "Query=lockbit-payment.onion-proxy.com Type=A "
                "NOTE: Ransomware payment portal DNS lookup."
            ),
            is_critical=True,
            keywords=["dns", "c2", "c2_communication", "newly_registered", "ransomware"],
        ),
        LogEntry(
            source="email",
            content=(
                "[02:30:00Z] DELIVERED: From=it-helpdesk@acme-support.com "
                "To=admin_svc@acmecorp.com Subject='Urgent: Password Reset Required' "
                "Body_Preview='Your admin account requires immediate password reset. "
                "Click here to verify: https://acme-support.com/reset?token=...' "
                "SPF=FAIL DKIM=FAIL "
                "NOTE: Credential harvesting phishing email targeting admin_svc. "
                "Domain acme-support.com registered 7 days ago. "
                "Tactic=INITIAL_ACCESS(T1566.002)"
            ),
            is_critical=True,
            keywords=["email", "phishing", "credential_phishing", "credential", "spearphish"],
        ),
    ],
    threat_intel=[
        ThreatIntelEntry(
            ioc="45.33.32.100",
            ioc_type="ip",
            description=(
                "Known RDP brute-force source linked to Initial Access Brokers. "
                "GeoIP: Romania. ASN: AS9009 (M247). AbuseIPDB: 98% confidence, "
                "2341 reports. Previously sold compromised RDP credentials on dark web "
                "marketplace. Active in credential-based attacks since 2025."
            ),
            severity="critical",
            source="AbuseIPDB / CrowdStrike / DarkOwl",
            keywords=["45.33.32.100", "ip", "rdp", "brute_force", "initial_access"],
        ),
        ThreatIntelEntry(
            ioc="198.51.100.77",
            ioc_type="ip",
            description=(
                "Cobalt Strike C2 server. Associated with LockBit ransomware affiliate "
                "'LB-Affiliate-7'. First seen: 5 days ago. Hosting Cobalt Strike Team "
                "Server v4.9. SSL cert: self-signed, CN=update-svc.net. "
                "FS-ISAC reports same affiliate in 4 other attacks this week."
            ),
            severity="critical",
            source="CrowdStrike / FS-ISAC / Shodan",
            keywords=["198.51.100.77", "ip", "cobalt_strike", "c2", "lockbit"],
        ),
        ThreatIntelEntry(
            ioc="c2.update-svc.net",
            ioc_type="domain",
            description=(
                "Recently registered C2 domain for Cobalt Strike beacon. "
                "Registered 5 days ago via bulletproof registrar. "
                "WHOIS: privacy protected. NS: ns1.bulletproof-dns.com. "
                "SSL: Let's Encrypt, issued 4 days ago."
            ),
            severity="high",
            source="DomainTools / PassiveTotal",
            keywords=["c2.update-svc.net", "domain", "c2", "cobalt_strike"],
        ),
        ThreatIntelEntry(
            ioc="e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
            ioc_type="hash",
            description=(
                "LockBit 3.0 ransomware variant (locker.exe). "
                "VirusTotal: 52/72 detections. First submission: 2026-03-24. "
                "Encrypts files with AES-256, appends .locked extension. "
                "Drops README_RESTORE.txt ransom note with Bitcoin payment instructions. "
                "Anti-VM and anti-debug capabilities detected."
            ),
            severity="critical",
            source="VirusTotal / Hybrid Analysis / ANY.RUN",
            keywords=["hash", "lockbit", "ransomware", "locker.exe"],
        ),
    ],
    endpoints=[
        EndpointInfo(
            endpoint_id="EP-ADMIN",
            hostname="WS-ADMIN-PC",
            os="Windows 11 Enterprise 23H2",
            ip="10.1.20.5",
            status="ONLINE - COMPROMISED - COBALT STRIKE ACTIVE",
            processes=[
                "rundll32.exe -> C:\\temp\\update.dll [COBALT STRIKE BEACON]",
                "svchost.exe (PID:3201) [INJECTED - C2 COMMS]",
                "ADFind.exe [DISCOVERY TOOL]",
                "PsExec.exe [LATERAL MOVEMENT TOOL]",
            ],
            connections=[
                "HTTPS to 198.51.100.77:443 (Cobalt Strike C2 - ACTIVE)",
                "SMB to 10.1.10.11:445, 10.1.10.12:445, 10.1.10.13:445",
                "RDP from 45.33.32.100:3389 (External attacker)",
            ],
            files_modified=[
                "C:\\temp\\update.dll (Cobalt Strike beacon DLL)",
                "C:\\Windows\\Temp\\PsExec.exe (Sysinternals PsExec)",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-FILE01",
            hostname="SRV-FILE-01",
            os="Windows Server 2022",
            ip="10.1.10.11",
            status="ONLINE - ENCRYPTED - RANSOMWARE ACTIVE",
            processes=[
                "locker.exe (PID:7801) [RANSOMWARE - ENCRYPTING FILES]",
                "vssadmin.exe -> 'delete shadows /all' [SHADOW COPY DELETION]",
            ],
            connections=[
                "SMB from WS-ADMIN-PC (PsExec deployment)",
            ],
            files_modified=[
                "12,847 files encrypted (.locked extension)",
                "README_RESTORE.txt (ransom note) in every directory",
                "Volume Shadow Copies DELETED",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-APP02",
            hostname="SRV-APP-02",
            os="Windows Server 2022",
            ip="10.1.10.12",
            status="ONLINE - ENCRYPTED - RANSOMWARE ACTIVE",
            processes=[
                "locker.exe (PID:6502) [RANSOMWARE - ENCRYPTING FILES]",
            ],
            connections=[
                "SMB from WS-ADMIN-PC (PsExec deployment)",
            ],
            files_modified=[
                "8,391 files encrypted (.locked extension)",
                "README_RESTORE.txt in every directory",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-DB03",
            hostname="SRV-DB-03",
            os="Windows Server 2022",
            ip="10.1.10.13",
            status="ONLINE - ENCRYPTED - RANSOMWARE ACTIVE",
            processes=[
                "locker.exe (PID:5903) [RANSOMWARE - ENCRYPTING FILES]",
                "sqlservr.exe (DATABASE SERVICE - IMPACTED)",
            ],
            connections=[
                "SMB from WS-ADMIN-PC (PsExec deployment)",
            ],
            files_modified=[
                "5,672 files encrypted (.locked extension)",
                "Database files (.mdf, .ldf) ENCRYPTED",
            ],
            is_compromised=True,
        ),
    ],
    users=[
        UserProfile(
            user_id="admin_svc",
            display_name="Admin Service Account",
            department="IT Infrastructure",
            role="IT Service Account - Domain Admin",
            recent_logins=[
                "2026-03-26 03:05 - WS-ADMIN-PC from 45.33.32.100 [ANOMALOUS - EXTERNAL]",
                "2026-03-25 09:00 - IT-ADMIN-WS-01 (Normal - internal)",
                "2026-03-24 09:15 - IT-ADMIN-WS-01 (Normal - internal)",
            ],
            risk_score=0.98,
            notes=(
                "Domain Admin service account used by IT team. MFA disabled due to "
                "legacy exception for automated scripts. Password last changed: 2025-11-01. "
                "Has NEVER logged in from external IP before — always internal from "
                "IT-ADMIN-WS-01. External RDP access suggests credential compromise."
            ),
        ),
    ],
    correlation_findings=[
        (
            "CORRELATION: admin_svc has NEVER logged in from an external IP. "
            "All prior logins were from internal IT-ADMIN-WS-01 (10.1.20.10). "
            "The login from 45.33.32.100 (Romania) at 03:05 UTC is FIRST-TIME "
            "external access. Combined with 312 failed attempts, this confirms "
            "credential compromise via brute force."
        ),
        (
            "CORRELATION: 3 servers encrypted within a 7-minute window (03:22-03:22 UTC). "
            "PsExec deployment from WS-ADMIN-PC to all 3 servers in rapid succession. "
            "Cobalt Strike C2 domain registered same day as phishing email to admin_svc. "
            "Attack chain: Phish → Credential Harvest → RDP Brute Force → "
            "Cobalt Strike → Lateral Movement → Ransomware."
        ),
        (
            "CORRELATION: Same LockBit affiliate 'LB-Affiliate-7' observed in "
            "4 other attacks this week per FS-ISAC intelligence. Same C2 infrastructure "
            "(198.51.100.77) and same ransomware variant (locker.exe). "
            "Coordinated campaign targeting mid-size enterprises."
        ),
    ],
    critical_evidence={
        "rdp_bruteforce_external",
        "cobalt_strike_beacon",
        "lateral_movement_psexec",
        "ransomware_encryption",
        "c2_communication",
        "credential_phishing",
    },
    critical_iocs={
        "45.33.32.100",
        "198.51.100.77",
        "c2.update-svc.net",
        "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        "locker.exe",
    },
    report_keywords=[
        "ransomware", "lockbit", "cobalt_strike", "psexec",
        "lateral_movement", "encryption", "rdp", "credential",
        "critical", "isolate", "containment",
    ],
)

TASK_DEFINITION = {
    "name": "Ransomware Deployment & Encryption",
    "description": (
        "Investigate a ransomware attack with multiple encrypted servers. Trace the "
        "attack chain from initial credential phishing through RDP brute-force, "
        "Cobalt Strike C2 deployment, PsExec lateral movement, to coordinated "
        "LockBit ransomware encryption. Identify all IOCs and contain the threat "
        "across multiple hosts and attack infrastructure."
    ),
    "difficulty": "medium_hard",
    "expected_steps": "15-22",
    "key_skills": "Ransomware analysis, attack chain reconstruction, multi-host containment, C2 identification",
}
