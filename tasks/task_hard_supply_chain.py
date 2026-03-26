# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Hard-Plus: Supply Chain
# BSD-3-Clause License

"""
Task 5: HARD-PLUS - Software Supply Chain Compromise

A trusted internal build tool (BuildForge v3.2.1) pushed a compromised
update to developer workstations. The update contains a backdoor that
exfiltrates source code and injects a cryptominer. The compromised
package was signed with a stolen code-signing certificate.
"""

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
    from .base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory
    from tasks.base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile


SCENARIO_HARD_SUPPLY_CHAIN = Scenario(
    scenario_id="supply_chain_001",
    task_id="hard_plus",
    difficulty="hard_plus",
    alert_summary=(
        "ALERT [SIEM-2847]: Anomalous outbound traffic pattern detected from 8 developer "
        "workstations. DNS queries to unusual domains following BuildForge v3.2.1 update "
        "deployed 2026-03-24. CPU utilization spike (95%+) on affected hosts. BuildForge "
        "update hash does not match vendor's published hash."
    ),
    alert_source="SIEM Correlation Rule (Splunk)",
    alert_timestamp="2026-03-25T14:30:00Z",
    initial_observation=(
        "SIEM correlation rule triggered for anomalous traffic from multiple developer "
        "workstations following a software update. The BuildForge v3.2.1 update hash does "
        "not match the vendor's published hash, suggesting the update may have been "
        "tampered with. CPU spikes on affected hosts suggest unauthorized computation. "
        "This requires immediate investigation to determine if this is a supply chain "
        "compromise and assess the scope of potential data exfiltration."
    ),
    true_severity=Severity.CRITICAL,
    true_category=ThreatCategory.SUPPLY_CHAIN,
    required_containment=[
        ContainmentAction.ISOLATE_HOST,
        ContainmentAction.QUARANTINE_FILE,
        ContainmentAction.DISABLE_ACCOUNT,
        ContainmentAction.REVOKE_SESSIONS,
    ],
    containment_targets={
        "isolate_host": "WS-DEV-01",
        "quarantine_file": "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        "disable_account": "build-pipeline-svc",
        "revoke_sessions": "build-pipeline-svc",
    },
    correct_escalation="management",
    max_steps=30,
    # Multi-target containment pairs
    required_containment_pairs=[
        ("isolate_host", "WS-DEV-01"),
        ("quarantine_file", "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8"),
        ("disable_account", "build-pipeline-svc"),
        ("revoke_sessions", "build-pipeline-svc"),
    ],
    log_entries=[
        LogEntry(
            source="edr",
            content=(
                "[14:00:00Z] PROCESS_CREATE: Hosts=WS-DEV-01,WS-DEV-04,WS-DEV-07 (+5 others) "
                "Parent=BuildForge.exe -> Child=bf-helper.exe "
                "SHA256=f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8 "
                "NOTE: bf-helper.exe is NOT present in any prior BuildForge version. Binary was "
                "introduced in v3.2.1 update. Signed with cert serial NOT matching vendor's "
                "published certificates — possible stolen or forged code-signing cert. "
                "[14:02:00Z] PROCESS_CREATE: Host=WS-DEV-01 Parent=bf-helper.exe "
                "Child=git.exe CmdLine='git clone https://git.internal.acmecorp.com/core-algorithm.git' "
                "NOTE: bf-helper.exe cloning internal repos using embedded service token. "
                "Repos accessed: core-algorithm, customer-data-pipeline, encryption-key-mgmt. "
                "Tactic=COLLECTION(T1213)"
            ),
            is_critical=True,
            keywords=["edr", "bf_helper_backdoor", "buildforge", "process", "git", "code_exfiltration"],
        ),
        LogEntry(
            source="edr",
            content=(
                "[14:05:00Z] PROCESS_CREATE: Hosts=WS-DEV-01,WS-DEV-04,WS-DEV-07 (+5 others) "
                "Parent=bf-helper.exe -> Child=bf-optimizer.exe "
                "NOTE: bf-optimizer.exe is XMRig cryptominer disguised with BuildForge naming. "
                "CPU utilization spiked to 95%+ on all 8 affected hosts. "
                "Mining configuration: pool.supportxmr.com:3333 "
                "Wallet: 4BrL51JCc9NGQ71k... "
                "[14:08:00Z] ARCHIVE_CREATE: Host=WS-DEV-01 Process=bf-helper.exe "
                "Output=/tmp/telemetry-data-01.tar.gz Size=52MB "
                "Contents: cloned repository archives "
                "NOTE: Source code being packaged for exfiltration. "
                "Tactic=EXFILTRATION(T1567)"
            ),
            is_critical=True,
            keywords=["edr", "cryptominer_deployment", "xmrig", "mining", "exfiltration", "archive"],
        ),
        LogEntry(
            source="auth",
            content=(
                "[14:01:30Z] SERVICE_TOKEN_AUTH: Token_Owner=build-pipeline-svc "
                "Source=WS-DEV-01,WS-DEV-04,WS-DEV-07 (+5 others) "
                "Target=git.internal.acmecorp.com "
                "Repos_Accessed=['core-algorithm', 'customer-data-pipeline', "
                "'encryption-key-mgmt', 'payment-processing', 'ml-models'] "
                "NOTE: Service token embedded in bf-helper.exe binary. "
                "Token belongs to build-pipeline-svc (CI/CD service account). "
                "Token is valid but NOT authorized for these repos — "
                "authorized only for build-artifacts and release-binaries repos. "
                "Tactic=CREDENTIAL_ACCESS(T1552.001)"
            ),
            is_critical=True,
            keywords=["auth", "build_svc_token_misuse", "service_token", "git", "unauthorized"],
        ),
        LogEntry(
            source="proxy",
            content=(
                "[14:10:00Z] HTTPS_UPLOAD: Src=WS-DEV-01(10.1.30.11) "
                "Dst=api.telemetry-cdn.io:443 Method=POST "
                "Content_Type=application/octet-stream Size=52MB Duration=45s "
                "NOTE: Data exfiltration disguised as telemetry upload. "
                "7 similar uploads from other affected hosts (total: ~350MB). "
                "[14:05:30Z] TCP_CONN: Src=WS-DEV-01(10.1.30.11) "
                "Dst=pool.supportxmr.com:3333 Protocol=Stratum "
                "NOTE: Monero mining pool connection. Initially allowed, "
                "then blocked by updated firewall rule at 14:35."
            ),
            is_critical=True,
            keywords=["proxy", "code_exfiltration_telemetry", "telemetry", "upload", "mining", "exfiltration"],
        ),
        LogEntry(
            source="dns",
            content=(
                "[14:00:15Z] QUERY: Client=WS-DEV-01(10.1.30.11) "
                "Query=api.telemetry-cdn.io Type=A Response=104.21.45.67 TTL=300 "
                "NOTE: Domain registered 14 days ago. Cloudflare-fronted. "
                "No prior TI entries. WHOIS: privacy protected. "
                "[14:05:25Z] QUERY: Client=WS-DEV-01(10.1.30.11) "
                "Query=pool.supportxmr.com Type=A Response=51.15.56.164 "
                "NOTE: Known Monero mining pool. Not inherently malicious "
                "but strong indicator of cryptojacking when unexpected."
            ),
            is_critical=True,
            keywords=["dns", "telemetry", "newly_registered", "mining", "c2"],
        ),
        LogEntry(
            source="firewall",
            content=(
                "[14:10:00Z-14:30:00Z] ALLOW: Src=10.1.30.0/24(Dev-VLAN) "
                "Dst=104.21.45.67(api.telemetry-cdn.io) Port=443 "
                "Proto=TCP Rule=Outbound-HTTPS-Allow "
                "Total_Bytes_Out=350MB across 8 hosts "
                "NOTE: Outbound HTTPS allowed (categorized as CDN). "
                "[14:05:30Z] ALLOW→BLOCK: Src=10.1.30.0/24 "
                "Dst=51.15.56.164(pool.supportxmr.com) Port=3333 "
                "Proto=TCP Rule=Mining-Block (added 14:35) "
                "NOTE: Mining pool traffic initially allowed, blocked after rule update."
            ),
            is_critical=False,
            keywords=["firewall", "outbound", "exfiltration", "mining"],
        ),
        LogEntry(
            source="email",
            content=(
                "[2026-03-22 10:15:00Z] DELIVERED: From=buildforge-security@buildforge-updates.com "
                "To=build-team-lead@acmecorp.com "
                "Subject='CRITICAL: BuildForge Security Patch v3.2.1 - Immediate Action Required' "
                "Body_Preview='A critical vulnerability has been identified in BuildForge v3.2.0. "
                "Please apply the attached patch immediately. Download: https://buildforge-updates.com/patch...' "
                "SPF=FAIL DKIM=FAIL "
                "NOTE: Phishing email targeting build team lead. Domain buildforge-updates.com "
                "registered 10 days ago, NOT the official BuildForge domain. "
                "Likely vector for compromising build server or stealing signing key. "
                "Tactic=INITIAL_ACCESS(T1195.002)"
            ),
            is_critical=True,
            keywords=["email", "phishing_build_team", "phishing", "supply_chain", "buildforge"],
        ),
    ],
    threat_intel=[
        ThreatIntelEntry(
            ioc="telemetry-cdn.io",
            ioc_type="domain",
            description=(
                "Recently registered domain (14 days ago). Cloudflare-fronted. "
                "No prior threat intelligence entries. WHOIS: privacy protected. "
                "SSL certificate from Let's Encrypt. Used as data exfiltration "
                "endpoint disguised as telemetry service. First reported in this incident."
            ),
            severity="high",
            source="DomainTools / Internal Analysis",
            keywords=["telemetry-cdn.io", "domain", "exfiltration", "newly_registered"],
        ),
        ThreatIntelEntry(
            ioc="pool.supportxmr.com",
            ioc_type="domain",
            description=(
                "Known Monero mining pool operated by supportXMR. Not inherently "
                "malicious but used in cryptojacking campaigns. Commonly seen in "
                "supply chain attacks where miners are bundled with compromised software."
            ),
            severity="medium",
            source="Mining Pool Tracker / CrowdStrike",
            keywords=["pool.supportxmr.com", "domain", "mining", "monero", "cryptojacking"],
        ),
        ThreatIntelEntry(
            ioc="f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
            ioc_type="hash",
            description=(
                "bf-helper.exe: Backdoor component injected into BuildForge v3.2.1 update. "
                "VirusTotal: 28/72 detections. Capabilities: source code exfiltration via "
                "git clone, cryptominer deployment (XMRig), data staging and upload. "
                "Signed with cert serial 0x3A7F... which does NOT match BuildForge Inc's "
                "known code-signing certificates (stolen or forged cert). "
                "First submission: 2026-03-24."
            ),
            severity="critical",
            source="VirusTotal / Hybrid Analysis / Internal Cert Validation",
            keywords=["hash", "bf-helper", "backdoor", "supply_chain", "stolen_signing_cert"],
        ),
    ],
    endpoints=[
        EndpointInfo(
            endpoint_id="EP-DEV01",
            hostname="WS-DEV-01",
            os="Ubuntu 22.04 LTS",
            ip="10.1.30.11",
            status="ONLINE - COMPROMISED - BACKDOOR & CRYPTOMINER ACTIVE",
            processes=[
                "BuildForge.exe -> bf-helper.exe (PID:4501) [BACKDOOR]",
                "bf-helper.exe -> git (cloning internal repos) [EXFILTRATION]",
                "bf-optimizer.exe (PID:4502) [CRYPTOMINER - XMRig - CPU 95%]",
            ],
            connections=[
                "HTTPS to api.telemetry-cdn.io:443 (exfiltration)",
                "TCP to pool.supportxmr.com:3333 (mining)",
                "HTTPS to git.internal.acmecorp.com (repo cloning)",
            ],
            files_modified=[
                "/opt/buildforge/bin/bf-helper.exe (NEW - backdoor)",
                "/opt/buildforge/bin/bf-optimizer.exe (NEW - cryptominer)",
                "/tmp/telemetry-data-01.tar.gz (staged exfiltration archive)",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-DEV04",
            hostname="WS-DEV-04",
            os="Ubuntu 22.04 LTS",
            ip="10.1.30.14",
            status="ONLINE - COMPROMISED - SAME INDICATORS AS WS-DEV-01",
            processes=[
                "BuildForge.exe -> bf-helper.exe [BACKDOOR]",
                "bf-optimizer.exe [CRYPTOMINER - CPU 95%]",
            ],
            connections=[
                "HTTPS to api.telemetry-cdn.io:443",
                "TCP to pool.supportxmr.com:3333",
            ],
            files_modified=[
                "/opt/buildforge/bin/bf-helper.exe (backdoor)",
                "/opt/buildforge/bin/bf-optimizer.exe (cryptominer)",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-DEV07",
            hostname="WS-DEV-07",
            os="Ubuntu 22.04 LTS",
            ip="10.1.30.17",
            status="ONLINE - COMPROMISED - SAME INDICATORS",
            processes=[
                "BuildForge.exe -> bf-helper.exe [BACKDOOR]",
                "bf-optimizer.exe [CRYPTOMINER - CPU 95%]",
            ],
            connections=[
                "HTTPS to api.telemetry-cdn.io:443",
                "TCP to pool.supportxmr.com:3333",
            ],
            files_modified=[
                "/opt/buildforge/bin/bf-helper.exe (backdoor)",
                "/opt/buildforge/bin/bf-optimizer.exe (cryptominer)",
            ],
            is_compromised=True,
        ),
        EndpointInfo(
            endpoint_id="EP-BUILD01",
            hostname="BUILD-SRV-01",
            os="Ubuntu 22.04 LTS",
            ip="10.1.30.50",
            status="ONLINE - INVESTIGATION NEEDED - POSSIBLE COMPROMISED ORIGIN",
            processes=[
                "BuildForge-Server (build orchestration)",
                "nginx (package distribution)",
            ],
            connections=[
                "Internal connections from dev workstations",
            ],
            files_modified=[
                "/var/buildforge/packages/v3.2.1/BuildForge-3.2.1.pkg (HASH MISMATCH)",
            ],
            is_compromised=True,
        ),
    ],
    users=[
        UserProfile(
            user_id="build-pipeline-svc",
            display_name="Build Pipeline Service Account",
            department="Engineering - CI/CD",
            role="CI/CD Service Account",
            recent_logins=[
                "2026-03-25 14:01 - Multiple dev workstations (via embedded token) [ANOMALOUS]",
                "2026-03-24 02:00 - BUILD-SRV-01 (automated nightly build - normal)",
                "2026-03-23 02:00 - BUILD-SRV-01 (automated nightly build - normal)",
            ],
            risk_score=0.88,
            notes=(
                "CI/CD service account for automated builds. Token authorized for "
                "build-artifacts and release-binaries repos ONLY. Token found embedded "
                "in bf-helper.exe binary — unauthorized repo access detected. "
                "Token should be rotated immediately and scope audited."
            ),
        ),
        UserProfile(
            user_id="build-team-lead",
            display_name="Marcus Johnson",
            department="Engineering - DevOps",
            role="Build Team Lead",
            recent_logins=[
                "2026-03-25 08:30 - WS-DEV-MJOHNSON (Normal)",
                "2026-03-24 09:00 - WS-DEV-MJOHNSON (Normal)",
            ],
            risk_score=0.35,
            notes=(
                "Received phishing email from buildforge-updates.com on March 22. "
                "May have clicked the link, potentially compromising build server "
                "access credentials or code-signing key. Needs immediate interview."
            ),
        ),
    ],
    correlation_findings=[
        (
            "CORRELATION: All 8 affected hosts received BuildForge v3.2.1 update "
            "within the same 30-minute window (13:30-14:00 UTC). The update package "
            "hash on BUILD-SRV-01 does NOT match the vendor's published hash for v3.2.1. "
            "bf-helper.exe binary was injected into the package — not present in "
            "any previous BuildForge release."
        ),
        (
            "CORRELATION: Code-signing certificate used for the compromised update "
            "has serial 0x3A7F... which does NOT match BuildForge Inc's published "
            "certificates. The cert was issued to 'BuildForge Inc' but by a different "
            "CA than the vendor normally uses. Likely stolen or fraudulently obtained cert."
        ),
        (
            "CORRELATION: Internal Git repos accessed include critical IP: "
            "core-algorithm (proprietary ML models), customer-data-pipeline "
            "(PII handling), encryption-key-mgmt (crypto key management), and "
            "payment-processing (PCI-DSS scope). Total data exfiltrated: ~350MB "
            "of compressed source code to api.telemetry-cdn.io. "
            "This represents significant intellectual property and compliance risk."
        ),
    ],
    critical_evidence={
        "buildforge_hash_mismatch",
        "bf_helper_backdoor",
        "code_exfiltration_telemetry",
        "cryptominer_deployment",
        "stolen_signing_cert",
        "phishing_build_team",
        "build_svc_token_misuse",
    },
    critical_iocs={
        "telemetry-cdn.io",
        "pool.supportxmr.com",
        "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        "bf-helper.exe",
        "build-pipeline-svc",
    },
    report_keywords=[
        "supply_chain", "buildforge", "backdoor", "cryptominer",
        "exfiltration", "signing_certificate", "code_signing",
        "compromised_update", "critical",
    ],
)

TASK_DEFINITION = {
    "name": "Software Supply Chain Compromise",
    "description": (
        "Investigate a supply chain attack via a compromised build tool update. "
        "A trusted internal tool (BuildForge) distributed a backdoored update to "
        "developer workstations, exfiltrating source code and deploying a cryptominer. "
        "Identify the compromised package, trace the initial access vector, assess "
        "data exfiltration scope, and contain all affected systems."
    ),
    "difficulty": "hard_plus",
    "expected_steps": "18-26",
    "key_skills": "Supply chain analysis, code-signing verification, exfiltration detection, multi-host triage",
}
