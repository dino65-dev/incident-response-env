"""
Procedural Scenario Generator

Converts ScenarioGenome parameters into fully-realized Scenario objects
with realistic cybersecurity content (log entries, IOCs, endpoints, etc).

Uses template-based generation with parameterized complexity to ensure
scenarios are both varied and solvable.
"""

import hashlib
import logging
import random
from string import Formatter
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    from ..tasks.base import (
        EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
    )
    from ..models import ContainmentAction, Severity, ThreatCategory
except ImportError:
    import sys, os
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    from tasks.base import (
        EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
    )
    from models import ContainmentAction, Severity, ThreatCategory

try:
    from .evolution_engine import ScenarioGenome
except ImportError:
    from self_evolving.evolution_engine import ScenarioGenome


# ═══════════════════════════════════════════════════════════════════
# Content Templates (realistic cybersecurity data)
# ═══════════════════════════════════════════════════════════════════

ATTACK_TEMPLATES = {
    "phishing": {
        "categories": [ThreatCategory.PHISHING, ThreatCategory.MALWARE],
        "severities": [Severity.HIGH, Severity.MEDIUM],
        "alert_templates": [
            "Suspicious email with malicious attachment detected targeting {user}",
            "Spear phishing campaign detected - credential harvesting attempt on {user}",
            "Business email compromise attempt flagged by DLP - sender: {attacker_email}",
        ],
        "log_templates": {
            "email": [
                "Email received from {attacker_email} to {user}@corp.local - Subject: '{subject}' - Attachment: {filename}",
                "DMARC FAIL for sender domain {attacker_domain} - SPF: fail, DKIM: fail",
                "Attachment {filename} (SHA256: {file_hash}) downloaded by {user}",
            ],
            "edr": [
                "Process {proc_name} spawned by outlook.exe on {hostname} - PID: {pid}",
                "Suspicious DLL injection detected: {filename} loaded into {proc_name}",
                "Network beacon detected from {hostname} to {c2_ip}:{c2_port} every {interval}s",
            ],
            "proxy": [
                "HTTP POST to {c2_domain}/beacon - User-Agent: {ua} - Host: {hostname}",
                "Data upload detected: {hostname} -> {c2_ip} ({data_size}MB)",
                "SSL connection to known malicious domain: {c2_domain} from {hostname}",
            ],
            "auth": [
                "Successful login for {user} from {src_ip} at {timestamp}",
                "Failed login attempt for {user} - source: {src_ip} - {attempts} attempts",
            ],
            "firewall": [
                "ALLOW: {hostname}({src_ip}) -> {c2_ip}:443 (HTTPS) - {bytes} bytes",
                "BLOCK: {c2_ip} -> {hostname}:{port} (reverse shell attempt)",
            ],
            "dns": [
                "DNS query: {c2_domain} -> {c2_ip} from {hostname}",
                "Suspicious DNS TXT record query: {domain} from {hostname}",
            ],
        },
        "containment_actions": [
            (ContainmentAction.QUARANTINE_FILE, "{file_hash}"),
            (ContainmentAction.ISOLATE_HOST, "{hostname}"),
            (ContainmentAction.BLOCK_IP, "{c2_ip}"),
            (ContainmentAction.DISABLE_ACCOUNT, "{user}"),
        ],
        "escalation": "tier3",
        "report_keywords": ["phishing", "malicious attachment", "C2 beacon", "credential theft"],
    },
    "lateral_movement": {
        "categories": [ThreatCategory.LATERAL_MOVEMENT, ThreatCategory.BRUTE_FORCE],
        "severities": [Severity.CRITICAL, Severity.HIGH],
        "alert_templates": [
            "Multiple failed authentication attempts followed by lateral movement from {hostname}",
            "Credential stuffing attack detected - {attempts} failed logins then successful RDP to {target_host}",
            "Pass-the-hash attack detected: {user} authenticating across multiple systems",
        ],
        "log_templates": {
            "auth": [
                "Failed login: {user} from {src_ip} - {attempts} attempts in {window}min",
                "Successful login: {user} from {src_ip} after {failed_count} failures",
                "Kerberos TGT request: {user} from {hostname} - ticket type: {ticket_type}",
                "NTLM authentication: {user} from {src_ip} to {target_host}",
            ],
            "edr": [
                "PsExec.exe execution detected on {target_host} from {hostname}",
                "Mimikatz-like memory access detected on {hostname} - LSASS.exe read",
                "WMI remote execution: {hostname} -> {target_host} - command: {command}",
                "Credential dump detected: {hostname} - tool: {tool_name}",
            ],
            "firewall": [
                "ALLOW: {hostname}({src_ip}) -> {target_host}:3389 (RDP)",
                "ALLOW: {hostname} -> {target_host}:445 (SMB)",
                "Spike in traffic: {hostname} -> internal subnets ({connection_count} connections in {window}min)",
            ],
            "dns": [
                "DNS query: {target_host}.corp.local from {hostname}",
                "Internal DNS enumeration detected from {hostname} - {query_count} queries",
            ],
            "proxy": [
                "Internal proxy: {hostname} -> {target_host}:8080 ({data_size}MB transferred)",
            ],
            "email": [
                "No relevant email logs for this incident type",
            ],
        },
        "containment_actions": [
            (ContainmentAction.ISOLATE_HOST, "{hostname}"),
            (ContainmentAction.ISOLATE_HOST, "{target_host}"),
            (ContainmentAction.DISABLE_ACCOUNT, "{user}"),
            (ContainmentAction.REVOKE_SESSIONS, "{user}"),
            (ContainmentAction.BLOCK_IP, "{src_ip}"),
        ],
        "escalation": "tier3",
        "report_keywords": ["lateral movement", "credential theft", "brute force", "RDP", "privilege escalation"],
    },
    "insider_threat": {
        "categories": [ThreatCategory.INSIDER_THREAT, ThreatCategory.DATA_EXFILTRATION],
        "severities": [Severity.CRITICAL, Severity.HIGH],
        "alert_templates": [
            "Data exfiltration alert: {user} transferring sensitive files to external storage",
            "Insider threat indicator: {user} accessing files outside normal scope at unusual hours",
            "DLP alert: Bulk download of confidential documents by {user}",
        ],
        "log_templates": {
            "email": [
                "Email from {user}@corp.local to {ext_email} - {attachment_count} attachments ({total_size}MB)",
                "Email forwarding rule created by {user} to {ext_email}",
            ],
            "auth": [
                "Off-hours login: {user} at {timestamp} (normal hours: 9-17)",
                "VPN connection: {user} from {src_ip} ({geo_location})",
                "Privilege escalation: {user} added to {group_name} group",
            ],
            "edr": [
                "USB device connected: {device_name} on {hostname} - {user} session",
                "File copy to removable media: {file_count} files ({total_size}MB) by {user}",
                "Screen capture tool detected: {tool_name} on {hostname}",
            ],
            "proxy": [
                "Upload to {cloud_service}: {hostname} ({user}) - {data_size}MB",
                "Connection to file sharing site: {cloud_service} from {hostname}",
            ],
            "dns": [
                "DNS query: {cloud_service_domain} from {hostname}",
            ],
            "firewall": [
                "Outbound data transfer: {hostname} -> {ext_ip}:{port} ({data_size}MB)",
                "ALLOW: {hostname} -> {ext_ip}:443 (HTTPS to cloud storage)",
            ],
        },
        "containment_actions": [
            (ContainmentAction.DISABLE_ACCOUNT, "{user}"),
            (ContainmentAction.REVOKE_SESSIONS, "{user}"),
            (ContainmentAction.ISOLATE_HOST, "{hostname}"),
        ],
        "escalation": "management",
        "report_keywords": ["insider threat", "data exfiltration", "unauthorized access", "sensitive data"],
    },
    "ransomware": {
        "categories": [ThreatCategory.RANSOMWARE, ThreatCategory.MALWARE],
        "severities": [Severity.CRITICAL],
        "alert_templates": [
            "Ransomware activity detected: Mass file encryption on {target_host}",
            "File encryption alert: {file_count} files encrypted on {target_host} in {window} minutes",
            "Known ransomware variant {malware_name} detected on {hostname}",
        ],
        "log_templates": {
            "edr": [
                "Mass file modification: {file_count} files renamed to .{extension} on {target_host}",
                "Suspicious process: {proc_name} modifying files in {directory} on {target_host}",
                "Ransom note created: {ransom_file} in {directory} on {target_host}",
                "Shadow copy deletion: vssadmin.exe delete shadows on {target_host}",
            ],
            "auth": [
                "Service account {user} used to access {target_host} from {hostname}",
                "Failed RDP attempts: {hostname} -> {target_host} ({attempts} attempts)",
                "Successful authentication: {user} on {target_host} via {auth_method}",
            ],
            "firewall": [
                "ALLOW: {hostname} -> {c2_ip}:443 (C2 communication)",
                "ALLOW: {hostname} -> {target_host}:445 (SMB lateral movement)",
                "BLOCK: {target_host} -> {c2_ip}:{port} (ransom payment page)",
            ],
            "dns": [
                "DNS query: {c2_domain} from {hostname}",
                "DNS query: {ransom_domain}.onion.to from {target_host}",
            ],
            "proxy": [
                "TOR traffic detected from {target_host}",
                "HTTP GET to {c2_domain}/key - Encrypted payload received",
            ],
            "email": [
                "Phishing email to {user}: '{subject}' with malicious macro attachment",
            ],
        },
        "containment_actions": [
            (ContainmentAction.ISOLATE_HOST, "{hostname}"),
            (ContainmentAction.ISOLATE_HOST, "{target_host}"),
            (ContainmentAction.BLOCK_IP, "{c2_ip}"),
            (ContainmentAction.DISABLE_ACCOUNT, "{user}"),
            (ContainmentAction.QUARANTINE_FILE, "{file_hash}"),
        ],
        "escalation": "tier3",
        "report_keywords": ["ransomware", "encryption", "C2", "lateral movement", "shadow copies"],
    },
    "supply_chain": {
        "categories": [ThreatCategory.SUPPLY_CHAIN, ThreatCategory.MALWARE],
        "severities": [Severity.CRITICAL],
        "alert_templates": [
            "Supply chain compromise detected: Backdoor in {software_name} update",
            "Compromised third-party library {library_name} detected in production",
            "Suspicious code execution from auto-updated {software_name} package",
        ],
        "log_templates": {
            "edr": [
                "Code execution from {software_name} update: {proc_name} spawned {child_proc}",
                "Backdoor detected: {file_name} in {install_path} ({file_hash})",
                "Persistence mechanism: Registry key added by {proc_name} on {hostname}",
                "Memory injection detected: {proc_name} injected into {target_proc}",
            ],
            "dns": [
                "DNS query to staging server: {staging_domain} from {hostname}",
                "DNS tunneling detected: long subdomain queries to {c2_domain} from {hostname}",
            ],
            "firewall": [
                "ALLOW: {hostname} -> {c2_ip}:{port} (backdoor C2)",
                "ALLOW: {hostname} -> {staging_ip}:443 (data staging)",
            ],
            "proxy": [
                "HTTPS to {staging_domain}: {hostname} - Certificate mismatch detected",
                "Data upload: {hostname} -> {staging_domain} ({data_size}MB)",
            ],
            "auth": [
                "Service account {svc_account} created by {software_name} installer",
                "Elevated privileges: {svc_account} added to Administrators group on {hostname}",
            ],
            "email": [
                "Vendor notification email from {vendor_email} about update {version}",
            ],
        },
        "containment_actions": [
            (ContainmentAction.ISOLATE_HOST, "{hostname}"),
            (ContainmentAction.QUARANTINE_FILE, "{file_hash}"),
            (ContainmentAction.BLOCK_IP, "{c2_ip}"),
            (ContainmentAction.DISABLE_ACCOUNT, "{svc_account}"),
        ],
        "escalation": "management",
        "report_keywords": ["supply chain", "backdoor", "compromise", "third-party", "update"],
    },
    "apt_zeroday": {
        "categories": [ThreatCategory.APT_ZERO_DAY],
        "severities": [Severity.CRITICAL],
        "alert_templates": [
            "APT activity detected: Zero-day exploit in {software_name} targeting {target_host}",
            "Advanced persistent threat: Multi-stage attack with unknown exploit on {hostname}",
            "Sophisticated attack chain: {exploit_name} vulnerability exploitation with DNS tunneling",
        ],
        "log_templates": {
            "edr": [
                "Zero-day exploit: Buffer overflow in {software_name} on {target_host} (CVE pending)",
                "Post-exploitation: {tool_name} dropped in {directory} on {target_host}",
                "Living-off-the-land: {proc_name} executing encoded PowerShell on {hostname}",
                "DCSync attack detected: {user} replicating AD credentials from {dc_host}",
                "Keylogger installed: {file_name} injected into {target_proc} on {hostname}",
            ],
            "dns": [
                "DNS tunneling: {subdomain}.{c2_domain} from {hostname} ({query_count} queries/hr)",
                "DNS C2 channel: TXT record responses from {c2_domain} to {hostname}",
                "Fast-flux DNS detected: {c2_domain} resolving to {ip_count} IPs",
            ],
            "auth": [
                "Golden ticket detected: Kerberos ticket for {user} with suspicious lifetime",
                "Admin account compromise: {admin_user} authenticating from {attacker_ip}",
                "Privilege escalation: {user} -> {admin_user} via {technique}",
            ],
            "firewall": [
                "ALLOW: {hostname} -> {c2_ip}:{port} (encrypted C2)",
                "Covert channel: {hostname} -> {c2_ip} via ICMP (data embedded in payload)",
                "Suspicious outbound: {target_host} -> {exfil_ip}:53 ({data_size}MB via DNS)",
            ],
            "proxy": [
                "Encrypted traffic anomaly: {hostname} -> {c2_ip} ({data_size}MB, high entropy)",
                "Certificate pinning bypass detected from {hostname} to {c2_domain}",
            ],
            "email": [
                "Initial access: Spear phishing to {user} from {attacker_email} with zero-day PDF",
            ],
        },
        "containment_actions": [
            (ContainmentAction.ISOLATE_HOST, "{hostname}"),
            (ContainmentAction.ISOLATE_HOST, "{target_host}"),
            (ContainmentAction.BLOCK_IP, "{c2_ip}"),
            (ContainmentAction.DISABLE_ACCOUNT, "{user}"),
            (ContainmentAction.DISABLE_ACCOUNT, "{admin_user}"),
            (ContainmentAction.QUARANTINE_FILE, "{file_hash}"),
        ],
        "escalation": "legal",
        "report_keywords": ["APT", "zero-day", "DNS tunneling", "DCSync", "advanced persistent threat"],
    },
}

# Random data pools for filling templates
IP_POOL = [
    "185.220.101.42", "203.0.113.50", "198.51.100.23", "192.0.2.100",
    "45.33.32.156", "94.102.49.190", "195.123.237.18", "104.248.29.53",
    "64.225.8.203", "161.35.38.117", "178.128.83.12", "134.209.76.34",
    "159.89.115.241", "167.172.182.15", "142.93.118.76", "68.183.44.143",
    "10.50.25.101", "10.50.25.102", "10.50.25.103", "10.50.25.104",
]
DOMAIN_POOL = [
    "malware-cdn.evil.com", "secure-update.net", "cdn-analytics.cloud",
    "api-sync.services", "update-service.io", "data-backup.cloud",
    "metrics-relay.net", "auth-verify.cloud", "cloud-sync.services",
    "cdn-static.cloud", "api-gateway.services", "log-collector.net",
]
HOSTNAME_POOL = [
    "WS-USER01-PC", "WS-ADMIN-PC", "SRV-DC-01", "SRV-FILE-01",
    "SRV-WEB-01", "SRV-DB-01", "WS-DEV-PC", "SRV-APP-01",
    "SRV-MAIL-01", "WS-FINANCE-PC", "SRV-BACKUP-01", "SRV-DNS-01",
]
USERNAME_POOL = [
    "jsmith", "agarcia", "mbrown", "klee", "tnguyen",
    "dwilson", "schen", "rjohnson", "lpatel", "mkim",
    "svc_backup", "svc_deploy", "admin_ops", "svc_monitor",
]
HASH_POOL = [
    "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1",
    "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
]
FILENAMES = [
    "svchost_update.exe", "chrome_helper.dll", "sys32_patch.bin",
    "update_agent.ps1", "backup_tool.py", "report.xlsm",
    "invoice_Q4.docm", "driver_update.exe", "monitoring_agent.dll",
]


class ScenarioGenerator:
    """
    Procedural scenario generator that converts genome parameters
    into fully-realized Scenario objects.
    """

    # Semantic keyword mapping: content patterns → evidence-compatible keywords
    # These MUST match keywords recognized by keyword_to_evidence in the environment
    SEMANTIC_KEYWORD_MAP = {
        # Phishing keywords
        "spf": ["spf", "dmarc", "dkim"],
        "dkim": ["dkim", "spf", "dmarc"],
        "dmarc": ["dmarc", "spf"],
        "macro": ["macro", "vba"],
        "powershell": ["powershell"],
        "c2": ["c2", "c2_communication", "beacon"],
        "beacon": ["beacon", "c2"],
        "malware": ["dropped", "executable"],
        "outlook": ["macro"],
        # Lateral movement keywords
        "brute_force": ["brute_force"],
        "rdp": ["rdp", "lateral", "lateral_movement"],
        "psexec": ["psexec", "lateral_movement_psexec"],
        "mimikatz": ["credential", "ntds"],
        "lsass": ["credential"],
        "ntlm": ["credential"],
        "kerberos": ["kerberos", "golden_ticket"],
        "golden_ticket": ["golden_ticket", "kerberos"],
        "smb": ["lateral", "lateral_movement"],
        "wmi": ["lateral_movement"],
        # Insider threat keywords
        "dlp": ["dlp", "confidential"],
        "off-hours": ["after_hours"],
        "usb": ["anomalous", "bulk_download"],
        "bulk": ["bulk_download", "anomalous"],
        "upload": ["upload", "exfiltration"],
        "exfiltrat": ["exfiltration", "data_transfer"],
        "transfer": ["data_transfer", "volume"],
        # Ransomware keywords
        "encrypt": ["ransomware_encryption", "ransomware"],
        "ransom": ["ransomware_encryption", "ransomware"],
        "shadow cop": ["ransomware_encryption"],
        "vssadmin": ["ransomware_encryption"],
        "cobalt strike": ["cobalt_strike_beacon", "cobalt_strike"],
        # Supply chain keywords
        "backdoor": ["bf_helper_backdoor"],
        "hash mismatch": ["buildforge"],
        "supply chain": ["supply_chain", "buildforge"],
        "cryptominer": ["cryptominer_deployment", "xmrig"],
        "xmrig": ["xmrig", "cryptominer_deployment"],
        "signing cert": ["stolen_signing_cert"],
        "service account": ["build_svc_token_misuse", "service_token"],
        # APT keywords
        "dns tunnel": ["dns_tunneling_c2", "dns_tunneling"],
        "zero-day": ["zero_day_confluence_exploit", "zero_day"],
        "zero_day": ["zero_day_confluence_exploit", "zero_day"],
        "confluence": ["confluence", "zero_day_confluence_exploit"],
        "fileless": ["fileless_implant", "fileless"],
        "dcsync": ["dcsync_credential_theft", "dcsync"],
        "living-off-the-land": ["fileless_implant"],
    }

    def __init__(self, seed: Optional[int] = None):
        # Bug G fix: use a LOCAL Random instance to avoid corrupting global state
        self._rng = random.Random(seed)

    def generate(self, genome: ScenarioGenome, seed: Optional[int] = None) -> Scenario:
        """
        Generate a complete Scenario from a ScenarioGenome.

        The genome's parameters control:
        - Number and complexity of evidence items
        - Number of IOCs and their types
        - Network topology (endpoints, users)
        - Time pressure (max_steps vs required actions)
        - Noise level (decoy/irrelevant evidence)
        """
        # Bug J fix: seed with genome_id hash for deterministic content per-genome
        # This prevents Elo corruption from non-deterministic regeneration
        if seed is not None:
            self._rng = random.Random(seed)
        else:
            # Use genome_id as seed for reproducibility
            genome_seed = int(hashlib.md5(genome.genome_id.encode()).hexdigest()[:8], 16)
            self._rng = random.Random(genome_seed)

        # Select attack type based on difficulty
        attack_type = self._select_attack_type(genome)
        template = ATTACK_TEMPLATES[attack_type]

        # Generate scenario variables
        variables = self._generate_variables(genome)

        # Build scenario components
        severity = self._select_severity(genome, template)
        category = self._rng.choice(template["categories"])

        # Bug H fix: pre-compute max achievable critical entries to prevent
        # declaring more than we can actually generate. Count available templates.
        sources = ["email", "edr", "auth", "proxy", "firewall", "dns"]
        max_possible_critical = 0
        for source in sources:
            if source in template["log_templates"]:
                n_per_source = max(1, genome.num_log_entries // len(sources))
                max_possible_critical += min(n_per_source, len(template["log_templates"][source]))
        effective_num_critical = min(genome.num_critical_evidence, max_possible_critical)

        log_entries = self._generate_logs(genome, template, variables, effective_num_critical)
        threat_intel = self._generate_threat_intel(genome, variables)
        endpoints = self._generate_endpoints(genome, variables)
        users = self._generate_users(genome, variables)
        correlations = self._generate_correlations(genome, variables)
        containment = self._generate_containment(genome, template, variables)

        # Determine difficulty label
        diff = genome.aggregate_difficulty
        if diff < 0.2:
            difficulty = "easy"
            task_id = f"evolved_easy_{genome.genome_id}"
        elif diff < 0.4:
            difficulty = "medium"
            task_id = f"evolved_medium_{genome.genome_id}"
        elif diff < 0.6:
            difficulty = "medium_hard"
            task_id = f"evolved_medhard_{genome.genome_id}"
        elif diff < 0.8:
            difficulty = "hard"
            task_id = f"evolved_hard_{genome.genome_id}"
        else:
            difficulty = "expert"
            task_id = f"evolved_expert_{genome.genome_id}"

        # Build alert summary
        alert_summary = self._rng.choice(template["alert_templates"]).format(**variables)

        # Determine critical evidence and IOCs
        critical_evidence = set()
        critical_iocs = set()
        for entry in log_entries:
            if entry.is_critical:
                for kw in entry.keywords:
                    critical_evidence.add(kw)
        for ti in threat_intel:
            # Bug I fix: normalize to lowercase to prevent case mismatches
            critical_iocs.add(ti.ioc.lower())

        # Build containment pairs
        containment_actions = []
        containment_targets = {}
        required_containment_pairs = []
        for action, target in containment:
            containment_actions.append(action)
            containment_targets[action.value] = target
            required_containment_pairs.append((action.value, target))

        scenario = Scenario(
            scenario_id=f"evolved_{genome.genome_id}",
            task_id=task_id,
            difficulty=difficulty,
            alert_summary=alert_summary,
            alert_source="SOC-SIEM-EVOLVED",
            alert_timestamp="2026-03-28T10:00:00Z",
            initial_observation=f"[Evolved Scenario Gen-{genome.generation}] {alert_summary}. Begin investigation.",
            true_severity=severity,
            true_category=category,
            required_containment=containment_actions,
            containment_targets=containment_targets,
            is_false_positive=False,
            correct_escalation=template.get("escalation"),
            log_entries=log_entries,
            threat_intel=threat_intel,
            endpoints=endpoints,
            users=users,
            correlation_findings=correlations,
            critical_evidence=critical_evidence,
            critical_iocs=critical_iocs,
            max_steps=genome.max_steps,
            report_keywords=template["report_keywords"],
            required_containment_pairs=required_containment_pairs,
        )

        return scenario

    def _select_attack_type(self, genome: ScenarioGenome) -> str:
        """Select attack type based on difficulty."""
        diff = genome.aggregate_difficulty
        if diff < 0.25:
            weights = {"phishing": 5, "lateral_movement": 2, "insider_threat": 1,
                       "ransomware": 0, "supply_chain": 0, "apt_zeroday": 0}
        elif diff < 0.5:
            weights = {"phishing": 2, "lateral_movement": 4, "insider_threat": 3,
                       "ransomware": 2, "supply_chain": 1, "apt_zeroday": 0}
        elif diff < 0.75:
            weights = {"phishing": 1, "lateral_movement": 2, "insider_threat": 2,
                       "ransomware": 4, "supply_chain": 3, "apt_zeroday": 1}
        else:
            weights = {"phishing": 0, "lateral_movement": 1, "insider_threat": 1,
                       "ransomware": 2, "supply_chain": 3, "apt_zeroday": 5}

        types = list(weights.keys())
        w = [weights[t] for t in types]
        return self._rng.choices(types, weights=w, k=1)[0]

    def _generate_variables(self, genome: ScenarioGenome) -> Dict[str, str]:
        """Generate random scenario variables."""
        hostnames = self._rng.sample(HOSTNAME_POOL, min(genome.num_endpoints + 2, len(HOSTNAME_POOL)))
        ips = self._rng.sample(IP_POOL, min(genome.num_endpoints + 4, len(IP_POOL)))
        users = self._rng.sample(USERNAME_POOL, min(genome.num_users + 2, len(USERNAME_POOL)))

        return {
            "hostname": hostnames[0],
            "target_host": hostnames[1] if len(hostnames) > 1 else hostnames[0],
            "dc_host": "SRV-DC-01",
            "user": users[0],
            "admin_user": users[1] if len(users) > 1 else "admin_ops",
            "svc_account": f"svc_{self._rng.choice(['deploy', 'backup', 'monitor', 'update'])}",
            "src_ip": ips[0],
            "c2_ip": self._rng.choice(IP_POOL[:10]),  # External IPs
            "ext_ip": self._rng.choice(IP_POOL[:10]),
            "attacker_ip": self._rng.choice(IP_POOL[:10]),
            "exfil_ip": self._rng.choice(IP_POOL[:10]),
            "staging_ip": self._rng.choice(IP_POOL[:10]),
            "c2_domain": self._rng.choice(DOMAIN_POOL),
            "staging_domain": self._rng.choice(DOMAIN_POOL),
            "attacker_domain": self._rng.choice(DOMAIN_POOL),
            "c2_port": str(self._rng.choice([443, 8443, 4444, 9090, 8080])),
            "port": str(self._rng.choice([443, 445, 3389, 22, 8080])),
            "file_hash": self._rng.choice(HASH_POOL),
            "filename": self._rng.choice(FILENAMES),
            "file_name": self._rng.choice(FILENAMES),
            "proc_name": self._rng.choice(["svchost.exe", "rundll32.exe", "powershell.exe", "cmd.exe"]),
            "child_proc": self._rng.choice(["cmd.exe", "powershell.exe", "certutil.exe"]),
            "target_proc": self._rng.choice(["explorer.exe", "lsass.exe", "svchost.exe"]),
            "tool_name": self._rng.choice(["Cobalt Strike", "Mimikatz", "BloodHound", "PsExec"]),
            "pid": str(self._rng.randint(1000, 65535)),
            "interval": str(self._rng.choice([30, 60, 120, 300])),
            "attempts": str(self._rng.randint(5, 500)),
            "failed_count": str(self._rng.randint(3, 20)),
            "window": str(self._rng.choice([5, 10, 15, 30])),
            "data_size": str(round(self._rng.uniform(0.5, 500), 1)),
            "total_size": str(round(self._rng.uniform(10, 1000), 1)),
            "bytes": str(self._rng.randint(1024, 10485760)),
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "timestamp": "2026-03-28T" + f"{self._rng.randint(0,23):02d}:{self._rng.randint(0,59):02d}:00Z",
            "subject": self._rng.choice([
                "Urgent: Invoice Payment Required",
                "Action Required: Account Verification",
                "Q4 Financial Report - Confidential",
                "Password Reset Request",
                "IT Security Update - Please Install",
            ]),
            "attacker_email": f"attacker_{self._rng.randint(100,999)}@{self._rng.choice(DOMAIN_POOL)}",
            "ext_email": f"external_{self._rng.randint(100,999)}@gmail.com",
            "vendor_email": f"updates@vendor-{self._rng.randint(1,99)}.com",
            "device_name": self._rng.choice(["USB_Drive_SanDisk", "External_HDD_WD", "USB_Kingston_128GB"]),
            "cloud_service": self._rng.choice(["Dropbox", "Google Drive", "OneDrive", "Mega.nz"]),
            "cloud_service_domain": self._rng.choice(["dropbox.com", "drive.google.com", "onedrive.live.com"]),
            "group_name": self._rng.choice(["Domain Admins", "Backup Operators", "Enterprise Admins"]),
            "geo_location": self._rng.choice(["Moscow, RU", "Beijing, CN", "Unknown VPN", "São Paulo, BR"]),
            "software_name": self._rng.choice(["SolarUpdate", "NetMonitor Pro", "CloudSync Agent", "DevPipeline"]),
            "library_name": self._rng.choice(["node-ipc", "ua-parser-js", "event-stream", "coa"]),
            "version": f"v{self._rng.randint(1,5)}.{self._rng.randint(0,9)}.{self._rng.randint(0,99)}",
            "install_path": self._rng.choice(["C:\\Program Files\\", "C:\\Windows\\System32\\", "/opt/", "/usr/local/bin/"]),
            "exploit_name": self._rng.choice(["CVE-2026-XXXX", "Log4Shell-variant", "ProxyNotShell", "ZeroLogon-v2"]),
            "malware_name": self._rng.choice(["LockBit 4.0", "BlackCat v3", "REvil-NG", "DarkSide-X"]),
            "extension": self._rng.choice(["locked", "encrypted", "crypt", "ransom"]),
            "ransom_file": "README_DECRYPT.txt",
            "ransom_domain": f"ransom-{self._rng.randint(1000,9999)}",
            "directory": self._rng.choice(["C:\\Users\\", "D:\\Shares\\Finance\\", "C:\\Data\\", "/home/"]),
            "file_count": str(self._rng.randint(100, 50000)),
            "attachment_count": str(self._rng.randint(1, 10)),
            "auth_method": self._rng.choice(["RDP", "SMB", "WinRM", "NTLM"]),
            "ticket_type": self._rng.choice(["TGT", "TGS", "golden_ticket"]),
            "command": self._rng.choice(["whoami", "net user /domain", "ipconfig /all", "systeminfo"]),
            "connection_count": str(self._rng.randint(20, 200)),
            "query_count": str(self._rng.randint(50, 5000)),
            "ip_count": str(self._rng.randint(5, 50)),
            "technique": self._rng.choice(["token impersonation", "DLL hijacking", "service account abuse"]),
            "domain": self._rng.choice(DOMAIN_POOL),
            "subdomain": f"{''.join(self._rng.choices('abcdef0123456789', k=32))}",
        }

    def _generate_logs(
        self, genome: ScenarioGenome, template: Dict, variables: Dict,
        num_critical: Optional[int] = None,
    ) -> List[LogEntry]:
        """Generate log entries with appropriate noise and critical evidence."""
        entries = []
        critical_entries = []
        non_critical_entries = []
        sources = ["email", "edr", "auth", "proxy", "firewall", "dns"]

        # Bug H: use clamped critical count
        target_critical = num_critical if num_critical is not None else genome.num_critical_evidence

        # Generate critical entries from template
        critical_count = 0
        for source in sources:
            if source not in template["log_templates"]:
                continue
            source_templates = template["log_templates"][source]

            # Number of entries per source
            n = max(1, genome.num_log_entries // len(sources))

            for i in range(min(n, len(source_templates))):
                tmpl = source_templates[i % len(source_templates)]
                # Bug P fix: safe format with missing-var handling
                content = self._safe_format(tmpl, variables)

                is_crit = critical_count < target_critical
                keywords = self._extract_keywords(content, variables)

                entry = LogEntry(
                    source=source,
                    content=content,
                    is_critical=is_crit,
                    keywords=keywords,
                )
                if is_crit:
                    critical_entries.append(entry)
                    critical_count += 1
                else:
                    non_critical_entries.append(entry)

        # Bug M fix: base noise count on num_log_entries (genome param)
        # not on len(entries) which couples noise to critical count
        noise_count = int(genome.num_log_entries * genome.noise_ratio)
        for _ in range(noise_count):
            source = self._rng.choice(sources)
            non_critical_entries.append(LogEntry(
                source=source,
                content=f"[BENIGN] Routine {source} activity - {self._rng.choice(['scan', 'update', 'backup', 'maintenance'])} completed successfully",
                is_critical=False,
                keywords=["benign", "routine"],
            ))

        # Bug L fix: use evidence_obscurity to position critical entries
        # High obscurity = critical entries buried deep, low = early
        self._rng.shuffle(non_critical_entries)
        self._rng.shuffle(critical_entries)
        total_non_crit = len(non_critical_entries)

        if total_non_crit == 0 or not critical_entries:
            # Degenerate case: just concatenate
            entries = critical_entries + non_critical_entries
        else:
            entries = list(non_critical_entries)  # Start with non-critical
            # evidence_obscurity 0.0 = insert at front, 1.0 = insert at end
            obscurity = genome.evidence_obscurity
            for idx, crit_entry in enumerate(critical_entries):
                # Distribute critical entries around the obscurity position
                base_pos = int(obscurity * len(entries))
                # Add small jitter so they're not all at the same index
                jitter = self._rng.randint(-1, 1)
                insert_pos = max(0, min(len(entries), base_pos + jitter))
                entries.insert(insert_pos, crit_entry)

        return entries

    def _generate_threat_intel(
        self, genome: ScenarioGenome, variables: Dict
    ) -> List[ThreatIntelEntry]:
        """Generate threat intelligence entries."""
        entries = []
        ioc_sources = [
            (variables.get("c2_ip", ""), "ip", "Known C2 server", "critical"),
            (variables.get("file_hash", ""), "hash", "Known malware hash", "high"),
            (variables.get("c2_domain", ""), "domain", "Malicious domain", "high"),
            (variables.get("attacker_email", ""), "email", "Phishing sender", "medium"),
            (variables.get("attacker_ip", variables.get("src_ip", "")), "ip", "Attack source", "medium"),
        ]

        for ioc, ioc_type, desc, sev in ioc_sources[:genome.num_threat_intel]:
            if ioc:
                entries.append(ThreatIntelEntry(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    description=f"{desc} associated with current campaign",
                    severity=sev,
                    source=self._rng.choice(["VirusTotal", "AlienVault OTX", "IBM X-Force", "Mandiant"]),
                    keywords=[ioc.lower(), ioc_type],
                ))

        return entries

    def _generate_endpoints(
        self, genome: ScenarioGenome, variables: Dict
    ) -> List[EndpointInfo]:
        """Generate endpoint information."""
        endpoints = []
        hostnames = [variables.get("hostname", "WS-01"), variables.get("target_host", "SRV-01")]
        hostnames.extend(self._rng.sample(HOSTNAME_POOL, min(genome.num_endpoints, len(HOSTNAME_POOL))))

        for i, host in enumerate(hostnames[:genome.num_endpoints]):
            ip = variables.get("src_ip", "10.0.0.1") if i == 0 else f"10.50.25.{100+i}"
            endpoints.append(EndpointInfo(
                endpoint_id=host,
                hostname=host,
                os=self._rng.choice(["Windows Server 2022", "Windows 11 Pro", "Ubuntu 22.04"]),
                ip=ip,
                status="compromised" if i < 2 else "active",
                processes=[variables.get("proc_name", "svchost.exe")] if i < 2 else [],
                connections=[f"-> {variables.get('c2_ip', '1.2.3.4')}:443"] if i == 0 else [],
                is_compromised=i < 2,
            ))

        return endpoints

    def _generate_users(
        self, genome: ScenarioGenome, variables: Dict
    ) -> List[UserProfile]:
        """Generate user profiles."""
        users = []
        usernames = [variables.get("user", "jsmith")]
        if genome.num_users > 1:
            usernames.append(variables.get("admin_user", "admin"))
        usernames.extend(self._rng.sample(USERNAME_POOL, min(genome.num_users, len(USERNAME_POOL))))

        for i, uid in enumerate(usernames[:genome.num_users]):
            users.append(UserProfile(
                user_id=uid,
                display_name=uid.replace("_", " ").title(),
                department=self._rng.choice(["IT", "Finance", "Engineering", "Operations", "HR"]),
                role=self._rng.choice(["Analyst", "Engineer", "Manager", "Admin", "Developer"]),
                risk_score=0.8 if i == 0 else self._rng.uniform(0.1, 0.5),
                notes="Primary suspect" if i == 0 else "",
            ))

        return users

    def _generate_correlations(
        self, genome: ScenarioGenome, variables: Dict
    ) -> List[str]:
        """Generate event correlations."""
        correlations = [
            f"Timeline correlation: Initial compromise at {variables.get('hostname', 'HOST')} "
            f"followed by lateral movement to {variables.get('target_host', 'TARGET')}",
            f"Network correlation: C2 traffic from {variables.get('hostname', 'HOST')} "
            f"to {variables.get('c2_ip', 'C2_IP')} matches known threat pattern",
        ]

        if genome.correlation_depth >= 3:
            correlations.append(
                f"Credential correlation: Compromised user {variables.get('user', 'USER')} "
                f"was the initial access vector via {variables.get('attacker_email', 'EMAIL')}"
            )
        if genome.correlation_depth >= 4:
            correlations.append(
                f"Data flow correlation: {variables.get('data_size', '0')}MB exfiltrated "
                f"from {variables.get('target_host', 'TARGET')} to {variables.get('c2_ip', 'C2_IP')}"
            )

        return correlations[:genome.correlation_depth]

    def _generate_containment(
        self, genome: ScenarioGenome, template: Dict, variables: Dict
    ) -> List[Tuple[ContainmentAction, str]]:
        """Generate containment actions with targets."""
        containment = []
        for action, target_template in template["containment_actions"][:genome.num_containment_targets]:
            try:
                target = target_template.format(**variables)
            except (KeyError, IndexError):
                target = target_template
            containment.append((action, target))

        return containment

    def _select_severity(self, genome: ScenarioGenome, template: Dict) -> Severity:
        """
        Select severity based on difficulty AND template.

        Bug K/R fix: previously forced CRITICAL for diff>0.6 regardless of
        template, teaching agents 'hard = CRITICAL' as a shortcut.
        Now uses template's severity range with difficulty-weighted probability.
        """
        severities = template["severities"]
        if len(severities) == 1:
            return severities[0]

        diff = genome.aggregate_difficulty
        # Weight toward higher severity as difficulty increases
        # but never force — the agent must learn from evidence
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        available = [s for s in severity_order if s in severities]
        if not available:
            return self._rng.choice(severities)

        # Higher diff = bias toward the last (most severe) option
        weights = []
        for i, s in enumerate(available):
            # Exponential weight toward severe end based on difficulty
            w = (1.0 - diff) if i == 0 else diff ** (i / max(1, len(available) - 1))
            weights.append(max(0.05, w))  # Floor so nothing has zero weight

        return self._rng.choices(available, weights=weights, k=1)[0]

    @staticmethod
    def _safe_format(template_str: str, variables: Dict) -> str:
        """
        Bug P fix: Safe string format that replaces missing keys with '?'
        instead of silently returning the raw template string.
        """
        try:
            return template_str.format(**variables)
        except (KeyError, IndexError) as e:
            # Fall back to partial format — replace known keys, leave unknown as '?'
            logger.warning(f"Template format partial failure: {e} in '{template_str[:60]}...'")
            result = template_str
            for key, val in variables.items():
                result = result.replace(f"{{{key}}}", str(val))
            # Replace any remaining {xxx} with ?
            import re
            result = re.sub(r'\{[^}]+\}', '?', result)
            return result

    def _extract_keywords(self, content: str, variables: Dict) -> List[str]:
        """
        Extract SEMANTIC keywords from log content that are compatible
        with keyword_to_evidence in the environment.

        Bug F fix: previous version returned variable VALUES (IPs, hostnames)
        which never matched any keyword_to_evidence entry, making evolved
        scenarios impossible to solve.
        """
        keywords = []
        content_lower = content.lower()

        # Match semantic patterns → evidence-compatible keywords
        for pattern, kws in self.SEMANTIC_KEYWORD_MAP.items():
            if pattern in content_lower:
                keywords.extend(kws)

        # Also include variable values for IOC matching (secondary)
        for key in ["c2_ip", "file_hash", "c2_domain", "src_ip",
                     "attacker_email", "hostname", "target_host"]:
            val = variables.get(key, "")
            if val and val.lower() in content_lower:
                keywords.append(val.lower())

        # Deduplicate while preserving order
        seen = set()
        unique_kws = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                unique_kws.append(kw)
        return unique_kws
