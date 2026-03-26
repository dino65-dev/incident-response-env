# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Hard: Insider Threat
# BSD-3-Clause License

"""
Task 3: HARD - Insider Threat Disguised as Normal Activity

A DLP alert for a director uploading confidential data to personal
Google Drive. Agent must distinguish malicious exfiltration from
routine work by correlating behavioral anomalies.
"""

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
    from .base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory
    from tasks.base import EndpointInfo, LogEntry, Scenario, ThreatIntelEntry, UserProfile


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

TASK_DEFINITION = {
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
}
