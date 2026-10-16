"""Organizational catalog for the synthetic enterprise."""
from __future__ import annotations

DEPARTMENTS: list[dict[str, str]] = [
    {"id": "data", "name": "Data Platform"},
    {"id": "ml", "name": "Machine Learning"},
    {"id": "finance", "name": "Finance"},
    {"id": "security", "name": "Security"},
    {"id": "platform", "name": "Platform Engineering"},
    {"id": "support", "name": "Customer Operations"},
    {"id": "research", "name": "Research"},
    {"id": "it", "name": "Corporate IT"},
]

# 25 slots per department → 200 resources.
KIND_CYCLE: list[tuple[str, str]] = [
    ("store", "low"),
    ("store", "medium"),
    ("warehouse", "high"),
    ("warehouse", "critical"),
    ("orch", "medium"),
    ("model", "medium"),
    ("secret", "critical"),
    ("iam", "critical"),
    ("billing", "high"),
    ("ticket", "low"),
    ("host", "high"),
    ("log", "medium"),
    ("key", "critical"),
    ("store", "high"),
    ("warehouse", "medium"),
    ("orch", "low"),
    ("model", "high"),
    ("secret", "high"),
    ("host", "medium"),
    ("log", "low"),
    ("billing", "medium"),
    ("ticket", "medium"),
    ("key", "high"),
    ("store", "medium"),
    ("warehouse", "low"),
]

ACTIONS: dict[str, list[tuple[str, bool]]] = {
    "store": [("s3:GetObject", False), ("s3:PutObject", False), ("s3:DeleteObject", True)],
    "warehouse": [("db:Query", False), ("db:Write", True), ("db:Restore", True)],
    "orch": [("airflow:RunDag", False), ("airflow:Admin", True)],
    "model": [("ml:ReadModel", False), ("ml:RegisterModel", True), ("ml:CreateTrainingJob", True)],
    "secret": [("secrets:Get", True), ("secrets:Put", True)],
    "iam": [("iam:Read", False), ("iam:CreateUser", True), ("iam:AttachPolicy", True)],
    "billing": [("billing:Read", False), ("billing:Update", True)],
    "ticket": [("ticket:Read", False), ("ticket:Update", False)],
    "host": [("host:Deploy", True), ("host:Admin", True)],
    "log": [("logs:Read", False)],
    "key": [("kms:Decrypt", True), ("kms:Admin", True)],
}

PURPOSE_WORDS: dict[str, tuple[str, ...]] = {
    "s3:GetObject": ("pipeline", "landing", "extract", "dataset", "read"),
    "s3:PutObject": ("pipeline", "landing", "dataset", "publish"),
    "s3:DeleteObject": ("retention", "delete", "cleanup"),
    "db:Query": ("warehouse", "analyst", "query", "report"),
    "db:Write": ("warehouse", "pipeline", "load"),
    "db:Restore": ("restore", "recovery", "drill", "quarterly"),
    "airflow:RunDag": ("pipeline", "airflow", "orchestration"),
    "airflow:Admin": ("airflow", "orchestration", "admin"),
    "ml:ReadModel": ("model", "fraud", "evaluate"),
    "ml:RegisterModel": ("model", "register", "fraud"),
    "ml:CreateTrainingJob": ("train", "model", "fraud"),
    "secrets:Get": ("credential", "secret", "customer"),
    "secrets:Put": ("credential", "secret", "rotation"),
    "iam:Read": ("identity", "iam", "directory"),
    "iam:CreateUser": ("identity", "iam", "account", "provision"),
    "iam:AttachPolicy": ("identity", "iam", "policy"),
    "billing:Read": ("billing", "invoice", "close", "finance"),
    "billing:Update": ("billing", "invoice", "payroll"),
    "ticket:Read": ("ticket", "customer", "support"),
    "ticket:Update": ("ticket", "customer", "support"),
    "host:Deploy": ("deploy", "release", "production", "staging"),
    "host:Admin": ("host", "admin", "production"),
    "logs:Read": ("log", "detection", "audit"),
    "kms:Decrypt": ("key", "decrypt", "secret"),
    "kms:Admin": ("key", "kms", "admin"),
}

JOB_ROLES: list[dict[str, str]] = [
    {"id": "data-engineer", "title": "Data Engineer", "department": "data", "duty": "Build and repair data pipelines"},
    {"id": "analytics-engineer", "title": "Analytics Engineer", "department": "data", "duty": "Model warehouse tables for analysts"},
    {"id": "data-steward", "title": "Data Steward", "department": "data", "duty": "Classify datasets and approve access"},
    {"id": "data-manager", "title": "Data Engineering Manager", "department": "data", "duty": "Own data platform delivery"},
    {"id": "ml-engineer", "title": "ML Engineer", "department": "ml", "duty": "Train and register models"},
    {"id": "fraud-ml-engineer", "title": "Fraud ML Engineer", "department": "ml", "duty": "Train fraud models for fraud-model-v2"},
    {"id": "ml-scientist", "title": "ML Scientist", "department": "ml", "duty": "Design experiments and evaluate models"},
    {"id": "ml-operator", "title": "ML Platform Operator", "department": "ml", "duty": "Operate the shared training platform"},
    {"id": "finance-analyst", "title": "Finance Analyst", "department": "finance", "duty": "Read billing data and prepare the monthly close"},
    {"id": "billing-admin", "title": "Billing Admin", "department": "finance", "duty": "Update billing records"},
    {"id": "payroll", "title": "Payroll Specialist", "department": "finance", "duty": "Run payroll extracts"},
    {"id": "contractor-analyst", "title": "Contractor Analyst", "department": "finance", "duty": "Read a limited billing extract during the contract"},
    {"id": "security-analyst", "title": "Security Analyst", "department": "security", "duty": "Review detections and access findings"},
    {"id": "iam-admin", "title": "IAM Administrator", "department": "security", "duty": "Administer workforce identities and provision accounts"},
    {"id": "detection-engineer", "title": "Detection Engineer", "department": "security", "duty": "Maintain detection content from audit logs"},
    {"id": "breakglass", "title": "Break-glass Operator", "department": "security", "duty": "Use emergency access during a declared incident"},
    {"id": "devops", "title": "DevOps Engineer", "department": "platform", "duty": "Deploy services to staging and production"},
    {"id": "sre", "title": "Site Reliability Engineer", "department": "platform", "duty": "Keep production services within error budgets"},
    {"id": "recovery-engineer", "title": "Recovery Engineer", "department": "platform", "duty": "Restore production data during quarterly recovery drills"},
    {"id": "service-owner", "title": "Service Integration Owner", "department": "platform", "duty": "Own one integration landing bucket"},
    {"id": "eng-manager", "title": "Engineering Manager", "department": "platform", "duty": "Coordinate platform delivery and releases"},
    {"id": "support-agent", "title": "Support Agent", "department": "support", "duty": "Read and update customer tickets"},
    {"id": "support-lead", "title": "Support Lead", "department": "support", "duty": "Handle escalated customer tickets"},
    {"id": "knowledge", "title": "Knowledge Manager", "department": "support", "duty": "Maintain the support knowledge base"},
    {"id": "research-scientist", "title": "Research Scientist", "department": "research", "duty": "Run offline experiments on research datasets"},
    {"id": "research-engineer", "title": "Research Engineer", "department": "research", "duty": "Build research tooling and dataset extracts"},
    {"id": "lab-coordinator", "title": "Lab Coordinator", "department": "research", "duty": "Schedule lab resources"},
    {"id": "it-support", "title": "IT Support", "department": "it", "duty": "Resolve employee endpoint tickets"},
    {"id": "it-admin", "title": "IT Administrator", "department": "it", "duty": "Administer corporate endpoints"},
    {"id": "endpoint", "title": "Endpoint Engineer", "department": "it", "duty": "Package and deploy endpoint software"},
]

TEAMS: dict[str, list[str]] = {
    "data": ["Ingestion", "Warehouse", "Quality"],
    "ml": ["Fraud Detection", "Risk Models", "Platform"],
    "finance": ["Close", "Billing", "Payroll"],
    "security": ["Detection", "Identity", "Response"],
    "platform": ["Runtime", "Delivery", "Recovery"],
    "support": ["Tier 1", "Escalations", "Knowledge"],
    "research": ["Methods", "Tooling", "Lab"],
    "it": ["Service Desk", "Workplace", "Endpoint"],
}

PROJECTS: dict[str, list[str]] = {
    "data": ["lake-raw", "warehouse-v3"],
    "ml": ["fraud-model-v2", "risk-score-v1"],
    "finance": ["monthly-close", "billing-api"],
    "security": ["detect-content", "iam-cleanup"],
    "platform": ["runtime-rollout", "payments-dr"],
    "support": ["ticket-desk", "kb-refresh"],
    "research": ["offline-bench", "lab-schedule"],
    "it": ["endpoint-ring", "workplace-refresh"],
}

FIRST_NAMES = [
    "Maya", "Arun", "Leela", "Rohan", "Aisha", "Vikram", "Nora", "Imran",
    "Sara", "Dev", "Priya", "Kabir", "Anika", "Harsh", "Meera", "Omar",
    "Diya", "Nikhil", "Fatima", "Arjun", "Lina", "Sanjay", "Helen", "Ravi",
    "Tara", "Joseph", "Ananya", "Chris", "Pooja", "Aditya",
]
LAST_NAMES = [
    "Krishnan", "Desai", "Iyer", "Shah", "Nair", "Menon", "Kapoor", "Reddy",
    "Banerjee", "Chopra", "Fernandes", "Gupta", "Joshi", "Khan", "Mehta",
    "Patel", "Rao", "Singh", "Thomas", "Varma",
]

# Stable ids used by the demo and the tests.
P_DATA_S3_GET = "p-data-s3-get"
P_DATA_S3_PUT = "p-data-s3-put"
P_DATA_S3_DELETE = "p-data-s3-delete"
P_DATA_AIRFLOW = "p-data-airflow"
P_DATA_WH_QUERY = "p-data-wh-query"
P_DATA_WH_WRITE = "p-data-wh-write"
P_ML_TRAIN = "p-ml-train"
P_ML_REGISTER = "p-ml-register"
P_ML_READ = "p-ml-read"
P_PAY_RESTORE = "p-pay-restore"
P_SVC_S3_GET = "p-svc-s3-get"
P_CUST_SECRET = "p-cust-secret"
P_IAM_CREATE = "p-iam-create"
P_IAM_READ = "p-iam-read"
P_TICKET_READ = "p-ticket-read"
P_TICKET_UPDATE = "p-ticket-update"
P_BILLING_READ = "p-billing-read"
P_BILLING_UPDATE = "p-billing-update"
P_HOST_DEPLOY = "p-host-deploy"
P_LOGS_READ = "p-logs-read"
P_RESEARCH_READ = "p-research-read"
