"""initial schema — all 19 core tables

Revision ID: 0001
Revises:
Create Date: 2026-08-06

Generated from kiyooo.db.models via Alembic's autogenerate API
(produce_migrations/render_python_code) diffed against an empty database.
Column types are taken directly from the live SQLAlchemy model metadata, so
this migration cannot drift from models.py — see
scripts/gen_migration.py-equivalent process in project history.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "DOMAIN",
                "SUBDOMAIN",
                "IP",
                "URL",
                "HTTP_SERVICE",
                "TCP_SERVICE",
                "CLOUD_RESOURCE",
                "REPO",
                "CERT",
                "ASN",
                "NETBLOCK",
                "SAAS_TENANT",
                "MOBILE_APP",
                "LLM_ENDPOINT",
                "VECTOR_DB",
                "MCP_SERVER",
                "MODEL_REGISTRY",
                "AI_AGENT_WEBHOOK",
                name="asset_type",
            ),
            nullable=False,
        ),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("confidence_in_scope", sa.Float(), nullable=False),
        sa.Column("scope_reason", sa.Text(), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("type", "value", name="uq_asset_type_value"),
    )
    op.create_table(
        "external_finding_source",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "system",
            sa.Enum(
                "MANDIANT_ASM",
                "QUALYS",
                "TENABLE",
                "WIZ",
                "DEFENDER_EASM",
                "NUCLEI_JSON",
                "NESSUS",
                "CUSTOM",
                name="external_finding_system",
            ),
            nullable=False,
        ),
        sa.Column("config", postgresql.JSONB(astext_type=Text()), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cursor", sa.String(length=512), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "model_pin",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "role",
            sa.Enum("BULK", "ESCALATION", "EMBEDDING", name="model_pin_role"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("digest", sa.String(length=128), nullable=False),
        sa.Column("pinned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pinned_by", sa.String(length=256), nullable=False),
        sa.Column("eval_run_id", sa.String(length=128), nullable=True),
        sa.Column("changelog_note", sa.Text(), nullable=False),
        sa.Column("superseded_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["superseded_by"], ["model_pin.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scan_run",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", name="scan_run_status"
            ),
            nullable=False,
        ),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "trigger",
            sa.Enum("MANUAL", "SCHEDULED", "WEBHOOK", "EVENT", name="scan_trigger"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "asset_edge",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("src_asset_id", sa.Uuid(), nullable=False),
        sa.Column("dst_asset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "relation",
            sa.Enum(
                "RESOLVES_TO",
                "HOSTED_ON",
                "SERVES",
                "REDIRECTS_TO",
                "CNAME_TO",
                "ISSUED_FOR",
                "OWNED_BY",
                "DEPLOYED_FROM",
                "SAME_ORG_AS",
                name="asset_edge_relation",
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("discovered_by", sa.String(length=128), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["dst_asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["src_asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "asset_snapshot",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=Text()), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "change_event",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "ASSET_NEW",
                "ASSET_GONE",
                "PORT_OPENED",
                "PORT_CLOSED",
                "TECH_CHANGED",
                "DECOMMISSION_CANDIDATE",
                "CERT_CHANGED",
                "DNS_CHANGED",
                "TAKEOVER_RISK",
                "AUTH_REMOVED",
                "WENT_PUBLIC",
                "CONTENT_CHANGED",
                name="change_event_kind",
            ),
            nullable=False,
        ),
        sa.Column("before", postgresql.JSONB(astext_type=Text()), nullable=True),
        sa.Column("after", postgresql.JSONB(astext_type=Text()), nullable=True),
        sa.Column(
            "severity_hint",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity"),
            nullable=True,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "HTTP_RESPONSE",
                "TLS_CERT",
                "DNS_RECORD",
                "PORT_BANNER",
                "SCREENSHOT",
                "NUCLEI_RESULT",
                "GIT_SECRET",
                "CLOUD_CONFIG",
                "WHOIS",
                "ASN_RECORD",
                "FAVICON_HASH",
                "JS_ENDPOINT",
                "VERIFICATION_RESULT",
                name="evidence_kind",
            ),
            nullable=False,
        ),
        sa.Column("source_tool", sa.String(length=128), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_ref", sa.String(length=1024), nullable=True),
        sa.Column("content_inline", postgresql.JSONB(astext_type=Text()), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("redacted", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "finding",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("category_id", sa.String(length=128), nullable=False),
        sa.Column(
            "raw_severity",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "detector",
            sa.Enum("RULE", "NUCLEI", "LLM", "MANUAL", name="finding_detector"),
            nullable=False,
        ),
        sa.Column("detector_ref", sa.String(length=256), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("cluster_id", sa.Uuid(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "NEW",
                "TRIAGING",
                "TRIAGED",
                "ROUTED",
                "ACCEPTED_RISK",
                "VERIFICATION_PENDING",
                "FIXED",
                "REGRESSED",
                "SUPPRESSED",
                name="finding_status",
            ),
            nullable=False,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_cluster_id"), "finding", ["cluster_id"], unique=False)
    op.create_index(op.f("ix_finding_fingerprint"), "finding", ["fingerprint"], unique=True)
    op.create_table(
        "ownership",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("owner_type", sa.Enum("USER", "TEAM", name="owner_type"), nullable=False),
        sa.Column("owner_ref", sa.String(length=256), nullable=False),
        sa.Column("manager_ref", sa.String(length=256), nullable=True),
        sa.Column(
            "source",
            sa.Enum(
                "CLOUD_TAG",
                "IAC",
                "CODEOWNERS",
                "DNS_AUDIT",
                "INFERENCE",
                "MANUAL",
                name="ownership_source",
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_note", sa.Text(), nullable=True),
        sa.Column("verified_by_human", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "approval",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "draft_kind",
            sa.Enum("TICKET", "EMAIL", "SLACK", "COMMENT", name="approval_draft_kind"),
            nullable=False,
        ),
        sa.Column("rendered_body", sa.Text(), nullable=False),
        sa.Column("rendered_subject", sa.String(length=512), nullable=True),
        sa.Column("target_assignee", sa.String(length=256), nullable=True),
        sa.Column("target_cc", sa.ARRAY(sa.String()), nullable=False),
        sa.Column(
            "status",
            sa.Enum("PENDING", "APPROVED", "EDITED", "REJECTED", "EXPIRED", name="approval_status"),
            nullable=False,
        ),
        sa.Column("reviewer", sa.String(length=256), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("edit_diff", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("external_key", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "control",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("detected_by", sa.String(length=128), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "external_finding_raw",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=Text()), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mapped_finding_id", sa.Uuid(), nullable=True),
        sa.Column("mapping_status", sa.String(length=64), nullable=False),
        sa.Column("mapping_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["mapped_finding_id"], ["finding.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["source_id"], ["external_finding_source.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_id", "external_id", name="uq_external_finding_source_external_id"
        ),
    )
    op.create_table(
        "finding_evidence",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=False),
        sa.Column(
            "role",
            sa.Enum("PRIMARY", "SUPPORTING", "CONTEXT", name="finding_evidence_role"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id", "evidence_id"),
    )
    op.create_table(
        "human_review",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("reviewer", sa.String(length=256), nullable=False),
        sa.Column("agreed_with_model", sa.Boolean(), nullable=False),
        sa.Column(
            "final_verdict",
            sa.Enum(
                "TRUE_POSITIVE",
                "FALSE_POSITIVE",
                "NOT_EXPLOITABLE",
                "NEEDS_HUMAN",
                name="verdict_value",
            ),
            nullable=False,
        ),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("promote_to_rule", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "identifier_verification",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "CVE",
                "CVSS_VECTOR",
                "VERSION",
                "HOSTNAME",
                "PACKAGE",
                "CWE",
                name="identifier_kind",
            ),
            nullable=False,
        ),
        sa.Column("claimed_value", sa.String(length=512), nullable=False),
        sa.Column("source", sa.Enum("EVIDENCE", "MODEL", name="identifier_source"), nullable=False),
        sa.Column("resolved", sa.Boolean(), nullable=False),
        sa.Column(
            "authority",
            sa.Enum("NVD", "KEV", "OSV", "DNS", "EVIDENCE", name="identifier_authority"),
            nullable=True,
        ),
        sa.Column("resolved_value", sa.String(length=512), nullable=True),
        sa.Column(
            "status",
            sa.Enum("VERIFIED", "NOT_FOUND", "MISMATCH", "HALLUCINATED", name="identifier_status"),
            nullable=False,
        ),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "llm_call_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=True),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column(
            "purpose",
            sa.Enum(
                "ADJUDICATE", "VERIFY_PLAN", "OWNERSHIP", "REMEDIATION", name="llm_call_purpose"
            ),
            nullable=False,
        ),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("model_digest", sa.String(length=128), nullable=True),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("system_prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("messages", postgresql.JSONB(astext_type=Text()), nullable=False),
        sa.Column("raw_response", sa.Text(), nullable=True),
        sa.Column("refused", sa.Boolean(), nullable=False),
        sa.Column("refusal_reason", sa.Text(), nullable=True),
        sa.Column("retry_of_id", sa.Uuid(), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(precision=10, scale=6), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["retry_of_id"], ["llm_call_log.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ticket",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "system",
            sa.Enum("JIRA", "LINEAR", "GITHUB", "SERVICENOW", name="ticket_system"),
            nullable=False,
        ),
        sa.Column("external_key", sa.String(length=256), nullable=True),
        sa.Column("assignee", sa.String(length=256), nullable=True),
        sa.Column("cc", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "verdict",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("model_version", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column(
            "pass_type", sa.Enum("BULK", "ESCALATION", name="verdict_pass_type"), nullable=False
        ),
        sa.Column(
            "verdict",
            sa.Enum(
                "TRUE_POSITIVE",
                "FALSE_POSITIVE",
                "NOT_EXPLOITABLE",
                "NEEDS_HUMAN",
                name="verdict_value",
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "adjusted_severity",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity"),
            nullable=False,
        ),
        sa.Column("reasoning", sa.Text(), nullable=False),
        sa.Column("citations", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("compensating_controls", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("exploitability", postgresql.JSONB(astext_type=Text()), nullable=True),
        sa.Column("remediation", postgresql.JSONB(astext_type=Text()), nullable=True),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(precision=10, scale=6), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_verdict_input_hash"), "verdict", ["input_hash"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_verdict_input_hash"), table_name="verdict")
    op.drop_table("verdict")
    op.drop_table("ticket")
    op.drop_table("llm_call_log")
    op.drop_table("identifier_verification")
    op.drop_table("human_review")
    op.drop_table("finding_evidence")
    op.drop_table("external_finding_raw")
    op.drop_table("control")
    op.drop_table("approval")
    op.drop_table("ownership")
    op.drop_index(op.f("ix_finding_fingerprint"), table_name="finding")
    op.drop_index(op.f("ix_finding_cluster_id"), table_name="finding")
    op.drop_table("finding")
    op.drop_table("evidence")
    op.drop_table("change_event")
    op.drop_table("asset_snapshot")
    op.drop_table("asset_edge")
    op.drop_table("scan_run")
    op.drop_table("model_pin")
    op.drop_table("external_finding_source")
    op.drop_table("asset")
