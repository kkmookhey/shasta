"""Periodic Azure access review workflow for SOC 2 CC6.2/CC6.3 compliance.

Generates a structured access review report that lists every Entra ID user,
their RBAC role assignments, last sign-in activity, and flags issues for
human review. An auditor expects to see these conducted quarterly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from shasta.azure.client import AzureClient


@dataclass
class AzureUserAccessRecord:
    """A single Azure user's access profile for review."""

    display_name: str
    user_principal_name: str
    object_id: str
    user_type: str  # "Member" or "Guest"
    account_enabled: bool
    created_date: str | None = None
    last_sign_in: str | None = None
    days_inactive: int | None = None
    rbac_roles: list[dict[str, str]] = field(default_factory=list)
    group_memberships: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class AzureAccessReviewReport:
    """Complete Azure access review report."""

    subscription_id: str
    tenant_id: str
    review_date: str
    total_users: int
    enabled_users: int
    guest_users: int
    users_with_rbac: int
    users_flagged: int
    permissions_checked: list[str] = field(default_factory=list)
    permissions_missing: list[str] = field(default_factory=list)
    records: list[AzureUserAccessRecord] = field(default_factory=list)


def run_azure_access_review(client: AzureClient) -> AzureAccessReviewReport:
    """Run a comprehensive Entra ID / RBAC access review."""
    now = datetime.now(UTC)
    subscription_id = client.account_info.subscription_id if client.account_info else "unknown"
    tenant_id = client.account_info.tenant_id if client.account_info else "unknown"

    permissions_checked: list[str] = []
    permissions_missing: list[str] = []

    # ---------------------------------------------------------------
    # 1. Enumerate Entra ID users via Graph API
    # ---------------------------------------------------------------
    users_raw: list[Any] = []
    try:
        graph = client.graph_client()
        result = client.graph_call(graph.users.get())
        if result and result.value:
            users_raw = result.value
        permissions_checked.append("Directory.Read.All (users)")
    except Exception as e:
        permissions_missing.append(f"Directory.Read.All (users): {e}")

    # ---------------------------------------------------------------
    # 2. Get sign-in activity (requires AuditLog.Read.All)
    # ---------------------------------------------------------------
    sign_in_map: dict[str, str | None] = {}
    try:
        # Re-request users with sign-in activity selected
        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.users.users_request_builder import UsersRequestBuilder

        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=["id", "displayName", "signInActivity"],
        )
        config = RequestConfiguration(query_parameters=query_params)
        sign_in_result = client.graph_call(graph.users.get(request_configuration=config))
        if sign_in_result and sign_in_result.value:
            for u in sign_in_result.value:
                last_sign_in = None
                if hasattr(u, "sign_in_activity") and u.sign_in_activity:
                    dt = u.sign_in_activity.last_sign_in_date_time
                    if dt:
                        last_sign_in = dt.isoformat() if hasattr(dt, "isoformat") else str(dt)
                sign_in_map[u.id] = last_sign_in
        permissions_checked.append("AuditLog.Read.All (signInActivity)")
    except Exception as e:
        permissions_missing.append(f"AuditLog.Read.All (signInActivity): {e}")

    # ---------------------------------------------------------------
    # 3. Enumerate RBAC role assignments at subscription scope
    # ---------------------------------------------------------------
    rbac_by_principal: dict[str, list[dict[str, str]]] = {}
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = client.mgmt_client(AuthorizationManagementClient)
        scope = f"/subscriptions/{client.subscription_id}"

        for assignment in auth_client.role_assignments.list_for_scope(scope):
            pid = assignment.principal_id
            # Resolve role name
            role_name = "unknown"
            try:
                role_def = auth_client.role_definitions.get_by_id(assignment.role_definition_id)
                role_name = role_def.role_name or "unknown"
            except Exception:
                if assignment.role_definition_id:
                    role_name = assignment.role_definition_id.split("/")[-1]

            if pid not in rbac_by_principal:
                rbac_by_principal[pid] = []
            rbac_by_principal[pid].append(
                {
                    "role": role_name,
                    "scope": assignment.scope or "",
                }
            )
        permissions_checked.append("Microsoft.Authorization/roleAssignments/read")
    except Exception as e:
        permissions_missing.append(f"Microsoft.Authorization/roleAssignments/read: {e}")

    # ---------------------------------------------------------------
    # 4. Build user records and flag issues
    # ---------------------------------------------------------------
    records: list[AzureUserAccessRecord] = []

    for user in users_raw:
        record = _build_user_record(
            user=user,
            sign_in_map=sign_in_map,
            rbac_by_principal=rbac_by_principal,
            now=now,
        )
        records.append(record)

    # ---------------------------------------------------------------
    # 5. Build report
    # ---------------------------------------------------------------
    report = AzureAccessReviewReport(
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        review_date=now.strftime("%Y-%m-%d"),
        total_users=len(records),
        enabled_users=sum(1 for r in records if r.account_enabled),
        guest_users=sum(1 for r in records if r.user_type == "Guest"),
        users_with_rbac=sum(1 for r in records if r.rbac_roles),
        users_flagged=sum(1 for r in records if r.flags),
        permissions_checked=permissions_checked,
        permissions_missing=permissions_missing,
        records=records,
    )

    return report


def _build_user_record(
    user: Any,
    sign_in_map: dict[str, str | None],
    rbac_by_principal: dict[str, list[dict[str, str]]],
    now: datetime,
) -> AzureUserAccessRecord:
    """Build a detailed access record for a single Entra ID user."""
    object_id = user.id or ""
    display_name = user.display_name or ""
    upn = user.user_principal_name or ""
    user_type = user.user_type or "Member"
    account_enabled = user.account_enabled if user.account_enabled is not None else False
    created = str(user.created_date_time) if user.created_date_time else None

    # Sign-in activity
    last_sign_in = sign_in_map.get(object_id)

    # Calculate inactivity
    days_inactive: int | None = None
    if last_sign_in:
        try:
            sign_in_dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
            days_inactive = (now - sign_in_dt).days
        except (ValueError, TypeError):
            pass
    elif created:
        # Never signed in -- use creation date if old enough
        try:
            created_dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            if created_dt < now - timedelta(days=30):
                days_inactive = (now - created_dt).days
        except (ValueError, TypeError):
            pass

    # RBAC roles
    rbac_roles = rbac_by_principal.get(object_id, [])

    # Flags
    flags: list[str] = []

    # INACTIVE_90d
    if account_enabled and days_inactive is not None and days_inactive > 90:
        flags.append(f"INACTIVE_{days_inactive}d")

    # GUEST_USER
    if user_type == "Guest":
        flags.append("GUEST_USER")

    # OVERPRIVILEGED -- Global Admin or Owner at subscription scope
    overprivileged_roles = {"Owner", "Contributor", "User Access Administrator"}
    global_admin_roles = {"Global Administrator", "Company Administrator"}
    role_names = {r["role"] for r in rbac_roles}
    if role_names & overprivileged_roles:
        flags.append("OVERPRIVILEGED")
    if role_names & global_admin_roles:
        flags.append("OVERPRIVILEGED")

    # NO_MFA -- we cannot check per-user MFA without P1 license / Conditional Access
    # reporting API. Flag as informational if sign-in activity is unavailable.
    # A future enhancement can query Conditional Access policies.
    # For now, we note it if sign-in data was not retrievable at all.
    if not sign_in_map and account_enabled:
        flags.append("MFA_STATUS_UNKNOWN")

    return AzureUserAccessRecord(
        display_name=display_name,
        user_principal_name=upn,
        object_id=object_id,
        user_type=user_type,
        account_enabled=account_enabled,
        created_date=created,
        last_sign_in=last_sign_in,
        days_inactive=days_inactive,
        rbac_roles=rbac_roles,
        flags=flags,
    )


def save_azure_access_review(
    report: AzureAccessReviewReport,
    output_path: Path | str = "data/reviews",
) -> Path:
    """Save the Azure access review as a Markdown report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"azure-access-review-{report.subscription_id}-{report.review_date}.md"

    lines = [
        f"# Azure Access Review -- {report.review_date}",
        "",
        f"**Subscription:** {report.subscription_id}",
        f"**Tenant:** {report.tenant_id}",
        f"**Date:** {report.review_date}",
        f"**Total Users:** {report.total_users}",
        f"**Enabled Users:** {report.enabled_users}",
        f"**Guest Users:** {report.guest_users}",
        f"**Users with RBAC Roles:** {report.users_with_rbac}",
        f"**Users Flagged for Review:** {report.users_flagged}",
        "",
    ]

    # Permission notes
    if report.permissions_missing:
        lines.append("### Permissions Not Available")
        lines.append("")
        lines.append("The following permissions were not available; some data may be incomplete:")
        lines.append("")
        for perm in report.permissions_missing:
            lines.append(f"- {perm}")
        lines.append("")

    if report.permissions_checked:
        lines.append("### Permissions Verified")
        lines.append("")
        for perm in report.permissions_checked:
            lines.append(f"- {perm}")
        lines.append("")

    lines.extend(["---", ""])

    # Flagged users first
    flagged = [r for r in report.records if r.flags]
    if flagged:
        lines.append("## Flagged Users (Require Action)")
        lines.append("")
        for r in flagged:
            lines.append(f"### {r.display_name} ({r.user_principal_name})")
            lines.append(f"- **Flags:** {', '.join(r.flags)}")
            lines.append(
                f"- **Type:** {r.user_type} | **Enabled:** {'Yes' if r.account_enabled else 'No'}"
            )
            roles_str = (
                ", ".join(f"{role['role']} ({role['scope']})" for role in r.rbac_roles)
                if r.rbac_roles
                else "None"
            )
            lines.append(f"- **RBAC Roles:** {roles_str}")
            lines.append(f"- **Last Sign-In:** {r.last_sign_in or 'Never / Unknown'}")
            lines.append(f"- **Days Inactive:** {r.days_inactive or 'N/A'}")
            lines.append("")

    # All users table
    lines.append("## All Users Summary")
    lines.append("")
    lines.append(
        "| User | UPN | Type | Enabled | RBAC Roles | Last Sign-In | Inactive Days | Flags |"
    )
    lines.append(
        "|------|-----|------|---------|------------|-------------|---------------|-------|"
    )
    for r in report.records:
        flags_str = ", ".join(r.flags) if r.flags else "-"
        roles_count = len(r.rbac_roles)
        lines.append(
            f"| {r.display_name} | {r.user_principal_name} | {r.user_type} "
            f"| {'Y' if r.account_enabled else 'N'} "
            f"| {roles_count} "
            f"| {r.last_sign_in or '-'} "
            f"| {r.days_inactive or '-'} | {flags_str} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Reviewer Sign-off",
            "",
            "| Field | Value |",
            "|-------|-------|",
            "| Reviewed by | ___________________ |",
            "| Date | ___________________ |",
            "| Actions taken | ___________________ |",
            "",
            "*This review satisfies SOC 2 CC6.2 (Access Provisioning)"
            " and CC6.3 (Access Removal) requirements.*",
        ]
    )

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
