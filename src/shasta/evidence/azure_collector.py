"""Azure evidence collector -- snapshots Azure state for audit trail.

Captures point-in-time evidence that an auditor can review:
  - Entra ID (Azure AD) user configurations
  - RBAC role assignments
  - Storage account security settings
  - Network Security Group rules
  - SQL server configurations
  - Key Vault protection settings
  - Activity log diagnostic settings
  - Microsoft Defender for Cloud status

Each evidence artifact is timestamped and stored in the database + as JSON files.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shasta.azure.client import AzureClient
from shasta.db.schema import ShastaDB
from shasta.evidence.models import Evidence


def collect_all_evidence(
    client: AzureClient,
    scan_id: str,
    output_path: Path | str = "data/evidence",
) -> list[Path]:
    """Collect all Azure evidence artifacts and save to disk + database."""
    output_dir = Path(output_path)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_dir = output_dir / f"azure-scan-{scan_id}-{timestamp}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    db = ShastaDB()
    db.initialize()

    subscription_id = client.account_info.subscription_id if client.account_info else "unknown"
    saved_files: list[Path] = []

    collectors = [
        ("entra-users", "Entra ID user accounts and status", _collect_entra_users),
        (
            "rbac-assignments",
            "RBAC role assignments at subscription scope",
            _collect_rbac_assignments,
        ),
        (
            "storage-configs",
            "Storage account encryption, TLS, and public access settings",
            _collect_storage_configs,
        ),
        ("nsg-rules", "Network Security Group rules", _collect_nsg_rules),
        (
            "sql-configs",
            "SQL server configurations (public access, TDE, firewall)",
            _collect_sql_configs,
        ),
        (
            "keyvault-configs",
            "Key Vault soft-delete and purge protection status",
            _collect_keyvault_configs,
        ),
        (
            "activity-log-settings",
            "Diagnostic settings for activity log",
            _collect_activity_log_settings,
        ),
        ("defender-status", "Microsoft Defender for Cloud pricing tiers", _collect_defender_status),
    ]

    for evidence_id, description, collector_fn in collectors:
        try:
            data = collector_fn(client)
            evidence = Evidence(
                scan_id=scan_id,
                finding_id=evidence_id,
                evidence_type="config_snapshot",
                description=description,
                data=data,
            )
            db.save_evidence(evidence)

            filepath = scan_dir / f"{evidence_id}.json"
            filepath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            saved_files.append(filepath)
        except Exception as e:
            # Log but don't fail -- collect what we can
            error_path = scan_dir / f"{evidence_id}-error.txt"
            error_path.write_text(f"Collection failed: {e}", encoding="utf-8")
            saved_files.append(error_path)

    # Write manifest
    manifest = {
        "scan_id": scan_id,
        "subscription_id": subscription_id,
        "cloud_provider": "azure",
        "collected_at": datetime.now(UTC).isoformat(),
        "artifacts": [str(f.name) for f in saved_files],
    }
    manifest_path = scan_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    saved_files.append(manifest_path)

    db.close()
    return saved_files


def _collect_entra_users(client: AzureClient) -> dict[str, Any]:
    """Collect Entra ID users via Microsoft Graph API."""
    graph = client.graph_client()

    users_data: list[dict[str, Any]] = []
    try:
        result = client.graph_call(graph.users.get())
        if result and result.value:
            for user in result.value:
                users_data.append(
                    {
                        "id": user.id,
                        "display_name": user.display_name,
                        "user_principal_name": user.user_principal_name,
                        "user_type": user.user_type,
                        "account_enabled": user.account_enabled,
                        "created_date_time": str(user.created_date_time)
                        if user.created_date_time
                        else None,
                    }
                )
    except Exception as e:
        return {
            "users": [],
            "total": 0,
            "error": f"Graph API call failed (check Directory.Read.All permission): {e}",
        }

    return {"users": users_data, "total": len(users_data)}


def _collect_rbac_assignments(client: AzureClient) -> dict[str, Any]:
    """Collect RBAC role assignments at subscription scope."""
    from azure.mgmt.authorization import AuthorizationManagementClient

    auth_client = client.mgmt_client(AuthorizationManagementClient)
    scope = f"/subscriptions/{client.subscription_id}"

    assignments_data: list[dict[str, Any]] = []
    try:
        for assignment in auth_client.role_assignments.list_for_scope(scope):
            # Resolve role definition name
            role_name = (
                assignment.role_definition_id.split("/")[-1]
                if assignment.role_definition_id
                else "unknown"
            )
            try:
                role_def = auth_client.role_definitions.get_by_id(assignment.role_definition_id)
                role_name = role_def.role_name or role_name
            except Exception:
                pass

            assignments_data.append(
                {
                    "id": assignment.id,
                    "principal_id": assignment.principal_id,
                    "principal_type": str(assignment.principal_type)
                    if assignment.principal_type
                    else None,
                    "role_definition_id": assignment.role_definition_id,
                    "role_name": role_name,
                    "scope": assignment.scope,
                }
            )
    except Exception as e:
        return {
            "assignments": [],
            "total": 0,
            "error": f"RBAC enumeration failed: {e}",
        }

    return {"assignments": assignments_data, "total": len(assignments_data)}


def _collect_storage_configs(client: AzureClient) -> dict[str, Any]:
    """Collect storage account encryption, TLS, and public access settings."""
    from azure.mgmt.storage import StorageManagementClient

    storage_client = client.mgmt_client(StorageManagementClient)
    accounts_data: list[dict[str, Any]] = []

    try:
        for account in storage_client.storage_accounts.list():
            config: dict[str, Any] = {
                "name": account.name,
                "id": account.id,
                "location": account.location,
            }

            # Encryption settings
            if account.encryption:
                config["encryption"] = {
                    "key_source": str(account.encryption.key_source)
                    if account.encryption.key_source
                    else None,
                    "services": {},
                }
                if account.encryption.services:
                    for svc_name in ("blob", "file", "table", "queue"):
                        svc = getattr(account.encryption.services, svc_name, None)
                        if svc:
                            config["encryption"]["services"][svc_name] = {
                                "enabled": svc.enabled,
                                "key_type": str(svc.key_type) if svc.key_type else None,
                            }
            else:
                config["encryption"] = None

            # TLS version
            config["minimum_tls_version"] = (
                str(account.minimum_tls_version) if account.minimum_tls_version else None
            )

            # Public access
            config["allow_blob_public_access"] = account.allow_blob_public_access
            config["public_network_access"] = (
                str(account.public_network_access) if account.public_network_access else None
            )

            # HTTPS only
            config["enable_https_traffic_only"] = account.enable_https_traffic_only

            accounts_data.append(config)
    except Exception as e:
        return {
            "storage_accounts": [],
            "total": 0,
            "error": f"Storage account enumeration failed: {e}",
        }

    return {"storage_accounts": accounts_data, "total": len(accounts_data)}


def _collect_nsg_rules(client: AzureClient) -> dict[str, Any]:
    """Collect Network Security Group rules for all NSGs."""
    from azure.mgmt.network import NetworkManagementClient

    network_client = client.mgmt_client(NetworkManagementClient)
    nsgs_data: list[dict[str, Any]] = []

    try:
        for nsg in network_client.network_security_groups.list_all():
            rules: list[dict[str, Any]] = []
            for rule in nsg.security_rules or []:
                rules.append(
                    {
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": str(rule.direction) if rule.direction else None,
                        "access": str(rule.access) if rule.access else None,
                        "protocol": str(rule.protocol) if rule.protocol else None,
                        "source_address_prefix": rule.source_address_prefix,
                        "source_address_prefixes": list(rule.source_address_prefixes or []),
                        "destination_address_prefix": rule.destination_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                        "destination_port_ranges": list(rule.destination_port_ranges or []),
                    }
                )

            nsgs_data.append(
                {
                    "name": nsg.name,
                    "id": nsg.id,
                    "location": nsg.location,
                    "resource_group": nsg.id.split("/")[4]
                    if nsg.id and len(nsg.id.split("/")) > 4
                    else None,
                    "security_rules": rules,
                    "total_rules": len(rules),
                }
            )
    except Exception as e:
        return {
            "nsgs": [],
            "total": 0,
            "error": f"NSG enumeration failed: {e}",
        }

    return {"nsgs": nsgs_data, "total": len(nsgs_data)}


def _collect_sql_configs(client: AzureClient) -> dict[str, Any]:
    """Collect SQL server configurations including public access, TDE, and firewall rules."""
    from azure.mgmt.sql import SqlManagementClient

    sql_client = client.mgmt_client(SqlManagementClient)
    servers_data: list[dict[str, Any]] = []

    try:
        for server in sql_client.servers.list():
            rg = server.id.split("/")[4] if server.id and len(server.id.split("/")) > 4 else None
            server_name = server.name

            config: dict[str, Any] = {
                "name": server_name,
                "id": server.id,
                "location": server.location,
                "resource_group": rg,
                "public_network_access": str(server.public_network_access)
                if server.public_network_access
                else None,
                "minimal_tls_version": server.minimal_tls_version,
            }

            # Firewall rules
            firewall_rules: list[dict[str, Any]] = []
            try:
                if rg and server_name:
                    for rule in sql_client.firewall_rules.list_by_server(rg, server_name):
                        firewall_rules.append(
                            {
                                "name": rule.name,
                                "start_ip": rule.start_ip_address,
                                "end_ip": rule.end_ip_address,
                            }
                        )
            except Exception:
                firewall_rules = [{"error": "Could not enumerate firewall rules"}]
            config["firewall_rules"] = firewall_rules

            # TDE status per database
            tde_status: list[dict[str, Any]] = []
            try:
                if rg and server_name:
                    for db in sql_client.databases.list_by_server(rg, server_name):
                        if db.name == "master":
                            continue
                        try:
                            tde = sql_client.transparent_data_encryptions.get(
                                rg, server_name, db.name, "current"
                            )
                            tde_status.append(
                                {
                                    "database": db.name,
                                    "state": str(tde.state) if tde.state else None,
                                }
                            )
                        except Exception:
                            tde_status.append(
                                {
                                    "database": db.name,
                                    "state": "unknown",
                                }
                            )
            except Exception:
                tde_status = [{"error": "Could not enumerate databases"}]
            config["tde_status"] = tde_status

            servers_data.append(config)
    except Exception as e:
        return {
            "sql_servers": [],
            "total": 0,
            "error": f"SQL server enumeration failed: {e}",
        }

    return {"sql_servers": servers_data, "total": len(servers_data)}


def _collect_keyvault_configs(client: AzureClient) -> dict[str, Any]:
    """Collect Key Vault soft-delete and purge protection status."""
    from azure.mgmt.keyvault import KeyVaultManagementClient

    kv_client = client.mgmt_client(KeyVaultManagementClient)
    vaults_data: list[dict[str, Any]] = []

    try:
        for vault in kv_client.vaults.list_by_subscription():
            config: dict[str, Any] = {
                "name": vault.name,
                "id": vault.id,
                "location": vault.location,
            }
            if vault.properties:
                config["soft_delete_enabled"] = vault.properties.enable_soft_delete
                config["purge_protection_enabled"] = vault.properties.enable_purge_protection
                config["soft_delete_retention_days"] = (
                    vault.properties.soft_delete_retention_in_days
                )
                config["enable_rbac_authorization"] = vault.properties.enable_rbac_authorization
            else:
                config["soft_delete_enabled"] = None
                config["purge_protection_enabled"] = None

            vaults_data.append(config)
    except Exception as e:
        return {
            "key_vaults": [],
            "total": 0,
            "error": f"Key Vault enumeration failed: {e}",
        }

    return {"key_vaults": vaults_data, "total": len(vaults_data)}


def _collect_activity_log_settings(client: AzureClient) -> dict[str, Any]:
    """Collect diagnostic settings for the Azure activity log."""
    from azure.mgmt.monitor import MonitorManagementClient

    monitor_client = client.mgmt_client(MonitorManagementClient)
    settings_data: list[dict[str, Any]] = []

    try:
        # Activity log diagnostic settings are at subscription scope
        sub_id = client.subscription_id
        for setting in monitor_client.diagnostic_settings.list(
            resource_uri=f"/subscriptions/{sub_id}"
        ):
            logs: list[dict[str, Any]] = []
            for log_setting in setting.logs or []:
                logs.append(
                    {
                        "category": log_setting.category,
                        "enabled": log_setting.enabled,
                        "retention_days": (
                            log_setting.retention_policy.days
                            if log_setting.retention_policy
                            else None
                        ),
                    }
                )

            settings_data.append(
                {
                    "name": setting.name,
                    "id": setting.id,
                    "storage_account_id": setting.storage_account_id,
                    "workspace_id": setting.workspace_id,
                    "event_hub_authorization_rule_id": setting.event_hub_authorization_rule_id,
                    "logs": logs,
                }
            )
    except Exception as e:
        return {
            "diagnostic_settings": [],
            "total": 0,
            "error": f"Activity log diagnostic settings query failed: {e}",
        }

    return {"diagnostic_settings": settings_data, "total": len(settings_data)}


def _collect_defender_status(client: AzureClient) -> dict[str, Any]:
    """Collect Microsoft Defender for Cloud pricing tiers."""
    from azure.mgmt.security import SecurityCenter

    # SecurityCenter requires an asc_location; use the subscription-level API
    security_client = client.mgmt_client(SecurityCenter, asc_location="centralus")
    pricings_data: list[dict[str, Any]] = []

    try:
        result = security_client.pricings.list()
        for pricing in result.value or []:
            pricings_data.append(
                {
                    "name": pricing.name,
                    "pricing_tier": str(pricing.pricing_tier) if pricing.pricing_tier else None,
                    "free_trial_remaining_time": str(pricing.free_trial_remaining_time)
                    if pricing.free_trial_remaining_time
                    else None,
                }
            )
    except Exception as e:
        return {
            "pricings": [],
            "total": 0,
            "error": f"Defender for Cloud pricing query failed: {e}",
        }

    return {"pricings": pricings_data, "total": len(pricings_data)}
