"""Azure compute security checks for SOC 2 and ISO 27001.

Checks AKS cluster configuration for compliance with CC6.6
(System Boundaries) and related controls.
"""

from __future__ import annotations

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)


def run_all_azure_compute_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure compute compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_aks_security(client, sub_id, region))

    return findings


def check_aks_security(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.6] Check AKS clusters for RBAC, network policy, and API server restrictions."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.containerservice import ContainerServiceClient

        aks_client = client.mgmt_client(ContainerServiceClient)

        clusters = list(aks_client.managed_clusters.list())

        if not clusters:
            findings.append(
                Finding(
                    check_id="azure-aks-rbac",
                    title="No AKS clusters found",
                    description="No AKS managed clusters found in the subscription.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.COMPUTE,
                    resource_type="Azure::ContainerService::ManagedCluster",
                    resource_id=f"/subscriptions/{subscription_id}/aksClusters",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.6"],
                )
            )
            return findings

        for cluster in clusters:
            cluster_name = cluster.name or "unknown"
            cluster_id = cluster.id or ""
            cluster_location = cluster.location or region
            issues = []

            # Check RBAC
            if not cluster.enable_rbac:
                issues.append(
                    {
                        "issue": "RBAC disabled",
                        "severity": "HIGH",
                        "detail": "Kubernetes RBAC is not enabled on this cluster.",
                    }
                )

            # Check network policy
            network_profile = cluster.network_profile
            network_policy = network_profile.network_policy if network_profile else None
            if not network_policy:
                issues.append(
                    {
                        "issue": "No network policy",
                        "severity": "MEDIUM",
                        "detail": "No network policy plugin configured (calico or azure). "
                        "Without network policy, all pods can communicate freely.",
                    }
                )

            # Check API server authorized IP ranges (for public clusters)
            api_profile = cluster.api_server_access_profile
            if api_profile:
                authorized_ips = api_profile.authorized_ip_ranges
                is_private = getattr(api_profile, "enable_private_cluster", False)
                if not is_private and (not authorized_ips or len(authorized_ips) == 0):
                    issues.append(
                        {
                            "issue": "API server unrestricted",
                            "severity": "MEDIUM",
                            "detail": "Public AKS cluster has no authorized IP ranges set "
                            "on the API server, allowing access from any IP.",
                        }
                    )
            else:
                # No API server access profile at all on a public cluster
                issues.append(
                    {
                        "issue": "API server unrestricted",
                        "severity": "MEDIUM",
                        "detail": "No API server access profile configured. "
                        "The Kubernetes API may be publicly accessible.",
                    }
                )

            if issues:
                has_rbac_issue = any(i["issue"] == "RBAC disabled" for i in issues)
                severity = Severity.HIGH if has_rbac_issue else Severity.MEDIUM
                findings.append(
                    Finding(
                        check_id="azure-aks-rbac",
                        title=f"AKS cluster '{cluster_name}' has security issues",
                        description=f"AKS cluster '{cluster_name}' has {len(issues)} issue(s): "
                        f"{', '.join(i['issue'] for i in issues)}",
                        severity=severity,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.COMPUTE,
                        resource_type="Azure::ContainerService::ManagedCluster",
                        resource_id=cluster_id,
                        region=cluster_location,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=f"For AKS cluster '{cluster_name}': enable Kubernetes RBAC, "
                        "configure a network policy plugin (calico or azure), and restrict "
                        "API server access to authorized IP ranges or use a private cluster.",
                        soc2_controls=["CC6.6"],
                        details={
                            "cluster_name": cluster_name,
                            "issues": issues,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-aks-rbac",
                        title=f"AKS cluster '{cluster_name}' is properly secured",
                        description=f"AKS cluster '{cluster_name}' has RBAC enabled, "
                        "network policy configured, and API server access restricted.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.COMPUTE,
                        resource_type="Azure::ContainerService::ManagedCluster",
                        resource_id=cluster_id,
                        region=cluster_location,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.6"],
                        details={"cluster_name": cluster_name},
                    )
                )

    except ImportError:
        findings.append(
            Finding(
                check_id="azure-aks-rbac",
                title="AKS check skipped (azure-mgmt-containerservice not installed)",
                description="The azure-mgmt-containerservice package is not installed. "
                "Install it with: pip install azure-mgmt-containerservice",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.COMPUTE,
                resource_type="Azure::ContainerService::ManagedCluster",
                resource_id=f"/subscriptions/{subscription_id}/aksClusters",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        )
    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-aks-rbac",
                title="AKS check failed",
                description=f"Could not check AKS clusters: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.COMPUTE,
                resource_type="Azure::ContainerService::ManagedCluster",
                resource_id=f"/subscriptions/{subscription_id}/aksClusters",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        )

    return findings
