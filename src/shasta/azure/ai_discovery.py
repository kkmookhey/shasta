"""Azure AI/ML service discovery for Whitney.

Discovers Azure OpenAI, Azure ML workspaces, and Cognitive Services
accounts in the connected Azure subscription.
"""

from __future__ import annotations

import logging
from typing import Any

from shasta.azure.client import AzureClient

logger = logging.getLogger(__name__)

# Cognitive Services kinds that are AI-related
AI_COGNITIVE_KINDS: set[str] = {
    "OpenAI",
    "CognitiveServices",
    "TextAnalytics",
    "TextTranslation",
    "ComputerVision",
    "CustomVision.Training",
    "CustomVision.Prediction",
    "FormRecognizer",
    "SpeechServices",
    "ContentSafety",
    "AnomalyDetector",
    "Face",
    "ImmersiveReader",
    "LUIS",
    "QnAMaker",
    "Personalizer",
}


def discover_azure_ai_services(client: AzureClient) -> dict[str, Any]:
    """Discover AI/ML services in the Azure subscription.

    Returns a dict with service names as keys and discovery details as values.
    Handles ImportError gracefully when Azure SDK packages are not installed.
    """
    results: dict[str, Any] = {}

    results["azure_openai"] = _discover_azure_openai(client)
    results["azure_ml"] = _discover_azure_ml(client)
    results["cognitive_services"] = _discover_cognitive_services(client)

    # Compute totals
    total = 0
    for svc, info in results.items():
        if isinstance(info, dict):
            total += info.get("total_resources", 0)
    results["total_ai_resources"] = total

    return results


def _discover_azure_openai(client: AzureClient) -> dict[str, Any]:
    """Discover Azure OpenAI accounts and deployments."""
    result: dict[str, Any] = {
        "available": False,
        "accounts": [],
        "deployments": [],
        "total_resources": 0,
    }

    try:
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    except ImportError:
        logger.debug("azure-mgmt-cognitiveservices not installed")
        result["error"] = "azure-mgmt-cognitiveservices package not installed"
        return result

    try:
        cog_client = client.mgmt_client(CognitiveServicesManagementClient)

        # Find OpenAI accounts
        for account in cog_client.accounts.list():
            if account.kind != "OpenAI":
                continue

            account_info: dict[str, Any] = {
                "name": account.name,
                "id": account.id,
                "location": account.location,
                "sku": account.sku.name if account.sku else None,
                "provisioning_state": (
                    account.properties.provisioning_state if account.properties else None
                ),
            }
            result["accounts"].append(account_info)

            # List deployments for this account
            try:
                rg_name = _resource_group_from_id(account.id)
                if rg_name:
                    for deployment in cog_client.deployments.list(
                        resource_group_name=rg_name,
                        account_name=account.name,
                    ):
                        result["deployments"].append(
                            {
                                "name": deployment.name,
                                "model": (
                                    deployment.properties.model.name
                                    if deployment.properties and deployment.properties.model
                                    else None
                                ),
                                "account": account.name,
                            }
                        )
            except Exception as e:
                logger.debug("Failed to list deployments for %s: %s", account.name, e)

        result["total_resources"] = len(result["accounts"]) + len(result["deployments"])
        result["available"] = True

    except Exception as e:
        logger.warning("Error discovering Azure OpenAI: %s", e)
        result["error"] = str(e)

    return result


def _discover_azure_ml(client: AzureClient) -> dict[str, Any]:
    """Discover Azure ML workspaces."""
    result: dict[str, Any] = {
        "available": False,
        "workspaces": [],
        "total_resources": 0,
    }

    try:
        from azure.mgmt.machinelearningservices import MachineLearningServicesMgmtClient
    except ImportError:
        logger.debug("azure-mgmt-machinelearningservices not installed")
        result["error"] = "azure-mgmt-machinelearningservices package not installed"
        return result

    try:
        ml_client = client.mgmt_client(MachineLearningServicesMgmtClient)

        for workspace in ml_client.workspaces.list_by_subscription():
            result["workspaces"].append(
                {
                    "name": workspace.name,
                    "id": workspace.id,
                    "location": workspace.location,
                    "sku": workspace.sku.name if workspace.sku else None,
                    "provisioning_state": (
                        workspace.provisioning_state
                        if hasattr(workspace, "provisioning_state")
                        else None
                    ),
                }
            )

        result["total_resources"] = len(result["workspaces"])
        result["available"] = True

    except Exception as e:
        logger.warning("Error discovering Azure ML: %s", e)
        result["error"] = str(e)

    return result


def _discover_cognitive_services(client: AzureClient) -> dict[str, Any]:
    """Discover Cognitive Services accounts filtered by AI kinds."""
    result: dict[str, Any] = {
        "available": False,
        "accounts": [],
        "total_resources": 0,
    }

    try:
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    except ImportError:
        logger.debug("azure-mgmt-cognitiveservices not installed")
        result["error"] = "azure-mgmt-cognitiveservices package not installed"
        return result

    try:
        cog_client = client.mgmt_client(CognitiveServicesManagementClient)

        for account in cog_client.accounts.list():
            # Skip non-AI kinds (and OpenAI which is tracked separately)
            if account.kind not in AI_COGNITIVE_KINDS or account.kind == "OpenAI":
                continue

            result["accounts"].append(
                {
                    "name": account.name,
                    "id": account.id,
                    "kind": account.kind,
                    "location": account.location,
                    "sku": account.sku.name if account.sku else None,
                }
            )

        result["total_resources"] = len(result["accounts"])
        result["available"] = True

    except Exception as e:
        logger.warning("Error discovering Cognitive Services: %s", e)
        result["error"] = str(e)

    return result


def _resource_group_from_id(resource_id: str | None) -> str | None:
    """Extract resource group name from an Azure resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None
