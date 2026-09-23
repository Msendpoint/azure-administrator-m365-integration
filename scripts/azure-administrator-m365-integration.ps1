### FILE: index.php
<?php 
// Logic to fetch data from Graph and call render_premium_card multiple times to build the dashboard...
$endpoint = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies';
$accessToken = $_SESSION['ms_access_token'];
$response = $ms->graphCall($endpoint, $accessToken);

render_premium_card('Conditional Access Policies', 'Summary', count($response['value']));
// Additional cards can be rendered similarly...
?>

### FILE: scripts/Automation.ps1
<#
.SYNOPSIS
    PowerShell script to audit and automate Azure and Microsoft 365 integrations.

.DESCRIPTION
    This script connects to Microsoft Graph, audits custom RBAC roles, validates managed identity federation, and inspects diagnostic settings on storage accounts.

.EXAMPLE
    .\Automation.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000000' -ResourceGroupName 'myResourceGroup' -StorageAccountName 'myStorageAccount'

.NOTES
    Author:      Souhaiel Morhag
    Company:     MSEndpoint.com
    Blog:        https://msendpoint.com
    Academy:     https://app.msendpoint.com/academy
    LinkedIn:    https://linkedin.com/in/souhaiel-morhag
    GitHub:      https://github.com/Msendpoint
    License:     MIT
#>

#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$StorageAccountName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── 1. Connect to Microsoft Graph (required scopes) ──────────────────────────
$requiredScopes = @(
    'RoleManagement.Read.Directory',
    'Directory.Read.All',
    'Policy.Read.All'
)

try {
    Write-Host "[INFO] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $context = Get-MgContext
    Write-Host "[OK]   Connected as: $($context.Account) | TenantId: $($context.TenantId)" `
        -ForegroundColor Green
}
catch {
    Write-Error "[FATAL] Graph connection failed: $_"
    exit 1
}

# ── 2. Enumerate Custom RBAC Roles scoped to Resource Group ──────────────────
Write-Host "`n[DOMAIN: Identity & Governance] Auditing custom RBAC role assignments..." `
    -ForegroundColor Magenta

$rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

try {
    # Using Invoke-MgGraphRequest for ARM endpoint — Graph doesn't expose ARM RBAC
    $armToken = (Get-MgContext).AccessToken
    $armHeaders = @{ Authorization = "Bearer $armToken"; 'Content-Type' = 'application/json' }

    $assignmentsUri = "https://management.azure.com$($rgScope)/providers/" +
        "Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

    $assignments = Invoke-RestMethod -Method GET -Uri $assignmentsUri `
        -Headers $armHeaders

    $customAssignments = $assignments.value | Where-Object {
        $_.properties.roleDefinitionId -notmatch `
            '/providers/Microsoft.Authorization/roleDefinitions/[a-f0-9-]{36}'
    }

    Write-Host "[OK]   Total assignments on $ResourceGroupName : $($assignments.value.Count)"
    Write-Host "[INFO] Assignments referencing custom role definitions: $($customAssignments.Count)"

    foreach ($a in $assignments.value) {
        $roleDefId = $a.properties.roleDefinitionId.Split('/')[-1]
        $roleDef = Invoke-RestMethod -Method GET `
            -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($roleDefId)?api-version=2022-04-01" `
            -Headers $armHeaders
        
        $isCustom = $roleDef.properties.type -eq 'CustomRole'
        $customTag = if ($isCustom) { "[CUSTOM]" } else { "[BUILTIN]" }
        Write-Host "  $customTag $($roleDef.properties.roleName) → $($a.properties.principalId)"
    }
}
catch {
    Write-Warning "[WARN] RBAC enumeration failed: $_"
}

# ── 3. Validate Managed Identity Federation Status ────────────────────────────
Write-Host "`n[DOMAIN: Identity & Governance] Checking User-Assigned Managed Identities..." `
    -ForegroundColor Magenta

try {
    # Query Graph for Service Principals with ServicePrincipalType = ManagedIdentity
    $miFilter = "servicePrincipalType eq 'ManagedIdentity'"
    $managedIdentities = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$miFilter&`$select=id,displayName,servicePrincipalType,appId"

    Write-Host "[OK]   Managed Identity Service Principals found: $($managedIdentities.value.Count)"

    foreach ($mi in $managedIdentities.value) {
        # Check federated identity credentials (AZ-104 objective: OIDC federation)
        $fedCreds = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($mi.id)/federatedIdentityCredentials"

        $fedCount = $fedCreds.value.Count
        $fedStatus = if ($fedCount -gt 0) { "[$fedCount federated credentials]" } else { "[No federation]" }
        Write-Host "  MI: $($mi.displayName) | AppId: $($mi.appId) $fedStatus"
    }
}
catch {
    Write-Warning "[WARN] Managed Identity query failed: $_"
}

# ── 4. Validate Diagnostic Settings on Storage Account ───────────────────────
Write-Host "`n[DOMAIN: Monitor] Validating Diagnostic Settings on Storage Account..." `
    -ForegroundColor Magenta

try {
    $storageResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
        "/providers/Microsoft.Storage/storageAccounts/$StorageAccountName"

    $diagUri = "https://management.azure.com$($storageResourceId)" +
        "/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"

    $diagSettings = Invoke-RestMethod -Method GET -Uri $diagUri -Headers $armHeaders

    if ($diagSettings.value.Count -eq 0) {
        Write-Warning "[WARN] No diagnostic settings configured on $StorageAccountName"
        Write-Warning "       AZ-104 Objective: Configure Azure Monitor diagnostic settings"
    }
    else {
        foreach ($ds in $diagSettings.value) {
            $sink = if ($ds.properties.workspaceId) { "Log Analytics" } `
                    elseif ($ds.properties.storageAccountId) { "Storage" } `
                    elseif ($ds.properties.eventHubAuthorizationRuleId) { "Event Hub" } `
                    else { "Unknown" }
            Write-Host "[OK]   DiagSetting: '$($ds.name)' → Sink: $sink"
        }
    }
}
catch {
    Write-Warning "[WARN] Diagnostic settings check failed: $_"
}

# ── 5. Conditional Access Policy Inventory (Governance cross-check) ──────────
Write-Host "`n[DOMAIN: Identity & Governance] Enumerating Conditional Access Policies..." `
    -ForegroundColor Magenta

if ($PSCmdlet.ShouldProcess("Entra ID Tenant", "Read Conditional Access Policies")) {
    try {
        $caPolicies = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=displayName,state,conditions,grantControls"

        $enabledCount  = ($caPolicies.value | Where-Object { $_.state -eq 'enabled' }).Count
        $reportOnly    = ($caPolicies.value | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
        $disabledCount = ($caPolicies.value | Where-Object { $_.state -eq 'disabled' }).Count

        Write-Host "[OK]   CA Policies — Enabled: $enabledCount | Report-Only: $reportOnly | Disabled: $disabledCount"
    }
    catch {
        Write-Warning "[WARN] Conditional Access read failed (check Policy.Read.All scope): $_"
    }
}

Write-Host "`n[COMPLETE] AZ-104 Lab Validation finished." -ForegroundColor Green
exit 0