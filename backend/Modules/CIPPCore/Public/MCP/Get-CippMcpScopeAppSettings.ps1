function Get-CippMcpScopeAppSettings {
    <#
    .SYNOPSIS
        Builds the App Service settings that advertise the MCP OAuth scopes - the EasyAuth
        challenge header plus the protected-resource / authorization-server discovery documents -
        so a client requests offline_access and Entra issues a refresh token.
    .DESCRIPTION
        Single source of truth for WEBSITE_AUTH_PRM_DEFAULT_WITH_SCOPES and, on CIPPNG/Craft, the
        CRAFT_PRM and CRAFT_PRM_AS documents. Both Invoke-ExecApiClient (Save to Azure) and the
        Initialize-CIPPAuth warmup reconcile write these; defining the values here means the two
        callers cannot drift apart and fight each other with a restart on every warmup.

        offline_access is the load-bearing scope. Without it in the advertised scope set, strict
        discovery clients - e.g. GitHub Copilot CLI, which reads the scope only from the challenge
        header and never falls back to the discovery docs - never request it, so Entra never issues
        a refresh token and the client re-authenticates roughly every hour. (Copilot Studio uses
        Manual OAuth and ignores all of this; its refresh depends on app-registration consent.)

        The resource is advertised by its GUID-based app identifier (api://<appId>), NOT the
        host-based https:// URL, and this is deliberate. CIPP configures ONE API-client app as both
        the OAuth public client (Claude/ChatGPT connect with its own client_id) AND the protected
        resource (its identifier URIs). When a client refreshes, it echoes the RFC 8707 resource
        indicator - the value advertised here as CRAFT_PRM.resource - back to Entra. If that value
        is an https:// identifier URI, Entra resolves it to the very app making the request and
        rejects the refresh with AADSTS90009 ("Application is requesting a token for itself. This
        scenario is supported only if resource is specified using the GUID based App Identifier").
        Advertising api://<appId> instead names the resource by its GUID, which is exactly the form
        Entra permits for the client==resource case, so the non-interactive refresh_token grant
        succeeds and the connection stops silently dropping at the access-token lifetime. The v2
        access token's audience is the resource app's appId GUID either way, so EasyAuth validation
        (Set-CippApiAuth already allows api://<appId>, the bare appId, and the https:// URIs) is
        unaffected by the switch.
    .PARAMETER AppId
        Application (client) ID of the MCP resource app registration - the single API client with
        MCP access enabled. The advertised scope (api://<appId>/user_impersonation) and the
        protected-resource identifier (api://<appId>) are built from it so the refresh grant names
        the resource by GUID and Entra accepts the self-token case (see .DESCRIPTION).
    .PARAMETER TenantId
        Partner tenant ID, used to build the tenanted authorization-server endpoints.
    .PARAMETER IsCippNg
        When set, also emits the CRAFT_PRM / CRAFT_PRM_AS discovery documents (CIPPNG/Craft only).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [switch]$IsCippNg
    )

    $ResourceUri = "api://$AppId"
    $McpScope = "$ResourceUri/user_impersonation"
    $McpScopesSupported = @('openid', 'profile', 'offline_access', $McpScope)

    $Settings = @{
        'WEBSITE_AUTH_PRM_DEFAULT_WITH_SCOPES' = 'openid profile offline_access {0}' -f $McpScope
    }

    if ($IsCippNg) {
        $TenantedLogin = "https://login.microsoftonline.com/$TenantId"
        $Settings['CRAFT_PRM'] = [ordered]@{
            resource                 = $ResourceUri
            authorization_servers    = @('{origin}')
            scopes_supported         = $McpScopesSupported
            bearer_methods_supported = @('header')
        } | ConvertTo-Json -Compress
        $Settings['CRAFT_PRM_AS'] = [ordered]@{
            issuer                                = '{origin}'
            authorization_endpoint                = "$TenantedLogin/oauth2/v2.0/authorize"
            token_endpoint                        = "$TenantedLogin/oauth2/v2.0/token"
            jwks_uri                              = "$TenantedLogin/discovery/v2.0/keys"
            registration_endpoint                 = '{origin}/api/PublicMcpRegister'
            response_types_supported              = @('code')
            response_modes_supported              = @('query', 'form_post')
            grant_types_supported                 = @('authorization_code', 'refresh_token')
            code_challenge_methods_supported      = @('S256')
            token_endpoint_auth_methods_supported = @('none', 'client_secret_post', 'client_secret_basic')
            scopes_supported                      = $McpScopesSupported
        } | ConvertTo-Json -Compress
    }

    return $Settings
}
