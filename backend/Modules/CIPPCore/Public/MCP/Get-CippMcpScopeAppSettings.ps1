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

        Scope vs resource are two different levers and only the resource must change to fix the
        silent-refresh failure:

        - The advertised SCOPE (challenge header + scopes_supported) is what a client requests at
          AUTHORIZE / consent time. It stays the host-based https://<host>/user_impersonation form,
          which Entra has consented cleanly for every MCP client. Requesting the api://<appId> form
          of the scope at authorize is rejected with AADSTS28003 for this app because CIPP uses ONE
          API-client app as both the OAuth public client and the protected resource.

        - The protected-resource identifier (CRAFT_PRM.resource) is the value a client echoes back
          as the RFC 8707 resource indicator on the non-interactive refresh_token grant. When that
          was the https:// identifier URI, Entra resolved it to the very app making the request and
          rejected the refresh with AADSTS90009 ("Application is requesting a token for itself. This
          scenario is supported only if resource is specified using the GUID based App Identifier"),
          so the connection silently dropped at the access-token lifetime (~60-90 min). Advertising
          api://<appId> names the resource by its GUID, which is exactly the form Entra permits for
          the client==resource case, so the refresh succeeds.

        The v2 access token's audience is the resource app's appId GUID regardless of which form was
        requested, and Set-CippApiAuth already allows api://<appId>, the bare appId and the https://
        URIs as audiences, so EasyAuth validation is unaffected either way.
    .PARAMETER Hostname
        The App Service hostname (WEBSITE_HOSTNAME) - the *.azurewebsites.net host that matches the
        MCP client app registration's identifier URIs, not the vanity domain. Used to build the
        host-based authorize-time scope.
    .PARAMETER AppId
        Application (client) ID of the MCP resource app registration - the single API client with
        MCP access enabled. The protected-resource identifier (api://<appId>) is built from it so
        the refresh grant names the resource by GUID and Entra accepts the self-token case.
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
        [string]$Hostname,

        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [switch]$IsCippNg
    )

    # Authorize-time scope stays host-based (consented cleanly; the api:// form 28003s at authorize).
    $McpScope = "https://$Hostname/user_impersonation"
    $McpScopesSupported = @('openid', 'profile', 'offline_access', $McpScope)
    # Refresh-time resource indicator must be the GUID app identifier to avoid AADSTS90009.
    $ResourceUri = "api://$AppId"

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
