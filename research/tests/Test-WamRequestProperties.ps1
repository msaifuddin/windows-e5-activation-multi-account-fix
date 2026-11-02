$ErrorActionPreference='Stop'
try {
 $null=[Windows.Security.Credentials.WebAccountProvider,Windows.Security.Credentials,ContentType=WindowsRuntime]
 $null=[Windows.Security.Authentication.Web.Core.WebTokenRequest,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
 $stage='CreateInMemoryProvider'
 $provider=[Windows.Security.Credentials.WebAccountProvider]::new('https://login.microsoft.com','Local construction test',[Uri]'https://example.org/icon')
 $stage='CreateRequest'
 $request=[Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($provider,'','268761a2-03f3-40df-8a8b-c3db24145b6b')
 $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\Invoke-SingleTicketSubscriptionActivation.ps1') -Raw
 $native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
 Add-Type -TypeDefinition $native
 $stage='ConfigureActualRequestProperties'
 [E5Native]::ConfigureTokenRequest($request.Properties,'00000000-0000-0000-0000-000000000001')
 'Actual wrapper: resource and authority configuration/readback PASS'
}catch{
 'Stage: '+$stage
 'Error: '+$_.FullyQualifiedErrorId
 $_.Exception.ToString()
 exit 1
}
'No authentication request was made.'
