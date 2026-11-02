$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
$null = [Windows.Security.Credentials.WebAccountProvider,Windows.Security.Credentials,ContentType=WindowsRuntime]
$null = [Windows.Security.Authentication.Web.Core.FindAllAccountsResult,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
$script:asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
 $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1
function Await-Operation($Operation,[Type]$ResultType) {
 $task = $script:asTask.MakeGenericMethod($ResultType).Invoke($null,@($Operation))
 try {if(-not $task.Wait(10000)){throw 'WAM operation exceeded 10 seconds.'}} catch {if($task.Exception){throw $task.Exception.Flatten().InnerException};throw}
 $task.GetAwaiter().GetResult()
}
$provider = Await-Operation ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync('https://login.microsoft.com','organizations')) ([Windows.Security.Credentials.WebAccountProvider])
if($null -eq $provider){throw 'AAD provider unavailable.'}
'Provider found; authority: ' + $provider.Authority
$found = Await-Operation ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAllAccountsAsync($provider,'268761a2-03f3-40df-8a8b-c3db24145b6b')) ([Windows.Security.Authentication.Web.Core.FindAllAccountsResult])
'Status: ' + $found.Status
'Count: ' + $found.Accounts.Count
foreach($account in $found.Accounts){'Property names: '+($account.Properties.Keys -join ', ')}
