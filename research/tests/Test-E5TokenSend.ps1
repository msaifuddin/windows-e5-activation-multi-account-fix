# Local token-send test only: does not invoke licensing or change Windows activation.
param([Parameter(Mandatory)][Guid]$TenantId,[string]$UserPrincipalName,[switch]$NativeScope,[switch]$NativeClient,[switch]$FromActivationScript,[switch]$AcquireExistingEnterprise)
$ErrorActionPreference='Stop'
$result=[ordered]@{ComputerName=$env:COMPUTERNAME;RunAs=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Stage='Initialize';SelectedAccount=$null;Status=$null;ErrorCode=$null;ErrorMessage=$null}
function Safe-Text([string]$value){
 $value=[regex]::Replace($value,'[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}','[REDACTED JWT]')
 $value=[regex]::Replace($value,'(?i)Bearer\s+[^\s]+','Bearer [REDACTED]')
 if($value.Length -gt 2500){$value=$value.Substring(0,2500)}
 return $value
}
try {
 Add-Type -AssemblyName System.Runtime.WindowsRuntime
 $null=[Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
 $null=[Windows.Security.Credentials.WebAccountProvider,Windows.Security.Credentials,ContentType=WindowsRuntime]
 $null=[Windows.Security.Authentication.Web.Core.FindAllAccountsResult,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
 $null=[Windows.Security.Authentication.Web.Core.WebTokenRequest,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
 $null=[Windows.Security.Authentication.Web.Core.WebTokenRequestResult,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
 Add-Type -TypeDefinition @'
using System.Collections.Generic;
public static class TokenSendMap {
 public static void Configure(object properties,string tenant){
  var map=(IDictionary<string,string>)properties;
  map["resource"]="https://onestore.microsoft.com";
  map["authority"]="https://login.microsoftonline.com/"+tenant;
 }
}
'@
 $script:asTask=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {$_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'} | Select-Object -First 1
 function Await-Wam($op,[Type]$type){
  $task=$script:asTask.MakeGenericMethod($type).Invoke($null,@($op))
  try{if(-not $task.Wait(10000)){throw 'WAM timeout'}}catch{if($task.Exception){throw $task.Exception.Flatten().InnerException};throw}
  return $task.GetAwaiter().GetResult()
 }
 $result.Stage='FindProvider'
 $provider=Await-Wam ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync('https://login.microsoft.com','organizations')) ([Windows.Security.Credentials.WebAccountProvider])
 if($null -eq $provider){throw 'No AAD provider.'}
 $client='268761a2-03f3-40df-8a8b-c3db24145b6b'
 $result.Stage='FindAccount'
 $found=Await-Wam ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAllAccountsAsync($provider,$client)) ([Windows.Security.Authentication.Web.Core.FindAllAccountsResult])
 if([string]$found.Status -ne 'Success'){throw ('Enumeration: '+$found.Status)}
 $accounts=@($found.Accounts | Where-Object {if($UserPrincipalName){$_.UserName -ieq $UserPrincipalName}else{$true}})
 if($accounts.Count -ne 1){throw ('Expected one account (use -UserPrincipalName); found '+$accounts.Count)}
 $account=$accounts[0];$result.SelectedAccount=$account.UserName
 $result.Stage='CreateRequest'
 $scope='';if($NativeScope){$scope='service::www.microsoft.com::mbi_ssl'}
 $result['Scope']=$scope
 if($NativeClient){$client='{'+$client+'}'}
 $result['ClientId']=$client
 if($FromActivationScript){
  $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\Invoke-SingleTicketSubscriptionActivation.ps1') -Raw
  $native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
  Add-Type -TypeDefinition $native
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
  if($errors){throw 'Main script failed to parse.'}
  $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-StoreTokenRequest'},$true)
  if($null -eq $definition){throw 'Production request builder not found.'}
  . ([ScriptBlock]::Create($definition.Extent.Text))
  $request=New-StoreTokenRequest $provider $TenantId
  $result['ClientId']=$request.ClientId
  $result['RequestBuilder']='Activation script function'
 }else{
  $request=[Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($provider,$scope,$client)
  [TokenSendMap]::Configure($request.Properties,$TenantId.ToString())
  $request.CorrelationId=[Guid]::NewGuid()
 }
 $result['CorrelationId']=$request.CorrelationId.ToString()
 $result.Stage='SendSilentRequest'
 $response=Await-Wam ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($request,$account)) ([Windows.Security.Authentication.Web.Core.WebTokenRequestResult])
 $result.Status=[string]$response.ResponseStatus
 if($null -ne $response.ResponseError){
  $result.ErrorCode='0x'+$response.ResponseError.ErrorCode.ToString('X8')
  $result.ErrorMessage=Safe-Text $response.ResponseError.ErrorMessage
 }
 if($AcquireExistingEnterprise -and $result.Status -eq 'Success'){
  if(-not $FromActivationScript){throw 'Use the actual activation script wrapper.'}
  $os=Get-CimInstance Win32_OperatingSystem
  $service=Get-CimInstance SoftwareLicensingService
  $active=@(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseStatus=1" | Where-Object {$_.LicenseFamily -eq 'Enterprise'})
  if($os.OperatingSystemSKU -ne 4 -or ($service.SubscriptionStatus -ne 1 -and $active.Count -eq 0)){throw 'This local test requires an already activated Enterprise installation.'}
  $result.Stage='TestLocalEnterpriseAcquisition'
  $family=[E5Native]::Policy('Clip-SubscriptionPFN')
  $result['PackageFamilyName']=$family
  $content=[E5Native]::ContentIdForPackageFamily($family)
  $result['ContentId']=$content
  $ticket=$response.ResponseData[0].Token
  $hr=[E5Native]::Activate($content,$ticket)
  $ticket=$null
  $result['AcquisitionHResult']='0x'+$hr.ToString('X8')
  $result['AcquisitionTrace']=@([E5Native]::AcquisitionTrace)
  if($hr -lt 0){$result.Status='AcquisitionFailed'}
 }
 # No token contents or response object are persisted.
 $response=$null
 $result.Stage='Complete'
}catch{
 $exception=$_.Exception;while($exception.InnerException){$exception=$exception.InnerException}
 $result.Status='ExecutionFailed';$result.ErrorCode='0x'+$exception.HResult.ToString('X8');$result.ErrorMessage=Safe-Text $exception.Message
}
$json=$result | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'local-token-send-result.json'),$json,[Text.UTF8Encoding]::new($false))
Write-Output $json
if($result.Status -eq 'Success'){exit 0}else{exit 1}
