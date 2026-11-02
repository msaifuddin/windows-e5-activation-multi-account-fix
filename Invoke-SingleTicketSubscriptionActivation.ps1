<#
.SYNOPSIS
    Experimental workaround for Windows Enterprise subscription activation failing with
    "EntitlementExpectedForEachTenantId" when the user has more than one work/school account.

.DESCRIPTION
    Windows' normal subscription acquisition submits a token for EVERY Entra (AAD) account
    registered in the user's Web Account Manager. If any of those accounts belongs to a tenant
    without a Windows Enterprise entitlement, the Store licensing service rejects the whole
    request (HTTP 400, EntitlementExpectedForEachTenantId) and the device stays on Pro.

    This script silently obtains a Store token for ONE selected account in the device's join
    tenant and passes it explicitly to the OS licensing COM interface
    (IOperatingSystemLicenseManager2::ActivateLicenseForContentWithUserTicketAndType).
    A non-empty explicit ticket skips the "collect all account tickets" path.
    Microsoft's service still validates the token and the entitlement.

    No product keys are changed, no accounts or token caches are removed, no Windows files are
    patched and no services are restarted. The interface is UNDOCUMENTED and UNSUPPORTED.

    Run as the signed-in user (not SYSTEM), in 64-bit Windows PowerShell 5.1.

.PARAMETER TenantId
    Entra tenant that holds the Windows Enterprise entitlement. Defaults to the tenant the
    device is Entra joined to.

.PARAMETER UserPrincipalName
    Exact WAM account to use. Takes precedence over -AccountDomain.

.PARAMETER AccountDomain
    Select the single WAM account whose UPN ends in @<AccountDomain>.
    If neither -UserPrincipalName nor -AccountDomain is given, the script proceeds only when
    exactly one Entra account is available to the Store client.

.PARAMETER ProbeOnly
    Check that the licensing interface and subscription policy are readable. No token or license
    request is made.

.LINK
    README.md in this repository.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [ValidatePattern('^[^"\s]+@[^"\s]+$')][string]$UserPrincipalName,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$')][string]$AccountDomain,
    [ValidateRange(15,90)][int]$TimeoutSeconds = 45,
    [switch]$ProbeOnly,
    [switch]$Worker
)
$ErrorActionPreference = 'Stop'
$script:Version = '2.5-public'

# Keep an independent result file in case an RMM host loses stdout.
$script:resultDirectory=Join-Path $env:LOCALAPPDATA 'E5SubscriptionActivation'
$script:resultFile=Join-Path $script:resultDirectory 'latest-result.json'
function Save-ActivationResult($Value) {
    $Value['ScriptVersion']=$script:Version
    $Value['UpdatedUtc']=[DateTime]::UtcNow.ToString('o')
    $Value['ResultFile']=$script:resultFile
    $json=$Value | ConvertTo-Json -Depth 6
    try {
        $null=New-Item -ItemType Directory -Path $script:resultDirectory -Force
        [IO.File]::WriteAllText($script:resultFile,$json,[Text.UTF8Encoding]::new($false))
    } catch {} # Logging must not suppress the actual result.
    return $json
}
function Get-SafeStartupError([string]$Text) {
    # The worker never deliberately prints credentials. Also redact JWTs/bearer
    # values from incidental PowerShell errors before returning them.
    $Text=[regex]::Replace($Text,'[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}','[REDACTED JWT]')
    $Text=[regex]::Replace($Text,'(?i)Bearer\s+[^\s]+','Bearer [REDACTED]')
    if($Text.Length -gt 2000){$Text=$Text.Substring(0,2000)}
    return $Text.Trim()
}
function New-StoreTokenRequest($Provider,[Guid]$RequestedTenant) {
    # Preserve the native licensing client's braces. WAM includes this exact
    # string in its redirect URI; dropping the braces causes AADSTS50011.
    $clientId='{268761a2-03f3-40df-8a8b-c3db24145b6b}'
    $request=[Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($Provider,'',$clientId)
    [E5Native]::ConfigureTokenRequest($request.Properties,$RequestedTenant.ToString())
    $request.CorrelationId=[Guid]::NewGuid()
    return $request
}

# Launcher: supervise a separate process so a blocked COM call cannot hang the automation.
# Only metadata/JSON crosses stdout. Tokens stay in the worker's memory.
if (-not $Worker) {
    Write-Output "E5 subscription activation $($script:Version): launcher started."
    $bootstrapStage='CheckExecutionContext'
    try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.IsSystem -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
        Save-ActivationResult ([ordered]@{ComputerName=$env:COMPUTERNAME;Status='WrongExecutionContext';Stage=$bootstrapStage;RunAs=$identity.Name;SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;Message='Run as the signed-in user in an interactive session (RMM: "current logged-on user").'})
        exit 1
    }
    $bootstrapStage='PrepareWorker'
    $null=Save-ActivationResult ([ordered]@{ComputerName=$env:COMPUTERNAME;Status='Running';Stage=$bootstrapStage;RunAs=$identity.Name})
    if (-not $PSCommandPath) { throw 'Save/import this complete script as a .ps1 file before running it.' }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Worker'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['E5ACT_TENANT'] = $TenantId
    $start.EnvironmentVariables['E5ACT_UPN'] = $UserPrincipalName
    $start.EnvironmentVariables['E5ACT_DOMAIN'] = $AccountDomain
    $start.EnvironmentVariables['E5ACT_PROBE'] = [string][int][bool]$ProbeOnly
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        $bootstrapStage='LaunchWorker'
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            # Stop only our helper, never a Windows licensing service.
            try { $process.Kill(); $process.WaitForExit() } catch {}
            $lastStage=$bootstrapStage
            try {$lastStage=(Get-Content -LiteralPath $script:resultFile -Raw | ConvertFrom-Json).Stage} catch {}
            Save-ActivationResult ([ordered]@{ComputerName=$env:COMPUTERNAME;Status='OperationTimedOut';Stage=$lastStage;TimeoutSeconds=$TimeoutSeconds;Message='The helper exceeded its deadline. Activation is unconfirmed; Windows may still finish an already-submitted request.'})
            exit 1
        }
        $bootstrapStage='ReadWorkerResult'
        $text = $stdout.GetAwaiter().GetResult().Trim()
        $errorText=Get-SafeStartupError ($stderr.GetAwaiter().GetResult())
        try {
            if([string]::IsNullOrWhiteSpace($text)){throw 'Empty worker output.'}
            $decoded=$text | ConvertFrom-Json
            if($null -eq $decoded -or -not $decoded.Status){throw 'Missing result status.'}
        } catch {
            Save-ActivationResult ([ordered]@{ComputerName=$env:COMPUTERNAME;Status='WorkerFailed';Stage=$bootstrapStage;ExitCode=$process.ExitCode;WorkerOutputLength=$text.Length;StartupError=$errorText;Message='The helper did not return a JSON result. See StartupError and ExitCode.'})
            exit 1
        }
        Write-Output $text
        exit $process.ExitCode
    } finally { $process.Dispose() }
    } catch {
        $exception=$_.Exception
        while($exception.InnerException){$exception=$exception.InnerException}
        Save-ActivationResult ([ordered]@{ComputerName=$env:COMPUTERNAME;Status='LauncherFailed';Stage=$bootstrapStage;ErrorHResult=('0x'+$exception.HResult.ToString('X8'));StartupError=(Get-SafeStartupError $exception.Message)})
        exit 1
    }
}

# ---------------------------------------------------------------- worker
# Keep worker transport values separate from the validated script parameters:
# reassigning a validated parameter to an empty string throws in PowerShell 5.1
# before the worker's try/catch is entered.
$requestedTenant = [string]$env:E5ACT_TENANT
$requestedUpn = [string]$env:E5ACT_UPN
$requestedDomain = [string]$env:E5ACT_DOMAIN
$probeOnlyRequested = ($env:E5ACT_PROBE -eq '1')
$watch = [Diagnostics.Stopwatch]::StartNew()
$result = [ordered]@{
    ComputerName=$env:COMPUTERNAME;Status='Started';Stage='Preflight'
    TenantId=$null;RunAs=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    OsBuild=$null;SelectedAccount=$null;EditionBefore=$null;EditionAfter=$null
    ContentId=$null;TokenStatus=$null;TokenTenantMatched=$false;TokenUserMatched=$null
    AcquisitionHResult=$null;SubscriptionUpdateHResult=$null
    SubscriptionStatus=$null;EnterpriseSubscriptionActive=$false
    ElapsedSeconds=0;Message=$null
}
function Complete-Activation([string]$Status,[string]$Message,[int]$ExitCode) {
    $result.Status=$Status; $result.Message=$Message
    $result.ElapsedSeconds=[math]::Round($watch.Elapsed.TotalSeconds,1)
    Save-ActivationResult $result
    exit $ExitCode
}
function Save-ActivationProgress {
    $result.ElapsedSeconds=[math]::Round($watch.Elapsed.TotalSeconds,1)
    $null=Save-ActivationResult $result
}
function Add-FreshLicensingDiagnostics([datetime]$Since) {
    # Collect only this activation attempt, not unrelated historical errors.
    try {
        $events=Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Store/Operational';Id=8002,8003;StartTime=$Since
        } -MaxEvents 8 -ErrorAction Stop
        $result['LicensingDiagnostics']=@($events | ForEach-Object {
            [ordered]@{TimeUtc=$_.TimeCreated.ToUniversalTime().ToString('o');EventId=$_.Id;Message=(Get-SafeStartupError $_.Message)}
        })
    } catch {
        $result['LicensingDiagnostics']=@()
        $result['DiagnosticReadStatus']=$_.FullyQualifiedErrorId
    }
}
function Get-Edition {
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5
    switch ([int]$os.OperatingSystemSKU) { 48 {'Professional'} 4 {'Enterprise'} default {"SKU:$($os.OperatingSystemSKU)"} }
}
function Update-SubscriptionState {
    $result.EditionAfter=Get-Edition
    $service=Get-CimInstance SoftwareLicensingService -OperationTimeoutSec 5
    $property=$service.PSObject.Properties['SubscriptionStatus']
    if($null -ne $property){$result.SubscriptionStatus=$property.Value}
    $result.EnterpriseSubscriptionActive=($result.EditionAfter -eq 'Enterprise' -and $result.SubscriptionStatus -eq 1)
}

try {
    Save-ActivationProgress
    if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){
        Complete-Activation 'UnsupportedPowerShell' 'Use 64-bit Windows PowerShell 5.1.' 1
    }
    $cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.OsBuild="$($cv.CurrentBuildNumber).$($cv.UBR)"
    $result.EditionBefore=Get-Edition
    if($result.EditionBefore -notin @('Professional','Enterprise')){
        Complete-Activation 'UnsupportedEdition' 'Only Pro and Enterprise are handled.' 1
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
public static class E5Native {
 public static readonly List<string> AcquisitionTrace=new List<string>();
 static int Record(string stage,int hr){AcquisitionTrace.Add(stage+": 0x"+hr.ToString("X8"));return hr;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int PackageNameAndPublisherIdFromFamilyName(string family,ref uint nameLength,StringBuilder name,ref uint publisherLength,StringBuilder publisher);
 public static string ContentIdForPackageFamily(string family){
   uint nameLength=0,publisherLength=0;
   int error=PackageNameAndPublisherIdFromFamilyName(family,ref nameLength,null,ref publisherLength,null);
   if(error!=122)throw new System.ComponentModel.Win32Exception(error);
   var name=new StringBuilder((int)nameLength);var publisher=new StringBuilder((int)publisherLength);
   error=PackageNameAndPublisherIdFromFamilyName(family,ref nameLength,name,ref publisherLength,publisher);
   if(error!=0)throw new System.ComponentModel.Win32Exception(error);
   // Same deterministic content identity as ClipWinRT's GetContentId:
   // lowercase "name:publisher:win32", UTF-16LE, SHA-256, first 16 bytes as a GUID.
   string identity=(name.ToString()+":"+publisher.ToString()+":win32").ToLowerInvariant();
   using(var sha=SHA256.Create()){
     byte[] hash=sha.ComputeHash(Encoding.Unicode.GetBytes(identity));
     byte[] guid=new byte[16];Array.Copy(hash,guid,16);return new Guid(guid).ToString("D");
   }
 }
 public static void ConfigureTokenRequest(object properties,string tenant){
   // PowerShell sees the WinRT IMap as System.__ComObject. The typed
   // IDictionary projection supplies the adapter required to write it.
   var map=(IDictionary<string,string>)properties;
   string authority="https://login.microsoftonline.com/"+new Guid(tenant).ToString();
   map["resource"]="https://onestore.microsoft.com";
   map["authority"]=authority;
   if(map["resource"]!="https://onestore.microsoft.com"||map["authority"]!=authority)
     throw new InvalidOperationException("WAM request properties did not match after configuration.");
 }
 [DllImport("ole32.dll",ExactSpelling=true)] static extern int CoCreateInstance(ref Guid c,IntPtr outer,uint context,ref Guid iid,out IntPtr obj);
 [DllImport("ole32.dll",ExactSpelling=true)] static extern int CoSetProxyBlanket(IntPtr obj,uint authn,uint authz,IntPtr principal,uint level,uint impersonation,IntPtr auth,uint capabilities);
 [DllImport("slc.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int SLGetWindowsInformation(string name,out uint type,out uint length,out IntPtr data);
 [DllImport("kernel32.dll",ExactSpelling=true)] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("netapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int NetGetAadJoinInformation(string tenant,out IntPtr info);
 [DllImport("netapi32.dll",ExactSpelling=true)] static extern void NetFreeAadJoinInformation(IntPtr info);
 [StructLayout(LayoutKind.Sequential)] struct JoinInfo { public int Type; public IntPtr Cert,DeviceId,IdpDomain,TenantId,UserEmail; }
 [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)] delegate int Acquire(IntPtr self,[MarshalAs(UnmanagedType.LPWStr)] string content,[MarshalAs(UnmanagedType.LPWStr)] string ticket,int type,out IntPtr license);
 [DllImport("clipc.dll",ExactSpelling=true)] static extern int ClipOpen(out IntPtr handle);
 [DllImport("clipc.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int ClipCallServer(IntPtr handle,string command,uint length,IntPtr data);
 [DllImport("clipc.dll",ExactSpelling=true)] static extern void ClipClose(IntPtr handle);
 public static string JoinTenant(){
   IntPtr p;int hr=NetGetAadJoinInformation(null,out p);Marshal.ThrowExceptionForHR(hr);
   if(p==IntPtr.Zero)return null;
   try{var info=(JoinInfo)Marshal.PtrToStructure(p,typeof(JoinInfo));return info.Type==1?Marshal.PtrToStringUni(info.TenantId):null;}
   finally{NetFreeAadJoinInformation(p);}
 }
 public static string Policy(string name){
   uint type,length;IntPtr p;int hr=SLGetWindowsInformation(name,out type,out length,out p);Marshal.ThrowExceptionForHR(hr);
   try{if(type!=1||length<2)throw new InvalidOperationException("Policy is not a string.");return Marshal.PtrToStringUni(p);}
   finally{if(p!=IntPtr.Zero)LocalFree(p);}
 }
 // CLSID of the OS license manager (out-of-process, CLSCTX_LOCAL_SERVER) and IID of
 // IOperatingSystemLicenseManager2, taken from public symbols / binaries of Windows 11 26100.
 public static IntPtr Open(){
   Guid c=new Guid("22f5b1df-7d7a-4d21-97f8-c21aefba859c"),i=new Guid("9bb0f3fe-bcf3-4287-96b4-74fc6da8d7c3");
   IntPtr p;int hr=CoCreateInstance(ref c,IntPtr.Zero,4,ref i,out p);Marshal.ThrowExceptionForHR(hr);
   return p;
 }
 public static int Activate(string content,string ticket){
   AcquisitionTrace.Clear();
   IntPtr p=Open(),license=IntPtr.Zero;
   Record("CreateOperatingSystemLicenseManager2",0);
   try{
     // RPC_C_IMP_LEVEL_IMPERSONATE + EOAC_DYNAMIC_CLOAKING so the service sees the calling user.
     int hr=CoSetProxyBlanket(p,0xffffffff,0xffffffff,new IntPtr(-1),0,3,IntPtr.Zero,0x800);
     Record("SetOperatingSystemProxyBlanket",hr);
     if(hr<0)return hr;
     // Do not call InvalidateCacheForContentWithId first: it captures the ordinary
     // (all-accounts) identity without our ticket and can fail before this request.
     // IOperatingSystemLicenseManager2 vtable: 0-2 IUnknown, 3 ActivateLicenseForContent,
     // 4 ...WithUserTicket, 5 ...WithUserTicketAndType.
     IntPtr fn=Marshal.ReadIntPtr(Marshal.ReadIntPtr(p),5*IntPtr.Size);
     // LicenseUserTicketType: 0 = MSA, 1 = AAD. A non-empty ticket skips GetAllAccountTickets.
     hr=((Acquire)Marshal.GetDelegateForFunctionPointer(fn,typeof(Acquire)))(p,content,ticket,1,out license);
     return Record("ActivateWithAadTicket",hr);
   }finally{if(license!=IntPtr.Zero)Marshal.Release(license);Marshal.Release(p);}
 }
 public static int UpdateSubscription(){
   IntPtr handle;int hr=ClipOpen(out handle);if(hr<0)return hr;
   try{return ClipCallServer(handle,"ClipCallServerUpdateSubscriptionData",0,IntPtr.Zero);}
   finally{ClipClose(handle);}
 }
 public static string SidFromObjectId(string oid){
   byte[] bytes=new Guid(oid).ToByteArray();
   return "S-1-12-1-"+BitConverter.ToUInt32(bytes,0)+"-"+BitConverter.ToUInt32(bytes,4)+"-"+BitConverter.ToUInt32(bytes,8)+"-"+BitConverter.ToUInt32(bytes,12);
 }
}
'@
    $joinedTenant=[E5Native]::JoinTenant()
    if(-not $joinedTenant){Complete-Activation 'NotEntraJoined' 'The device is not Entra joined.' 1}
    if(-not $requestedTenant){$requestedTenant=$joinedTenant}
    $TenantGuid=[Guid]$requestedTenant
    $result.TenantId=$TenantGuid.ToString()
    if($joinedTenant -ne $result.TenantId){
        Complete-Activation 'JoinedTenantMismatch' 'The device is not Entra joined to the requested tenant.' 1
    }
    $packageFamily=[E5Native]::Policy('Clip-SubscriptionPFN')
    $result['PackageFamilyName']=$packageFamily
    if([string]::IsNullOrWhiteSpace($packageFamily) -or $packageFamily -eq 'EMPTY'){
        Complete-Activation 'SubscriptionContentUnavailable' 'Windows did not supply a subscription content ID.' 1
    }
    $result.ContentId=[E5Native]::ContentIdForPackageFamily($packageFamily)
    $interface=[E5Native]::Open()
    $null=[Runtime.InteropServices.Marshal]::Release($interface)
    if($probeOnlyRequested){Complete-Activation 'InterfaceAvailable' 'The OS licensing interface and subscription policy are readable. No token or license was requested.' 0}
    Update-SubscriptionState
    if($result.EnterpriseSubscriptionActive){Complete-Activation 'AlreadyActive' 'An active Enterprise subscription is already reported.' 0}

    $result.Stage='SelectAccount'
    Save-ActivationProgress
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null=[Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
    $null=[Windows.Security.Credentials.WebAccountProvider,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $null=[Windows.Security.Authentication.Web.Core.FindAllAccountsResult,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
    $null=[Windows.Security.Authentication.Web.Core.WebTokenRequest,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
    $null=[Windows.Security.Authentication.Web.Core.WebTokenRequestResult,Windows.Security.Authentication.Web.Core,ContentType=WindowsRuntime]
    $script:asTask=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    function Await-Wam($Operation,[Type]$ResultType){
        $task=$script:asTask.MakeGenericMethod($ResultType).Invoke($null,@($Operation))
        try {if(-not $task.Wait(10000)){throw [TimeoutException]::new('WAM timeout.')}} catch {if($task.Exception){throw $task.Exception.Flatten().InnerException};throw}
        return $task.GetAwaiter().GetResult()
    }
    $provider=Await-Wam ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync('https://login.microsoft.com','organizations')) ([Windows.Security.Credentials.WebAccountProvider])
    if($null -eq $provider){Complete-Activation 'NoAadProvider' 'The signed-in user has no available Entra WAM provider.' 1}
    $storeClient='268761a2-03f3-40df-8a8b-c3db24145b6b'
    $found=Await-Wam ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAllAccountsAsync($provider,$storeClient)) ([Windows.Security.Authentication.Web.Core.FindAllAccountsResult])
    if([string]$found.Status -ne 'Success'){Complete-Activation 'AccountEnumerationFailed' 'WAM did not return the accounts available to the Store client.' 1}
    $accounts=@($found.Accounts | Where-Object {
        if($requestedUpn){$_.UserName -ieq $requestedUpn}
        elseif($requestedDomain){$_.UserName -like "*@$requestedDomain"}
        else{$true}
    })
    $result['CandidateAccountCount']=$accounts.Count
    if($accounts.Count -ne 1){Complete-Activation 'AccountSelectionRequired' 'Specify -UserPrincipalName or -AccountDomain so that exactly one WAM account is selected.' 1}
    $account=$accounts[0]
    $result.SelectedAccount=$account.UserName
    $result.Stage='CreateTokenRequest'
    Save-ActivationProgress
    $request=New-StoreTokenRequest $provider $TenantGuid
    $result['TokenRequestClientId']=$request.ClientId
    $result['TokenRequestCorrelationId']=$request.CorrelationId.ToString()
    $result.Stage='RequestSilentToken'
    Save-ActivationProgress
    $response=Await-Wam ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($request,$account)) ([Windows.Security.Authentication.Web.Core.WebTokenRequestResult])
    $result.TokenStatus=[string]$response.ResponseStatus
    if($result.TokenStatus -ne 'Success'){
        if($null -ne $response.ResponseError){
            $result['TokenProviderErrorCode']='0x'+$response.ResponseError.ErrorCode.ToString('X8')
            $result['TokenProviderErrorMessage']=Get-SafeStartupError $response.ResponseError.ErrorMessage
        }
        Complete-Activation 'SilentTokenUnavailable' 'WAM could not issue the Store token silently. No activation request was sent.' 1
    }
    if($response.ResponseData.Count -ne 1){Complete-Activation 'UnexpectedTokenCount' 'WAM did not return exactly one response.' 1}
    $ticket=$response.ResponseData[0].Token
    # Decode only to guard tenant/user selection. Microsoft validates the token and entitlement.
    $parts=$ticket.Split('.')
    if($parts.Count -ne 3){Complete-Activation 'UnexpectedTokenFormat' 'WAM did not return an inspectable AAD JWT.' 1}
    $payload=$parts[1].Replace('-','+').Replace('_','/')
    while(($payload.Length % 4) -ne 0){$payload+='='}
    $claims=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
    $result.TokenTenantMatched=([string]$claims.tid -eq $result.TenantId)
    if(-not $result.TokenTenantMatched){Complete-Activation 'TokenTenantMismatch' 'The broker returned a token from another tenant; it was not submitted.' 1}
    # Audience: Windows Store for Business resource / first-party app ID.
    if([string]$claims.aud -notin @('https://onestore.microsoft.com','https://onestore.microsoft.com/','45a330b1-b1ec-4cc1-9161-9f03992aa49f')){
        Complete-Activation 'TokenAudienceMismatch' 'The broker returned a token for a different service; it was not submitted.' 1
    }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($sid -like 'S-1-12-1-*'){
        $result.TokenUserMatched=([E5Native]::SidFromObjectId([string]$claims.oid) -eq $sid)
        if(-not $result.TokenUserMatched){Complete-Activation 'TokenUserMismatch' 'The token does not belong to the signed-in Entra user; it was not submitted.' 1}
    }
    $result.Stage='AcquireLicenseWithSelectedTicket'
    Save-ActivationProgress
    $acquisitionStarted=(Get-Date).AddSeconds(-1)
    $hr=[E5Native]::Activate($result.ContentId,$ticket)
    $result['AcquisitionTrace']=@([E5Native]::AcquisitionTrace)
    $ticket=$null;$response=$null;$claims=$null;$payload=$null;$parts=$null
    $result.AcquisitionHResult='0x'+$hr.ToString('X8')
    if($hr -lt 0){
        Add-FreshLicensingDiagnostics $acquisitionStarted
        Complete-Activation 'SingleTenantAcquisitionFailed' 'Direct activation with the selected AAD ticket failed. See AcquisitionTrace and LicensingDiagnostics.' 1
    }
    $result.Stage='UpdateSubscription'
    Save-ActivationProgress
    $hr=[E5Native]::UpdateSubscription()
    $result.SubscriptionUpdateHResult='0x'+$hr.ToString('X8')
    if($hr -lt 0){Complete-Activation 'SubscriptionUpdateFailed' 'The license request succeeded, but Windows rejected the subscription update.' 1}
    $result.Stage='VerifyActivation'
    Save-ActivationProgress
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do {
        Update-SubscriptionState
        if($result.EnterpriseSubscriptionActive){Complete-Activation 'EnterpriseSubscriptionActive' 'Windows reports Enterprise with an active subscription.' 0}
        Start-Sleep -Seconds 2
    }while([DateTime]::UtcNow -lt $deadline)
    Complete-Activation 'ActivationNotConfirmed' 'The explicit request and subscription update succeeded, but active Enterprise was not confirmed within 10 seconds.' 1
}catch{
    # Do not emit token-bearing objects.
    $exception=$_.Exception
    while($exception.InnerException){$exception=$exception.InnerException}
    $result['ErrorHResult']='0x'+$exception.HResult.ToString('X8')
    $result['ErrorType']=$exception.GetType().FullName
    $result['ErrorId']=$_.FullyQualifiedErrorId
    $result['ErrorLine']=$_.InvocationInfo.ScriptLineNumber
    if($result.Stage -in @('CreateTokenRequest','RequestSilentToken')){
        $result['ErrorDetail']=Get-SafeStartupError $exception.Message
    }
    Complete-Activation 'ExecutionFailed' 'The operation failed at the reported Stage. No token data is included in this output.' 1
}finally{
    $ticket=$null;$response=$null;$claims=$null;$payload=$null;$parts=$null
}
