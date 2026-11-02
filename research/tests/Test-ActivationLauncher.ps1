$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\Invoke-SingleTicketSubscriptionActivation.ps1') -Raw
$cut=$source.IndexOf('$requestedTenant = [string]$env:E5ACT_TENANT')
if($cut -lt 0){throw 'Worker boundary missing.'}
$launcher=$source.Substring(0,$cut).Replace('if ($identity.IsSystem -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)', 'if ($false)')
$workerStart=$source.IndexOf('$watch = [Diagnostics.Stopwatch]::StartNew()',$cut)
if($workerStart -lt 0){throw 'Worker initialization boundary missing.'}
$workerInit=$source.Substring($cut,$workerStart-$cut)
$cases=@(
 @{Name='Empty';Body='[Console]::Error.WriteLine("simulated startup failure"); exit 7';Status='WorkerFailed';Code=1},
 @{Name='Invalid';Body='Write-Output "not-json"; exit 8';Status='WorkerFailed';Code=1},
 @{Name='OmittedUpn';Body='if($requestedUpn -ne ""){throw "Expected empty requested UPN."}; Write-Output ''{"Status":"SimulatedResult"}''; exit 0';Status='SimulatedResult';Code=0},
 @{Name='ProvidedUpn';Upn='user@contoso.com';Body='if($requestedUpn -ne "user@contoso.com"){throw "UPN transport changed."}; Write-Output ''{"Status":"SimulatedResult"}''; exit 0';Status='SimulatedResult';Code=0}
)
foreach($case in $cases){
 $directory=Join-Path $PSScriptRoot ('launcher-test-'+$case.Name)
 $null=New-Item -ItemType Directory -Path $directory -Force
 $file=Join-Path $directory 'stub.ps1'
 [IO.File]::WriteAllText($file,$launcher+$workerInit+$case.Body,[Text.UTF8Encoding]::new($false))
 $start=New-Object Diagnostics.ProcessStartInfo
 $start.FileName="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $start.Arguments='-NoProfile -NonInteractive -File "'+$file+'"'
 if($case.Upn){$start.Arguments+=' -UserPrincipalName '+$case.Upn}
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $start.EnvironmentVariables['LOCALAPPDATA']=$directory
 $process=[Diagnostics.Process]::Start($start)
 $output=$process.StandardOutput.ReadToEnd();$errorText=$process.StandardError.ReadToEnd()
 $process.WaitForExit()
 $json=$output.Substring($output.IndexOf('{')) | ConvertFrom-Json
 if($process.ExitCode -ne $case.Code -or $json.Status -ne $case.Status){throw ($case.Name+' failed: '+$output+$errorText)}
 if($case.Name -eq 'Empty' -and $json.StartupError -ne 'simulated startup failure'){throw 'Lost stderr.'}
 if($case.Status -eq 'WorkerFailed'){
  $saved=Get-Content (Join-Path $directory 'E5SubscriptionActivation\latest-result.json') -Raw | ConvertFrom-Json
  if($saved.Status -ne $case.Status){throw 'Lost saved result.'}
 }
 $process.Dispose()
 $case.Name+': PASS'
}
'No licensing code or authentication requests executed.'
