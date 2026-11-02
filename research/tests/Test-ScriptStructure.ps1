$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '..\..\Invoke-SingleTicketSubscriptionActivation.ps1'
$source=Get-Content -LiteralPath $path -Raw
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors){throw ($errors | Out-String)}
'PowerShell 5.1 parse: PASS'
$native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
if(-not $native){throw 'Native wrapper not found.'}
Add-Type -TypeDefinition $native
'C# wrapper compilation: PASS'
$p=[E5Native]::Open()
if($p -eq [IntPtr]::Zero){throw 'OS licensing interface was null.'}
$null=[Runtime.InteropServices.Marshal]::Release($p)
'IOperatingSystemLicenseManager2 creation: PASS'
$content=[E5Native]::Policy('Clip-SubscriptionPFN')
if(-not $content){throw 'Subscription policy was empty.'}
'Subscription policy read: PASS'
$null=[E5Native]::JoinTenant()
'Entra join metadata read: PASS'
$guid='3f2504e0-4f89-41d3-9a0c-0305e82c3301'
$bytes=([Guid]$guid).ToByteArray()
$computed='S-1-12-1-'+((0,4,8,12 | ForEach-Object {[BitConverter]::ToUInt32($bytes,$_)} ) -join '-')
if([E5Native]::SidFromObjectId($guid) -ne $computed){throw 'SID conversion failed.'}
'Object ID to Windows SID guard: PASS'
'No authentication token or activation request was made.'
