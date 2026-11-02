$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\Invoke-SingleTicketSubscriptionActivation.ps1') -Raw
$native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
Add-Type -TypeDefinition $native
$os=Get-CimInstance Win32_OperatingSystem
$service=Get-CimInstance SoftwareLicensingService
$active=@(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseStatus=1" | Where-Object {$_.LicenseFamily -eq 'Enterprise'})
if($os.OperatingSystemSKU -ne 4 -or ($service.SubscriptionStatus -ne 1 -and $active.Count -eq 0)){throw 'Requires already activated Enterprise.'}
$before=$service.SubscriptionStatus
$hr=[E5Native]::UpdateSubscription()
$service=Get-CimInstance SoftwareLicensingService
$os=Get-CimInstance Win32_OperatingSystem
[ordered]@{ComputerName=$env:COMPUTERNAME;UpdateHResult=('0x'+$hr.ToString('X8'));SubscriptionStatusBefore=$before;SubscriptionStatusAfter=$service.SubscriptionStatus;EditionAfter=$os.Caption;SkuAfter=$os.OperatingSystemSKU} | ConvertTo-Json
if($hr -lt 0){exit 1}
