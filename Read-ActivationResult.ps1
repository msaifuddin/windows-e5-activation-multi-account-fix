# Reads the result files written by Invoke-SingleTicketSubscriptionActivation.ps1.
# Use when an RMM tool loses the script's stdout. Run as SYSTEM (or an admin) in 64-bit PowerShell.
$ErrorActionPreference='Stop'
$paths=@(
 'C:\Users\*\AppData\Local\E5SubscriptionActivation\latest-result.json',
 "$env:SystemRoot\System32\config\systemprofile\AppData\Local\E5SubscriptionActivation\latest-result.json"
)
$files=@(foreach($path in $paths){Get-Item -Path $path -ErrorAction SilentlyContinue})
if(-not $files){
 [ordered]@{Status='NoResultFile';Message='No result file was found. The script may not have started, or the user profile uses a different location.'} | ConvertTo-Json
 exit 1
}
foreach($file in ($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 5)){
 try {
  $value=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
  [ordered]@{File=$file.FullName;LastWriteUtc=$file.LastWriteTimeUtc.ToString('o');Result=$value} | ConvertTo-Json -Depth 7
 }catch{
  [ordered]@{File=$file.FullName;Status='ResultUnreadable';ErrorType=$_.Exception.GetType().Name} | ConvertTo-Json
 }
}
