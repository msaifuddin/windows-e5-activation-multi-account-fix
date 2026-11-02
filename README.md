# windows-e5-activation-multi-account-fix

Fixes Windows 10/11 **Enterprise E3/E5 subscription activation** when the user has **more than one
work or school account**, without removing any accounts.

> **Unsupported and experimental.** This uses an undocumented Windows licensing COM interface
> found by reverse engineering. It does **not** bypass licensing. Microsoft's service still
> validates the token and requires a real Windows Enterprise entitlement for the selected user.
> Not affiliated with or endorsed by Microsoft. Test on one device before using it anywhere else.

## The problem

Subscription activation steps an Entra-joined Windows **Pro** device up to **Enterprise** when the
signed-in user holds a Windows Enterprise E3/E5 licence (service plan `WIN10_PRO_ENT_SUB`). On some
devices it never happens. The device stays on Pro or on unactivated Enterprise, and:

- The `\Microsoft\Windows\Subscription\LicenseAcquisition` task ends with **`0x87E10C0A`**.
- `Microsoft-Windows-Store/Operational` logs event **8003**:

  ```
  Service Fault: status: 400
  code: EntitlementExpectedForEachTenantId
  description: All Aad users provided in the request are expected have an associated entitlement.
  number of MSA tickets: 0
  number of AAD tickets: 2   (or more)
  ```

- Event **8002** records `hr: 0x87e10c0a` in `managercore.cpp` / `proxy.cpp`.

**Cause:** Windows sends a token for **every** Entra account in the user's Web Account Manager.
That includes accounts added through "Access work or school", Office or Teams sign-ins for other
tenants, and workplace-joined guest or customer accounts. If any of those tenants has no Windows
entitlement, the service rejects the entire request. Typical affected users are consultants and
MSP staff who are signed in to customer tenants.

The usual fixes (disconnect the extra accounts, block additional accounts by policy, use MAK/KMS,
change registry values) all disrupt the user or move away from subscription activation.

## How this workaround works

Reverse engineering of `LicenseManager.dll` showed that the identity-capture code **skips
`GetAllAccountTickets` when a ticket is supplied explicitly**. The OS licensing COM interface
`IOperatingSystemLicenseManager2` has a method that accepts one:
`ActivateLicenseForContentWithUserTicketAndType`.

The script:

1. Checks that the device is Entra joined and reads the subscription package family name from the licensing policy `Clip-SubscriptionPFN`. It converts that name to the licensing **content ID**, the same way `clipwinrt.dll` does.
2. Selects **one** account and asks WAM **silently** for a token with the Store client ID `{268761a2-…}` (braced), resource `https://onestore.microsoft.com` and an authority fixed to the join tenant. No UI is shown.
3. Checks the token's tenant (`tid`), audience (`aud`) and user (`oid` → the Windows SID of the signed-in user) before using it. The token is never printed or written to disk.
4. Calls `ActivateLicenseForContentWithUserTicketAndType(contentId, ticket, AAD)` on the out-of-process license manager.
5. Calls `ClipCallServerUpdateSubscriptionData`, then reports success only when Windows shows Enterprise **and** `SubscriptionStatus = 1`.

No product keys are changed, and no accounts, token caches or registrations are removed. No
Windows files are patched and no services are restarted.

Full technical detail, including the exact source binaries (versions, PDB GUIDs, SHA-256 hashes),
function addresses and the disassembly evidence, is in
**[research/REVERSE-ENGINEERING.md](research/REVERSE-ENGINEERING.md)**.

## Usage

Requirements:

- Windows 10/11 Pro or Enterprise, **Entra joined**, with internet access.
- The target user has a Windows Enterprise E3/E5 entitlement in the join tenant.
- Run **as the signed-in user** in an interactive session, not as SYSTEM, in **64-bit Windows PowerShell 5.1**.
- In an RMM tool (NinjaOne, Intune remediation and similar): "run as current logged-on user", with a timeout of at least 60 seconds.

```powershell
# Read-only check: interface reachable, content ID derivable. No token or licence request.
.\Invoke-SingleTicketSubscriptionActivation.ps1 -ProbeOnly

# Pick the user's account by domain (tenant defaults to the device's Entra join tenant)
.\Invoke-SingleTicketSubscriptionActivation.ps1 -AccountDomain contoso.com

# Or by exact UPN, optionally with an explicit tenant
.\Invoke-SingleTicketSubscriptionActivation.ps1 -UserPrincipalName jane@contoso.com -TenantId <tenant-guid>
```

Without `-UserPrincipalName` or `-AccountDomain`, the script continues only when WAM has exactly
one Entra account for the Store client. The token tenant check still stops any token from another
tenant from being sent.

The script outputs one JSON object and also saves it to
`%LOCALAPPDATA%\E5SubscriptionActivation\latest-result.json`. If your RMM tool loses the output,
run `Read-ActivationResult.ps1` as SYSTEM.

### Result statuses

| Status | Exit | Meaning |
|---|---|---|
| `EnterpriseSubscriptionActive` | 0 | Enterprise SKU with `SubscriptionStatus` 1. Done. |
| `AlreadyActive` | 0 | Nothing to do. |
| `InterfaceAvailable` | 0 | `-ProbeOnly` passed. |
| `SilentTokenUnavailable` | 1 | WAM could not issue a token without UI (MFA, CA, expired session). Nothing was sent. |
| `TokenTenantMismatch` / `TokenAudienceMismatch` / `TokenUserMismatch` | 1 | A safety check stopped the token. Nothing was sent. |
| `AccountSelectionRequired` | 1 | Zero or several candidate accounts. Use `-UserPrincipalName` or `-AccountDomain`. |
| `SingleTenantAcquisitionFailed` | 1 | The service rejected the request. See `AcquisitionHResult`, `AcquisitionTrace` and fresh Store events in `LicensingDiagnostics`. |
| `SubscriptionUpdateFailed` | 1 | Licence acquired, but ClipSVC rejected the refresh. |
| `ActivationNotConfirmed` | 1 | All calls succeeded but Enterprise was not seen within 10 s. Re-check later. |
| `NotEntraJoined` / `JoinedTenantMismatch` / `UnsupportedEdition` / `UnsupportedPowerShell` / `WrongExecutionContext` | 1 | Precondition not met. |
| `ExecutionFailed` / `WorkerFailed` / `LauncherFailed` / `OperationTimedOut` | 1 | See `Stage`, `ErrorHResult` and `StartupError`. |

## Verification status

- **Confirmed** on one affected production device (Windows 11 26H2, build 26300; one primary and two foreign-tenant workplace accounts; the normal task failing with 3 AAD tickets). Result `EnterpriseSubscriptionActive` in about 8 s, and Intune later reported the device compliant.
- **Confirmed** on an already-activated Enterprise device: every call returned `S_OK` and nothing changed.
- **Offline tests** in `research/tests` pass on Windows PowerShell 5.1: parse, C# compile, COM creation, policy read, SID guard, WAM property mapping and launcher error handling.
- **Unknown:** whether Windows' own periodic renewal, which still sends every account, keeps the subscription active over time; behaviour on other builds; fleet-scale results. Please share results through issues.

## Limitations and risks

- Calls an **undocumented** interface **by vtable slot (5)**. A Windows update that changes `IOperatingSystemLicenseManager2` could make the call reach a different method. The `OsBuild` field is reported so that results can be tied to builds.
- It acquires the licence once. It does not change how Windows renews it.
- It does not fix missing licence assignments, Conditional Access blocks on the Store for Business app (`45a330b1-b1ec-4cc1-9161-9f03992aa49f`), or devices that are not Entra joined.
- Microsoft does not support this method. Keep a support case open for a supported fix.

## Repository layout

```
Invoke-SingleTicketSubscriptionActivation.ps1   main script
Read-ActivationResult.ps1                       reads saved results (run as SYSTEM)
research/REVERSE-ENGINEERING.md                 binaries, symbols, addresses, disassembly evidence
research/tools/                                 Python PE/PDB/disassembly helpers used for the analysis
research/tests/                                 offline and local tests and probes
LICENSE                                         MIT
```

`research/tests/Test-E5TokenSend.ps1`, `Test-SubscriptionUpdate.ps1` and the `-AcquireExistingEnterprise`
switch make **live** requests. Use them only on a device that is already activated Enterprise.
The other tests make no authentication or licensing requests.

## Credits

Reverse engineering, analysis tooling and the activation script: OpenAI Codex (GPT 6.1 Sol).

## Licence

[MIT](LICENSE). The licence covers the code and documentation in this repository only. No Microsoft code, binaries or symbols are included.

## References

- [Windows subscription activation](https://learn.microsoft.com/en-us/windows/deployment/windows-subscription-activation)
- [WebAuthenticationCoreManager.GetTokenSilentlyAsync](https://learn.microsoft.com/en-us/uwp/api/windows.security.authentication.web.core.webauthenticationcoremanager.gettokensilentlyasync)
- [Web Account Manager](https://learn.microsoft.com/en-us/windows/apps/develop/security/web-account-manager)
- [SLGetWindowsInformation](https://learn.microsoft.com/en-us/windows/win32/api/slpublic/nf-slpublic-slgetwindowsinformation)
- [NetGetAadJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation)
- Community background on subscription activation and multiple accounts: [call4cloud](https://call4cloud.nl/kb5036980-subscription-activation-issue/), [azuretothemax](https://azuretothemax.net/2025/06/11/everything-i-know-on-subscription-activation/)
