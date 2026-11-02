# Reverse-engineering notes

How the single-ticket path was found, and exactly which Microsoft binaries it was derived from.
No Microsoft binaries, symbol files or disassembly dumps are redistributed in this repository.
Everything below can be reproduced from your own Windows installation and Microsoft's public
symbol server with the tools in [`tools/`](tools/).

## 1. Source binaries

All analysis was performed on the binaries shipped in `C:\Windows\System32` of the analysis machine:

- **OS:** Windows 11 Enterprise 26H2, build **26300.9711**, **ARM64**
- **Licensing component file version:** **10.0.26100.9549** (26H2 is serviced on the 26100 code base, so these files carry 26100 versions)
- **Analysis date:** 2026-10-29

| File | File version | Arch | PDB (GUID, age) | SHA-256 | Size (bytes) |
|---|---|---|---|---|---|
| `LicenseManager.dll` | 10.0.26100.9549 | ARM64 (`0xAA64`) | `LicenseManager.pdb` `431822191183B852400F9B01DFF37C8D`, 1 | `7C6D5EBC17FCE292E99A44BB50C158595B50A7B64CD0A0E6A9ECCED35DC3910E` | 2,256,712 |
| `clipwinrt.dll` | 10.0.26100.9549 | ARM64 | `ClipWinRT.pdb` `2E439F29CB0543DF237D8D8CCDF4B886`, 1 | `2C77A710D85EBB1A4282155258B37C97D04D5E79CA4728A9F641826B4F4D8E23` | 1,250,648 |
| `ClipRenew.exe` | 10.0.26100.9549 | ARM64 | `ClipRenew.pdb` `6B0A48EA63E2BA033C9A0776702133AE`, 1 | `1904CD9F3E5F4B27CA7069342D44A4A75B695956C36AE44C0E1BC1D0DE63C510` | 121,208 |
| `LicenseManagerSvc.dll` | 10.0.26100.9549 | ARM64 | `LicenseManagerSvc.pdb` `1634500DD8167E45C981278586F195C1`, 1 | `A51EC77F5C8C87DF6EAED98C62CE0C859B33409CDC2DB237040749CC2C6C08FF` | 150,016 |
| `clipc.dll` *(called, not disassembled)* | 10.0.26100.9549 | ARM64 | `ClipC.pdb` `E4BD7E435F89F42EF0ADAA21168F8DC4`, 1 | `0885802777134B68F9B1AB897748BC6F8E32806523BB4543444193CD380E93A6` | 400,744 |

The PDB GUIDs above are the ones downloaded during analysis. They were re-checked against the
files on disk afterwards and still match, so the table identifies the exact analysed builds.
**The RVAs below are only valid for these exact files** (ARM64, 10.0.26100.9549). x64 builds and
other servicing levels have different addresses. Symbol and method names are stable enough to
locate them again with `symquery.py`.

Public symbols were fetched from `https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><age>/<pdb>`.

## 2. Tooling

A self-contained Python 3.12 (embeddable) workspace using:

- [`pefile`](https://github.com/erocarrera/pefile) 2024.8.26: PE parsing, imports and exports, debug directory (RSDS) to symbol-server URL.
- [Capstone](https://www.capstone-engine.org/) 5.0.9: ARM64/x64 disassembly.
- A minimal MSF/PDB reader in `pe_analyze.py`. It reads the DBI stream and public `S_PUB32` (`0x110E`) records, maps them through OMAP and section headers, and writes `symbols/<file>.json` (RVA → decorated name).

| Script | Purpose |
|---|---|
| `tools/bootstrap.py` | Extracts the embeddable Python and the Capstone wheel into the workspace. |
| `tools/pe_analyze.py <file>…` | Downloads matching public PDBs and dumps symbols, filtered for identity, ticket, subscription and tenant names. |
| `tools/symquery.py <file> <regex>` | Searches symbols. For vtables (`??_7…`) it prints the first 16 slots resolved to names. |
| `tools/disasm.py <file> range <rva> [size]` | Disassembles a range and annotates `bl` targets with symbol names. |
| `tools/disasm.py <file> <string>…` | Finds ARM64 `adrp`/`add` cross-references to UTF-16/ASCII strings. |
| `tools/strings_probe.py`, `imports_probe.py`, `constants.py`, `apiset.py` | Read strings, imports and exports, GUID constants and the API-set map. |

`pe_analyze.load()` reads from `C:\Windows\System32` directly. Run the tools on the build you want to examine.

## 3. Findings

### 3.1 Why the normal path fails with several work accounts

`LicenseManager.dll`, function
`SingleUserStoredIdentitySnapshot::CaptureIdentity(ThreadContext const*)` at **RVA `0x1B0B0`**:

```
0001B11C bl   StoredIdentitySnapshot::CaptureIdentity        ; RVA 0x1B680
0001B13C bl   WinStoreAuth::AuthenticationInternal::GetDeviceTicketWithBroker
...
0001B308 ldr  x8, [x19, #0x140]          ; length of the caller-supplied user ticket
0001B30C cbnz x8, 0x1B49C                ; non-empty ticket -> skip enumeration
...
0001B340 mov  w2, #3
0001B344 bl   WinStoreAuth::AuthenticationInternal::GetAllAccountTickets   ; RVA 0x27A38
          ; then loops over every returned ticket and push_back()s a StoredTicket for each
```

When no ticket is supplied, the snapshot calls `GetAllAccountTickets`. That collects a token for
**every** account WAM has for the Store client and attaches all of them to the license request.
The Store licensing service then answers:

```
Microsoft-Windows-Store/Operational  Event 8003
Service Fault: status: 400
code: EntitlementExpectedForEachTenantId
description: All Aad users provided in the request are expected have an associated entitlement.
number of MSA tickets: 0
number of AAD tickets: <N>
```

Event 8002 at the same time records `hr: 0x87E10C0A` from `managercore.cpp` / `proxy.cpp`. The
scheduled task `\Microsoft\Windows\Subscription\LicenseAcquisition` (`ClipRenew.exe`) ends with
the same `0x87E10C0A`.

When the ticket field is non-empty, the `cbnz` branch skips `GetAllAccountTickets`, so exactly one
ticket is sent.

### 3.2 An entry point that accepts an explicit ticket

`symquery.py LicenseManager.dll "ApplicationLicenseManager@@6B"` lists the class's vtables.
`ApplicationLicenseManager` implements `IOperatingSystemLicenseManager` and
`IOperatingSystemLicenseManager2`. The `IOperatingSystemLicenseManager2` vtable (thunks
following the `ILicenseManagerUserContext` vtable at `0x18AC60`) is:

| Slot | Method | Impl. RVA |
|---|---|---|
| 0–2 | `QueryInterface` / `AddRef` / `Release` | |
| 3 | `ActivateLicenseForContent(PCWSTR contentId, ILicenseInstance**)` | `0x58F30` (adjustor thunk; `IOperatingSystemLicenseManager` impl. at `0x58E00`) |
| 4 | `ActivateLicenseForContentWithUserTicket(PCWSTR, PCWSTR ticket, ILicenseInstance**)` | `0x59080` (adjustor thunk; impl. at `0x58F40`) |
| **5** | **`ActivateLicenseForContentWithUserTicketAndType(PCWSTR contentId, PCWSTR ticket, LicenseUserTicketType, ILicenseInstance**)`** | **`0x59090`** |

Decorated name of slot 5:
`?ActivateLicenseForContentWithUserTicketAndType@ApplicationLicenseManager@@UEAAJPEBG0W4LicenseUserTicketType@@PEAPEAUILicenseInstance@@@Z`

`LicenseUserTicketType`: `0` = MSA, `1` = AAD (Entra).

COM activation, taken from the binaries:

- CLSID `{22F5B1DF-7D7A-4D21-97F8-C21AEFBA859C}`, created with `CLSCTX_LOCAL_SERVER` (`4`). It runs out of process in the license manager service, so the client receives a proxy.
- IID `IOperatingSystemLicenseManager2` = `{9BB0F3FE-BCF3-4287-96B4-74FC6DA8D7C3}`. (`IApplicationLicenseManager` = `{90E2000C-B946-42FA-892F-94506F30CA4F}`.)
- The proxy needs `CoSetProxyBlanket(..., RPC_C_IMP_LEVEL_IMPERSONATE, ..., EOAC_DYNAMIC_CLOAKING)` so that the service acts as the calling user.

Because the object is out of process, slot 5 on the client is the proxy's method #5, which is
marshalled by method number. If a future build reorders the interface, the call is sent to a
different remote method rather than failing locally.

### 3.3 The content ID: PFN → GUID

The subscription content comes from the licensing policy `Clip-SubscriptionPFN`
(`SLGetWindowsInformation`), for example `Microsoft.Windows.Pro.Addon_8wekyb3d8bbwe`.
The licensing interface wants a **content ID**, not a PFN. Passing the PFN returns `0x80070057`.

`clipwinrt.dll`, `GetContentIdFromPfn` at **RVA `0xCC278`** and `GetContentId` at **`0xDEE60`**:

1. `PackageNameAndPublisherIdFromFamilyName(pfn)` → name, publisherId
2. `identity = lowercase(name + ":" + publisherId + ":win32")`
3. `SHA-256(UTF-16LE(identity))`, without a terminator
4. The first 16 bytes, read as a Windows (little-endian) GUID

`Microsoft.Windows.Pro.Addon_8wekyb3d8bbwe` → `8d419748-b6f9-41a8-e3d0-ebd7a8880244`.

### 3.4 Calls that must be skipped

`ApplicationLicenseManager::InvalidateCacheForContentWithId` (`0x5C430`) delegates to
`LicenseManager::RefreshCacheForContentWithId` (`0x49EE0`). That path captures the ordinary
identity, so it runs the all-accounts enumeration again without the supplied ticket. On an
affected device it failed with `0x87E10C0A` before the explicit-ticket call was ever reached.
The script therefore calls slot 5 directly and makes no cache call first.

### 3.5 Token request parameters

These strings are embedded in both `clipwinrt.dll` and `LicenseManager.dll`:

| Value | Where | Meaning |
|---|---|---|
| `{268761a2-03f3-40df-8a8b-c3db24145b6b}` | clipwinrt `0x108C90`, LicenseManager `0x1A5640` | Universal Store native client ID, **with braces** |
| `268761a2-03f3-40df-8a8b-c3db24145b6b` | LicenseManager `0x1A1A30` | Same, unbraced |
| `https://onestore.microsoft.com` | clipwinrt `0x108CE0`, LicenseManager `0x1A1AB8` | Token resource |

The braces matter. WAM derives the redirect URI from the client-ID string. Without braces the
request fails with `0xCAA20009` / `AADSTS50011` (redirect URI not registered). With braces it
succeeds silently. The token's audience is Windows Store for Business, first-party app ID
`45a330b1-b1ec-4cc1-9161-9f03992aa49f`.

### 3.6 Refreshing subscription state

After the license is acquired, `clipc.dll!ClipCallServer(handle, "ClipCallServerUpdateSubscriptionData", 0, NULL)`
makes ClipSVC re-evaluate the subscription. Success is then confirmed by
`Win32_OperatingSystem.OperatingSystemSKU = 4` (Enterprise) and
`SoftwareLicensingService.SubscriptionStatus = 1`.

## 4. Development history (failures that shaped the script)

| Version | Symptom | Cause / fix |
|---|---|---|
| 1 → 2 | Empty RMM output | PS 5.1 treats an empty pipeline as a null JSON result. The launcher now rejects empty output, keeps stderr and writes `latest-result.json`. |
| 2.1 | `ValidationMetadataException` | The worker reassigned a validated parameter to `''`. It now uses separate variables. |
| 2.2 | `CannotIndex` `0x80131501` | The WinRT `WebTokenRequest.Properties` map appears as `__ComObject`. The fix casts it to `IDictionary<string,string>` in C#. |
| 2.3 | `0xCAA20009` / `AADSTS50011` | Unbraced client ID. The braced form from the binary is now used. |
| 2.4 | `0x80070057` | The PFN was passed instead of the content ID. Now derived as in §3.3. |
| 2.5 | `0x87E10C0A` at cache invalidation | §3.4. The cache call was removed and slot 5 is called directly. |

## 5. Verification status

- **Already-activated Enterprise device (analysis machine):** token send, slot-5 acquisition and `UpdateSubscriptionData` all returned `0x00000000`. SKU and subscription state were unchanged, as expected.
- **Affected device:** Windows 11 26H2 build 26300, Entra joined, one primary account plus two workplace-joined accounts from unrelated tenants. The normal task failed with `EntitlementExpectedForEachTenantId` (3 AAD tickets). Version 2.5 returned `EnterpriseSubscriptionActive` in about 8 seconds: Pro → Enterprise, `SubscriptionStatus` 1, acquisition and update HRESULTs `0`. Intune later reported the device compliant.
- **Not verified:** other devices; static analysis of x64 builds (the script itself uses the COM vtable slot, not RVAs); and whether Windows' own periodic renewal (which still enumerates all accounts) keeps the subscription active over time.
