#Requires -Version 5.1
<#
.SYNOPSIS
    Links a certificate in the Windows certificate store to a Google Cloud KMS
    private key by writing the CERT_KEY_PROV_INFO_PROP_ID property directly
    via Win32 P/Invoke (CertSetCertificateContextProperty).

.DESCRIPTION
    When a certificate is imported from a PFX it carries no Key Provider Info
    pointing at the Google Cloud KMS Provider. This script finds the certificate
    by thumbprint and writes the correct CRYPT_KEY_PROV_INFO structure so that
    Windows CNG-aware applications (SignTool, MMC, etc.) can locate the private
    key through the installed Google Cloud KMS KSP.

.PARAMETER Thumbprint
    SHA-1 thumbprint of the certificate already present in the store.
    Example: A1B2C3D4E5F6...

.PARAMETER KeyVersionPath
    Full Cloud KMS CryptoKeyVersion resource path used as the key container name.
    Example: projects/my-project/locations/europe-west3/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1

.PARAMETER StoreLocation
    Certificate store location: CurrentUser (default) or LocalMachine.

.PARAMETER StoreName
    Certificate store name. Defaults to "My" (Personal).

.EXAMPLE
    .\Set-KmsCertKeyLink.ps1 `
        -Thumbprint "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2" `
        -KeyVersionPath "projects/my-proj/locations/europe-west3/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"

.EXAMPLE
    # Machine store (run as Administrator)
    .\Set-KmsCertKeyLink.ps1 `
        -Thumbprint "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2" `
        -KeyVersionPath "projects/my-proj/locations/europe-west3/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1" `
        -StoreLocation LocalMachine
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $Thumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^projects/.+/locations/.+/keyRings/.+/cryptoKeys/.+/cryptoKeyVersions/\d+$')]
    [string] $KeyVersionPath,

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string] $StoreLocation = 'CurrentUser',

    [string] $StoreName = 'My'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Load Win32 types via Add-Type
# ---------------------------------------------------------------------------
$pinvokeCode = @'
using System;
using System.Runtime.InteropServices;

namespace KmsCertLink
{
    // CRYPT_KEY_PROV_INFO as defined in wincrypt.h
    // All flag/type values below are for CNG (KSP) keys.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_KEY_PROV_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszContainerName;   // Key container name = KMS key version path

        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProvName;        // KSP name

        public uint   dwProvType;          // 0 for CNG/KSP
        public uint   dwFlags;             // CRYPT_SILENT (0x40) recommended for non-interactive
        public uint   cProvParam;          // 0
        public IntPtr rgProvParam;         // NULL
        public uint   dwKeySpec;           // 0 for CNG/KSP (AT_NONE)
    }

    public static class NativeMethods
    {
        // Property ID 2 = CERT_KEY_PROV_INFO_PROP_ID
        public const uint CERT_KEY_PROV_INFO_PROP_ID = 2;

        // dwFlags for CertSetCertificateContextProperty
        // 0 = no special flags; use CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG (0x40000000)
        // only if you do NOT want the change persisted. We leave it at 0 to persist.
        public const uint CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG = 0x80000000;

        [DllImport("Crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertSetCertificateContextProperty(
            IntPtr  pCertContext,
            uint    dwPropId,
            uint    dwFlags,
            IntPtr  pvData
        );
    }
}
'@

# Only compile once per session
if (-not ([System.Management.Automation.PSTypeName]'KmsCertLink.NativeMethods').Type) {
    Add-Type -TypeDefinition $pinvokeCode -Language CSharp
}

# ---------------------------------------------------------------------------
# 2. Find the certificate in the requested store
# ---------------------------------------------------------------------------
Write-Host "Opening store: $StoreLocation\$StoreName" -ForegroundColor Cyan

$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    $StoreName,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
)

try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
}
catch {
    throw "Cannot open store '$StoreName' ($StoreLocation). " +
          "If using LocalMachine, run PowerShell as Administrator. Error: $_"
}

$thumbprintUpper = $Thumbprint.ToUpperInvariant()
$cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprintUpper }

if (-not $cert) {
    $store.Close()
    throw "Certificate with thumbprint '$Thumbprint' not found in $StoreLocation\$StoreName."
}

Write-Host "Found certificate:" -ForegroundColor Cyan
Write-Host "  Subject  : $($cert.Subject)"
Write-Host "  Issuer   : $($cert.Issuer)"
Write-Host "  NotAfter : $($cert.NotAfter)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"

# ---------------------------------------------------------------------------
# 3. Build the CRYPT_KEY_PROV_INFO structure
# ---------------------------------------------------------------------------
$KSP_NAME      = 'Google Cloud KMS Provider'
$PROV_TYPE_CNG = 0        # CNG KSPs always use type 0
$FLAG_SILENT   = 0x40     # CRYPT_SILENT - suppress UI prompts
$FLAG_MACHINE  = 0x20     # NCRYPT_MACHINE_KEY_FLAG - machine key scope
$KEYSPEC_NONE  = 0       # AT_NONE — correct for CNG/KSP

$provFlags = $FLAG_SILENT
if ($StoreLocation -eq 'LocalMachine') {
    $provFlags = $provFlags -bor $FLAG_MACHINE
}

$provInfo = [KmsCertLink.CRYPT_KEY_PROV_INFO]::new()
$provInfo.pwszContainerName = $KeyVersionPath
$provInfo.pwszProvName      = $KSP_NAME
$provInfo.dwProvType        = $PROV_TYPE_CNG
$provInfo.dwFlags           = $provFlags
$provInfo.cProvParam        = 0
$provInfo.rgProvParam       = [IntPtr]::Zero
$provInfo.dwKeySpec         = $KEYSPEC_NONE

# ---------------------------------------------------------------------------
# 4. Marshal struct to unmanaged memory and call the Win32 API
# ---------------------------------------------------------------------------
$structSize = [Runtime.InteropServices.Marshal]::SizeOf($provInfo)
$pProvInfo  = [Runtime.InteropServices.Marshal]::AllocHGlobal($structSize)

try {
    [Runtime.InteropServices.Marshal]::StructureToPtr($provInfo, $pProvInfo, $false)

    $action = "Set CERT_KEY_PROV_INFO on certificate '$($cert.Subject)' " +
              "pointing to '$KeyVersionPath' via '$KSP_NAME'"

    if ($PSCmdlet.ShouldProcess($cert.Thumbprint, $action)) {

        $success = [KmsCertLink.NativeMethods]::CertSetCertificateContextProperty(
            $cert.Handle,
            [KmsCertLink.NativeMethods]::CERT_KEY_PROV_INFO_PROP_ID,
            0,          # persist the property
            $pProvInfo
        )

        if (-not $success) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "CertSetCertificateContextProperty failed with Win32 error 0x{0:X8} ({0})" -f $err
        }

        Write-Host "`nKey provider info written successfully." -ForegroundColor Green
    }
}
finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($pProvInfo)
    $store.Close()
}

# ---------------------------------------------------------------------------
# 5. Verify by re-opening the store and reading back the property
# ---------------------------------------------------------------------------
Write-Host "`nVerifying - re-reading certificate from store..." -ForegroundColor Cyan

$verifyStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    $StoreName,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
)
$verifyStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
$verifyCert = $verifyStore.Certificates | Where-Object { $_.Thumbprint -eq $thumbprintUpper }
$verifyStore.Close()

if ($StoreLocation -eq 'CurrentUser') {
    $storeFlag = '-user'
} else {
    $storeFlag = ''
}

if ($verifyCert.HasPrivateKey) {
    Write-Host "HasPrivateKey = True - Windows now sees a private key for this certificate." -ForegroundColor Green
    Write-Host ""
    Write-Host "Verify the full link with:" -ForegroundColor Yellow
    Write-Host "  certutil $storeFlag -store My $Thumbprint" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Expected output should include:" -ForegroundColor Yellow
    Write-Host "  Key Container = $KeyVersionPath" -ForegroundColor Yellow
    Write-Host "  Provider      = $KSP_NAME" -ForegroundColor Yellow
    Write-Host "  Encryption test passed" -ForegroundColor Yellow
} else {
    Write-Warning "HasPrivateKey is still False after writing the property."
    Write-Warning "This usually means the Google Cloud KMS CNG provider could not validate the key container path."
    Write-Warning "Check:"
    Write-Warning "  1. C:\Windows\KMSCNG\config.yaml lists the exact key version path"
    Write-Warning "  2. gcloud auth application-default login has been run"
    Write-Warning "  3. The KMS key version state is ENABLED (not PENDING_IMPORT)"
}
