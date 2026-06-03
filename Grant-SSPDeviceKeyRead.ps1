# Grant-SSPDeviceKeyRead.ps1 — runs as SYSTEM (Tanium). Idempotent. Logs to %ProgramData%\TM.
# Grants the signed-in user (via Authenticated Users) Read on the device's
# twc-DC1-CA clientAuth machine cert private key, so the user-context browser
# can present it for mTLS to the Self-Service Portal. Safe no-op on machines
# without the cert. Renewal-safe: re-resolves the current key each run.
$ErrorActionPreference='Stop'
$log="$env:ProgramData\TM\ssp-keygrant.log"; New-Item -ItemType Directory -Force (Split-Path $log)|Out-Null
function Log($m){ "$(Get-Date -Format o)  $m" | Add-Content $log }
try{
  $c = Get-ChildItem Cert:\LocalMachine\My | ? {
        $_.Issuer -like '*twc-DC1-CA*' -and ($_.EnhancedKeyUsageList.FriendlyName -contains 'Client Authentication') } |
        sort NotAfter -Descending | select -First 1
  if(-not $c){ Log 'no twc-DC1-CA clientAuth cert'; exit 0 }
  $u   = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c).Key.UniqueName
  $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')   # Authenticated Users (locale-safe)
  $hit=$false
  foreach($d in "RSA\MachineKeys","Keys"){
    $f="$env:ProgramData\Microsoft\Crypto\$d\$u"
    if(Test-Path $f){ $hit=$true
      $acl=Get-Acl $f
      $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'Read','Allow')))
      Set-Acl -Path $f -AclObject $acl
      Log "granted AU Read on $f (thumb $($c.Thumbprint))"
    }
  }
  if(-not $hit){ Log "key file not found for $u" }
}catch{ Log "ERROR: $_"; exit 1 }
