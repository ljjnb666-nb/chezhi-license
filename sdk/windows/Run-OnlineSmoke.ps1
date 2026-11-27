# CI-only temporary trust root; never install on a user's production machine.
param([Parameter(Mandatory=$true)][string]$Bin)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted CI fixture only' }
$binPath=(Resolve-Path -LiteralPath $Bin).Path
$fixture=Join-Path $env:RUNNER_TEMP ('chezhi-sdk-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$proc=$null
$thumb=$null
try {
    $proc=Start-Process -FilePath (Join-Path $binPath 'SdkTestServer.exe') -ArgumentList ('"'+$fixture+'"') -PassThru -WindowStyle Hidden
    $cfg=Join-Path $fixture 'fixture.txt'
    for ($i=0;$i -lt 100 -and -not (Test-Path -LiteralPath $cfg);$i++) {
        if ($proc.HasExited) { throw 'Fixture exited early' }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $cfg)) { throw 'Fixture startup timeout' }
    $root=Import-Certificate -FilePath (Join-Path $fixture 'fixture-ca.cer') -CertStoreLocation Cert:\CurrentUser\Root
    $thumb=$root.Thumbprint
    if (-not $thumb) { throw 'Fixture root import failed' }
    $dll=Join-Path $binPath 'chezhi_license_sdk.dll'
    $hash=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
    & (Join-Path $binPath 'OnlineSmoke.exe') $cfg $dll $hash
    if ($LASTEXITCODE -ne 0) { throw 'Native online interop failed' }
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force; $proc.WaitForExit() }
    if ($thumb) { Remove-Item -LiteralPath ('Cert:\CurrentUser\Root\'+$thumb) -Force }
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
