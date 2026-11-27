# Disposable loopback fixture. Never modify the Windows certificate store.
param([Parameter(Mandatory=$true)][string]$Bin)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted CI fixture only' }
$binPath=(Resolve-Path -LiteralPath $Bin).Path
$fixture=Join-Path $env:RUNNER_TEMP ('chezhi-sdk-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$proc=$null
$smoke=$null
try {
    Write-Host 'STEP start loopback TLS fixture'
    $proc=Start-Process -FilePath (Join-Path $binPath 'SdkTestServer.exe') -ArgumentList ('"'+$fixture+'"') -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $fixture 'server.stderr')
    $cfg=Join-Path $fixture 'fixture.txt'
    for ($i=0;$i -lt 100 -and -not (Test-Path -LiteralPath $cfg);$i++) {
        if ($proc.HasExited) { throw 'Fixture exited early' }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $cfg)) { throw 'Fixture startup timeout' }
    $dll=Join-Path $binPath 'chezhi_license_sdk.dll'
    $hash=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
    $ca=Join-Path $fixture 'fixture-ca.cer'
    Write-Host 'STEP launch managed online smoke (explicit CA)'
    $stdout=Join-Path $fixture 'smoke.stdout'
    $stderr=Join-Path $fixture 'smoke.stderr'
    $argsLine=('"'+$cfg+'" "'+$dll+'" '+$hash+' "'+$ca+'"')
    $smoke=Start-Process -FilePath (Join-Path $binPath 'OnlineSmoke.exe') -ArgumentList $argsLine -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $smoke.WaitForExit(90000)) { throw 'Native online interop exceeded 90-second process deadline' }
    if ($smoke.ExitCode -ne 0) { throw "Native online interop failed: $($smoke.ExitCode)" }
} finally {
    if ($smoke -and -not $smoke.HasExited) { Stop-Process -Id $smoke.Id -Force; [void]$smoke.WaitForExit(5000) }
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force; [void]$proc.WaitForExit(5000) }
    foreach($name in @('smoke.stdout','smoke.stderr','server.stderr')) {
        $path=Join-Path $fixture $name
        if(Test-Path -LiteralPath $path) {Get-Content -LiteralPath $path}
    }
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
