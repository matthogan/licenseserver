[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot 'compose.test.yaml'
$testExitCode = 1

Push-Location $repoRoot
try {
    & docker compose -f $composeFile up --build --abort-on-container-exit --exit-code-from test
    $testExitCode = $LASTEXITCODE
}
finally {
    # Only this test project's containers/network are removed. Go caches remain.
    & docker compose -f $composeFile down
    Pop-Location
}
exit $testExitCode
