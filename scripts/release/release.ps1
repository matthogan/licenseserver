[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Export', 'Sign', 'Verify')][string]$Action,
    [Parameter(Mandatory)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$')][string]$Tag,
    [string]$Directory,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]+$')][string]$CandidateVolume = 'licd-release-candidates',
    [string]$SigningDirectory = "$env:USERPROFILE\.release-signing\licenceserver"
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Directory) { $Directory = Join-Path $repoRoot ".release-output/$Tag" }
$Directory = [IO.Path]::GetFullPath($Directory)
$image = 'local/licd-release:tools-v1'

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed (exit $LASTEXITCODE)." }
}

Push-Location $repoRoot
try {
    $trust = Join-Path $SigningDirectory 'allowed_signers'
    if (-not (Test-Path -LiteralPath $trust)) { throw "Missing trusted Git signers file: $trust" }
    Invoke-Checked git @('-c', 'gpg.format=ssh', '-c', "gpg.ssh.allowedSignersFile=$trust", 'verify-tag', $Tag)
    $commit = (Invoke-Checked git @('rev-parse', "$Tag^{commit}")).Trim()

    if ($Action -eq 'Export') {
        if (Test-Path -LiteralPath $Directory) { throw "Refusing to overwrite $Directory" }
        Invoke-Checked docker @('volume', 'inspect', $CandidateVolume) | Out-Null
        New-Item -ItemType Directory -Path $Directory | Out-Null
        $container = 'licd-release-export-' + [Guid]::NewGuid().ToString('N')
        try {
            Invoke-Checked docker @('create', '--name', $container, '--mount',
                "type=volume,source=$CandidateVolume,target=/releases,readonly", $image, 'true') | Out-Null
            Invoke-Checked docker @('cp', "${container}:/releases/$Tag/.", $Directory)
        }
        finally {
            & docker rm $container | Out-Null
        }
    }

    # Bind the exported signed tag object to the independently verified local tag.
    $expectedTag = (Invoke-Checked git @('rev-parse', "refs/tags/$Tag")).Trim()
    $exportedTag = (Invoke-Checked git @('hash-object', '-t', 'tag', (Join-Path $Directory 'source-tag.txt'))).Trim()
    if ($expectedTag -ne $exportedTag) { throw 'Exported tag differs from the trusted local Git tag.' }

    if ($Action -ne 'Export') {
        $cosign = Get-Command cosign-windows-amd64.exe -ErrorAction SilentlyContinue
        if (-not $cosign) { $cosign = Get-Command cosign -CommandType Application -ErrorAction Stop }
        $publicKey = Join-Path $SigningDirectory 'cosign-release.pub'
        $manifest = Join-Path $Directory 'checksums.txt'
        $bundle = Join-Path $Directory 'checksums.txt.sigstore.json'
        if ($Action -eq 'Verify') {
            Invoke-Checked $cosign.Source @('verify-blob', '--key', $publicKey, '--bundle', $bundle, $manifest)
        }
    }

    Invoke-Checked docker @('run', '--rm', '--network', 'none',
        '--mount', "type=bind,source=$repoRoot,target=/workspace,readonly",
        '--mount', "type=bind,source=$Directory,target=/candidate,readonly",
        $image, 'python3', 'scripts/release/bundle.py', 'verify', '/candidate', '--tag', $Tag, '--commit', $commit)

    if ($Action -eq 'Sign') {
        if (Test-Path -LiteralPath $bundle) { throw 'Signature bundle already exists. Use Verify instead of signing again.' }
        $privateKey = Join-Path $SigningDirectory 'cosign-release.key'
        Invoke-Checked $cosign.Source @('sign-blob', '--key', $privateKey, '--bundle', $bundle, '--yes', $manifest)
        Invoke-Checked $cosign.Source @('verify-blob', '--key', $publicKey, '--bundle', $bundle, $manifest)
    }

    if ($Action -ne 'Export') {
        [ordered]@{
            tag = $Tag; commit = $commit; verified_at = [DateTime]::UtcNow.ToString('o')
            manifest_sha256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
            trusted_public_key_file_sha256 = (Get-FileHash -LiteralPath $publicKey -Algorithm SHA256).Hash.ToLowerInvariant()
            checks = @('git-tag-signature', 'cosign-manifest-signature', 'artifact-checksums',
                'provenance-source-and-builder', 'package-sboms', 'oci-digests-and-attestations')
        } | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $Directory 'verification.json')
    }
    Write-Host "$Action completed: $Directory"
}
finally { Pop-Location }
