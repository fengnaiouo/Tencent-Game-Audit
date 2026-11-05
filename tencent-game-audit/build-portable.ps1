$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path (Split-Path -Parent $project) 'portable-release'
$exe = Join-Path $outDir 'Tencent-Game-Audit.exe'
$rootExe = Join-Path (Split-Path -Parent $project) 'Tencent-Game-Audit.exe'
$zip = Join-Path (Split-Path -Parent $project) 'Tencent-Game-Audit-Portable.zip'

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
Push-Location $project
try {
    go test -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'go test failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
    go build -trimpath -ldflags='-s -w' -o $exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
    try { Copy-Item -LiteralPath $exe -Destination $rootExe -Force } catch { Write-Warning "Root EXE is in use; portable-release contains the new build. Rerun this script after closing Tencent-Game-Audit.exe." }
}
finally {
    Pop-Location
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

Copy-Item -LiteralPath (Join-Path $project 'portable-readme.txt') -Destination (Join-Path $outDir 'README-PORTABLE.txt') -Force
if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $outDir '*') -DestinationPath $zip -CompressionLevel Optimal
Get-FileHash -Algorithm SHA256 -LiteralPath $exe
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $rootExe).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash) { Write-Warning 'Root EXE differs from the portable build (likely still running).' }
Get-Item $rootExe, $exe, $zip | Select-Object FullName, Length, LastWriteTime
