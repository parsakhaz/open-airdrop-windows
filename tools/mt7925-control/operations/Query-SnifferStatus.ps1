[CmdletBinding()]
param([Parameter(Mandatory = $true)] [string] $AdapterName)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$probe = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\MtkwlanProbe.exe'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw "Build the probe first: $probe"
}
$result = Join-Path $env:ProgramData 'OpenAirdrop\mt7925-control\sniffer-status-latest.json'
& $probe --output $result
exit $LASTEXITCODE
