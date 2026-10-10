[CmdletBinding()]
param([string] $OutputDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'bin' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw "C# compiler not found: $compiler"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = Join-Path $OutputDirectory 'MtkwlanProbe.exe'
& $compiler /nologo /optimize+ "/out:$output" (Join-Path $PSScriptRoot 'MtkwlanProbe.cs')
if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE" }
Get-Item -LiteralPath $output
