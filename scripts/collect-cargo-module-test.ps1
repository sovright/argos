[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]] $Failures,

    [Parameter(Mandatory = $true)]
    [string] $Package,

    [Parameter(Mandatory = $true)]
    [string] $TestFilter,

    [string] $Target = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = 'Stop'
# Classify Cargo's exit ourselves, including when the caller enables native
# command error promotion. Command-not-found and other tool errors still throw.
$PSNativeCommandUseErrorActionPreference = $false
$output = [System.Collections.Generic.List[string]]::new()
& cargo test --color never -p $Package $TestFilter --target $Target 2>&1 | ForEach-Object {
    $output.Add($_.ToString())
    Write-Host $_
}
$cargoExitCode = $LASTEXITCODE

$summaries = [regex]::Matches(
    ($output -join "`n"),
    '(?m)^test result: (?:ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed;'
)
$ranTests = $false
$failedTests = $false
foreach ($summary in $summaries) {
    $passed = [long]::Parse($summary.Groups[1].Value)
    $failed = [long]::Parse($summary.Groups[2].Value)
    if ($passed + $failed -gt 0) { $ranTests = $true }
    if ($failed -gt 0) { $failedTests = $true }
}
if (-not $ranTests) {
    throw "Cargo module '$Package $TestFilter' did not complete a nonempty test run (exit code $cargoExitCode). Stopping before named tests."
}
if ($cargoExitCode -ne 0 -or $failedTests) {
    $message = "Cargo module '$Package $TestFilter' failed (exit code $cargoExitCode); continuing named tests for diagnostics."
    $Failures.Add($message)
    Write-Host "::error::$message"
}
