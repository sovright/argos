[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]] $Failures,

    [Parameter(Mandatory = $true)]
    [string] $Package,

    [Parameter(Mandatory = $true)]
    [string] $TestName
)

# Keep the exact runner's nonzero-exit and zero-test checks. Only named test
# failures are collected; the workflow still throws after attempting the list.
try {
    & "$PSScriptRoot/run-exact-cargo-test.ps1" -Package $Package -TestName $TestName
} catch {
    $message = "${Package}: ${TestName}: $($_.Exception.Message)"
    $Failures.Add($message)
    Write-Host "::error::$message"
}
