[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Package,

    [Parameter(Mandatory = $true)]
    [string] $TestName,

    [string] $Target = "x86_64-pc-windows-msvc"
)

$cargoArguments = @(
    "test"
    "--color", "never"
    "-p", $Package
    "--target", $Target
    $TestName
    "--"
    "--exact"
)

$output = & cargo @cargoArguments 2>&1
$cargoExitCode = $LASTEXITCODE
$output | ForEach-Object { Write-Host $_ }

if ($cargoExitCode -ne 0) {
    throw "Exact Cargo test '$TestName' in package '$Package' failed with exit code $cargoExitCode."
}

$summary = $output -join [Environment]::NewLine
if ($summary -notmatch '(?m)^test result: ok\. [1-9][0-9]* passed;') {
    throw "Exact Cargo test '$TestName' in package '$Package' ran zero tests."
}
