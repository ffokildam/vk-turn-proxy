# Получаем default gateway (IPv4)
$gateway = Get-NetRoute `
    -DestinationPrefix "0.0.0.0/0" `
    | Sort-Object RouteMetric `
    | Select-Object -First 1 -ExpandProperty NextHop

if (-not $gateway) {
    Write-Error "Failed to determine default gateway"
    exit 1
}

Write-Host "Default gateway: $gateway"

# Читаем stdin
$stdin = [System.Console]::In
while (($line = $stdin.ReadLine()) -ne $null) {
    $addr = $line.Trim()
    if ($addr -eq "") { continue }

    Write-Host "Adding route to $addr via $gateway"

    New-NetRoute `
        -DestinationPrefix "$addr/32" `
        -NextHop $gateway `
        -PolicyStore ActiveStore `
        -ErrorAction Stop
}