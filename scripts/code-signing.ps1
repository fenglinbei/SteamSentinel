# Shared release helper. The caller must select a certificate explicitly.
function Get-ReleaseSigningProfile([string]$Thumbprint, [string]$SignToolPath) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    if ($Thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid signing certificate thumbprint.' }
    $cert = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $Thumbprint) -ErrorAction Stop
    if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date) -or $cert.NotBefore -gt (Get-Date)) { throw 'Signing certificate is missing a private key or outside its validity period.' }
    if (-not ($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })) { throw 'A Code Signing certificate is required.' }
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
        $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        $SignToolPath = Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace($SignToolPath) -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) { throw 'Windows SDK SignTool was not found.' }
    $selfSigned = $cert.Subject -eq $cert.Issuer
    return [pscustomobject]@{ Certificate=$cert; Thumbprint=$Thumbprint.ToUpperInvariant(); Tool=(Resolve-Path -LiteralPath $SignToolPath).Path; SelfSigned=$selfSigned }
}

function Sign-ReleaseFiles($Profile, [string]$Root, [string[]]$RelativeFiles) {
    if ($null -eq $Profile) { return }
    foreach ($relative in $RelativeFiles) {
        $file = [IO.Path]::GetFullPath((Join-Path $Root $relative))
        if (-not $file.StartsWith([IO.Path]::GetFullPath($Root).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Signing target escaped payload root.' }
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Signing target missing or redirected: $relative" }
        & $Profile.Tool sign /s My /sha1 $Profile.Thumbprint /fd SHA256 $file
        if ($LASTEXITCODE -ne 0) { throw "Code signing failed: $relative" }
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $Profile.Thumbprint -or $signature.Status -eq 'HashMismatch') { throw "Signed file failed identity/integrity inspection: $relative" }
    }
}

function Write-ReleaseSigningInfo($Profile, [string]$Root) {
    if ($null -eq $Profile) { $status='UNSIGNED'; $lines=@('SignatureStatus=UNSIGNED') }
    else {
        $status = if ($Profile.SelfSigned) { 'SELF-SIGNED' } else { 'SIGNED' }
        $lines=@("SignatureStatus=$status", "Subject=$($Profile.Certificate.Subject)", "CertificateThumbprint=$($Profile.Thumbprint)",
            "CertificateExpires=$($Profile.Certificate.NotAfter.ToUniversalTime().ToString('O'))", 'Timestamp=NONE',
            'Trust=Not installed or modified by this build. A self-signed certificate is not publicly trusted.',
            'PrivateKey=Not included. Certificate contains only the public key.',
            'Verify=Compare release hashes and certificate fingerprints through a trusted independent channel.')
        Export-Certificate -Cert $Profile.Certificate -FilePath (Join-Path $Root 'SIGNER.cer') -Type CERT | Out-Null
    }
    [IO.File]::WriteAllLines((Join-Path $Root 'SIGNING.txt'), $lines, [Text.UTF8Encoding]::new($false))
    return $status
}

function Get-InnoSigningArguments($Profile) {
    if ($null -eq $Profile) { return @() }
    # Inno expands $q and $f, PowerShell must pass them literally. No arbitrary $p command.
    $command = '$q' + $Profile.Tool + '$q sign /s My /sha1 ' + $Profile.Thumbprint + ' /fd SHA256 $f'
    return @('/DEnableSigning=1', ('/Sfenglinbei=' + $command))
}
