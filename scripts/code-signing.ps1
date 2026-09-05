# Shared release helper. The caller must select a certificate explicitly.

function Get-ReleaseSigningProfile {
    [CmdletBinding()]
    param(
        [string]$Thumbprint,
        [string]$SignToolPath,
        [string]$TimestampUrl,
        [switch]$RequirePublicTrust
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        if ($RequirePublicTrust) {
            throw 'A public release requires an explicitly selected, publicly trusted Code Signing certificate.'
        }

        return $null
    }

    $normalizedThumbprint = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[A-F0-9]{40}$') {
        throw 'Invalid signing certificate thumbprint.'
    }

    if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
        $timestampUri = $null
        if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or
            $timestampUri.Scheme -ne [Uri]::UriSchemeHttps) {
            throw 'The RFC 3161 timestamp URL must be an absolute HTTPS URL.'
        }
    }
    elseif ($RequirePublicTrust) {
        throw 'A public release requires an HTTPS RFC 3161 timestamp URL.'
    }

    $cert = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $normalizedThumbprint) -ErrorAction Stop
    $now = Get-Date
    if (-not $cert.HasPrivateKey -or $cert.NotAfter -le $now -or $cert.NotBefore -gt $now) {
        throw 'Signing certificate is missing a private key or outside its validity period.'
    }
    if (-not ($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })) {
        throw 'A Code Signing certificate is required.'
    }

    if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
        $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        $SignToolPath = Get-ChildItem -LiteralPath $sdkRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace($SignToolPath) -or
        -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
        throw 'Windows SDK SignTool was not found.'
    }

    $selfSigned = $cert.Subject -eq $cert.Issuer
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        $chainTrusted = $chain.Build($cert)
        $chainStatus = ($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ','
        if ([string]::IsNullOrWhiteSpace($chainStatus)) { $chainStatus = 'NoError' }
    }
    finally {
        $chain.Dispose()
    }

    if ($RequirePublicTrust -and ($selfSigned -or -not $chainTrusted)) {
        throw "Public release certificate trust validation failed (SelfSigned=$selfSigned; ChainStatus=$chainStatus)."
    }

    return [pscustomobject]@{
        Certificate = $cert
        Thumbprint = $normalizedThumbprint
        Tool = (Resolve-Path -LiteralPath $SignToolPath).Path
        SelfSigned = $selfSigned
        ChainTrusted = $chainTrusted
        ChainStatus = $chainStatus
        TimestampUrl = $TimestampUrl
        RequirePublicTrust = [bool]$RequirePublicTrust
    }
}

function Assert-ReleaseSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$DisplayName = $Path
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $Profile.Thumbprint -or
        $signature.Status.ToString() -eq 'HashMismatch') {
        throw "Signed file failed identity/integrity inspection: $DisplayName"
    }
    if ($Profile.RequirePublicTrust -and $signature.Status.ToString() -ne 'Valid') {
        throw "Public release signature is not trusted for $DisplayName (Status=$($signature.Status))."
    }
    if (-not [string]::IsNullOrWhiteSpace($Profile.TimestampUrl) -and
        $null -eq $signature.TimeStamperCertificate) {
        throw "RFC 3161 timestamp is missing from $DisplayName."
    }

    return $signature
}

function Sign-ReleaseFiles {
    [CmdletBinding()]
    param(
        $Profile,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$RelativeFiles
    )

    if ($null -eq $Profile) { return }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    foreach ($relative in $RelativeFiles) {
        $file = [IO.Path]::GetFullPath((Join-Path $rootFull $relative))
        if (-not $file.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Signing target escaped payload root.'
        }
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
            ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Signing target missing or redirected: $relative"
        }

        $arguments = @('sign', '/s', 'My', '/sha1', $Profile.Thumbprint, '/fd', 'SHA256')
        if (-not [string]::IsNullOrWhiteSpace($Profile.TimestampUrl)) {
            $arguments += @('/tr', $Profile.TimestampUrl, '/td', 'SHA256')
        }
        $arguments += $file
        & $Profile.Tool @arguments
        if ($LASTEXITCODE -ne 0) { throw "Code signing failed: $relative" }
        Assert-ReleaseSignature -Profile $Profile -Path $file -DisplayName $relative | Out-Null
    }
}

function Write-ReleaseSigningInfo {
    [CmdletBinding()]
    param(
        $Profile,
        [Parameter(Mandatory = $true)][string]$Root
    )

    if ($null -eq $Profile) {
        $status = 'UNSIGNED-PREVIEW'
        $lines = @(
            'SignatureStatus=UNSIGNED-PREVIEW',
            'Trust=This preview is not a public release and has no publisher authentication.',
            'Timestamp=NONE'
        )
    }
    else {
        if ($Profile.RequirePublicTrust) { $status = 'PUBLIC-TRUSTED-TIMESTAMPED' }
        elseif ($Profile.SelfSigned) { $status = 'SELF-SIGNED-PREVIEW' }
        else { $status = 'SIGNED-PREVIEW' }

        $timestamp = if ([string]::IsNullOrWhiteSpace($Profile.TimestampUrl)) { 'NONE' } else { $Profile.TimestampUrl }
        $lines = @(
            "SignatureStatus=$status",
            "Subject=$($Profile.Certificate.Subject)",
            "CertificateThumbprint=$($Profile.Thumbprint)",
            "CertificateExpires=$($Profile.Certificate.NotAfter.ToUniversalTime().ToString('O'))",
            "CertificateChainTrusted=$($Profile.ChainTrusted)",
            "CertificateChainStatus=$($Profile.ChainStatus)",
            "Timestamp=$timestamp",
            'PrivateKey=Not included. SIGNER.cer contains only the public key.',
            'Verify=Compare release hashes and certificate fingerprints through a trusted independent channel.'
        )
        Export-Certificate -Cert $Profile.Certificate -FilePath (Join-Path $Root 'SIGNER.cer') -Type CERT | Out-Null
    }

    [IO.File]::WriteAllLines((Join-Path $Root 'SIGNING.txt'), $lines, [Text.UTF8Encoding]::new($false))
    return $status
}

function Get-InnoSigningArguments {
    [CmdletBinding()]
    param($Profile)

    if ($null -eq $Profile) { return @() }
    # Inno expands $q and $f. PowerShell must pass those tokens literally.
    $command = '$q' + $Profile.Tool + '$q sign /s My /sha1 ' + $Profile.Thumbprint + ' /fd SHA256'
    if (-not [string]::IsNullOrWhiteSpace($Profile.TimestampUrl)) {
        $command += ' /tr $q' + $Profile.TimestampUrl + '$q /td SHA256'
    }
    $command += ' $f'
    return @('/DEnableSigning=1', ('/SsteamSentinelSign=' + $command))
}
