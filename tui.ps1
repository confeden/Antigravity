# AI Unlocker - terminal mode in one command (Windows 10/11):
#
#   PowerShell:  irm https://raw.githubusercontent.com/confeden/Antigravity/main/tui.ps1 | iex
#   cmd:         powershell -NoProfile -c "irm https://raw.githubusercontent.com/confeden/Antigravity/main/tui.ps1 | iex"
#
# Installs the latest Windows release for the current user and opens its TUI.
# An elevated console is only needed for the privileged DNS features.
#
# ASCII only, and no BOM (G60): `irm | iex` keeps a BOM as U+FEFF, which the
# PowerShell 5.1 parser rejects, while without a BOM a *file* is read as ANSI by
# 5.1 and any non-ASCII byte can turn into a quote character. ASCII is the one
# encoding both ways read the same.

# In a script block, so `iex` leaves nothing behind in the caller's session.
& {
    $ErrorActionPreference = 'Stop'
    # Invoke-WebRequest's progress bar makes a 15 MB download take minutes on
    # Windows PowerShell 5.1.
    $ProgressPreference = 'SilentlyContinue'
    # An older Windows 10 can still default to TLS 1.0, which GitHub refuses.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'confeden/Antigravity'
    $exe = Join-Path $env:LOCALAPPDATA 'Programs\AI Unlocker\ag_unlocker.exe'
    $installed = $null
    $updated = $false

    function Parse-ReleaseVersion([string]$value) {
        if ($value -notmatch '^[vV]?(\d+\.\d+\.\d+)(?:[._](\d+))?$') { return $null }
        $build = if ($Matches[2]) { $Matches[2] } else { '0' }
        return [version]($Matches[1] + '.' + $build)
    }

    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        $installed = Parse-ReleaseVersion ([Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion)
    }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -TimeoutSec 15
    } catch {
        if (!$installed) { throw }
        Write-Host "GitHub did not answer - starting the installed copy. $($_.Exception.Message)"
        $release = $null
    }

    if ($release) {
        $tag = [string]$release.tag_name
        $latest = Parse-ReleaseVersion $tag
        if (!$latest -or $release.draft -or $release.prerelease) { throw 'Invalid release version.' }
        if (!$installed -or $latest -gt $installed) {
            $version = $tag.TrimStart('v', 'V')
            $names = @("AI_Unlocker_setup-$version.exe")
            if ($version -match '^(\d+\.\d+\.\d+)[._](\d+)$') {
                $names += "AI_Unlocker_setup-$($Matches[1]).$($Matches[2]).exe"
                $names += "AI_Unlocker_setup-$($Matches[1])_$($Matches[2]).exe"
            }
            $asset = $release.assets | Where-Object {
                $_.name -cin $names -and $_.browser_download_url -ceq "https://github.com/$repo/releases/download/$tag/$($_.name)" -and
                $_.digest -match '^sha256:[0-9a-fA-F]{64}$' -and $_.size -gt 0 -and $_.size -le 200MB
            } | Select-Object -First 1
            if (!$asset) { throw "Release $tag has no verifiable Windows installer." }

            Write-Host "Installing AI Unlocker $version ..."
            $folder = Join-Path ([IO.Path]::GetTempPath()) ('ai-unlocker-tui-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $folder | Out-Null
            $setup = Join-Path $folder 'setup.exe'
            $package = $null
            try {
                Invoke-WebRequest -UseBasicParsing -TimeoutSec 90 -MaximumRedirection 4 -Uri $asset.browser_download_url -OutFile $setup
                $package = [IO.File]::Open($setup, 'Open', 'Read', 'Read')
                if ($package.Length -ne $asset.size -or (Get-FileHash -InputStream $package -Algorithm SHA256).Hash -ne $asset.digest.Substring(7)) {
                    throw 'The Windows installer failed verification.'
                }
                $result = Start-Process -FilePath $setup -ArgumentList '/SILENT /NORESTART /RESTARTEXITCODE=75' -Wait -PassThru
                if ($result.ExitCode -ne 0) { throw "Setup exit code: $($result.ExitCode)" }
                $product = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
                if ((Parse-ReleaseVersion $product) -ne $latest) { throw 'The installed version does not match the release.' }
                $updated = $true
            } finally {
                if ($package) { $package.Dispose() }
                if (Test-Path -LiteralPath $setup) { Remove-Item -LiteralPath $setup }
                Remove-Item -LiteralPath $folder
            }
        }
    }

    # -Wait: the exe is a window program, which a console does not wait for by
    # itself. Waiting is what lets it draw here (--inline) without the prompt
    # taking every other keystroke.
    $flags = @('--tui', '--inline')
    if ($updated) { $flags += '--updated' }
    Start-Process -FilePath $exe -ArgumentList $flags -Wait -NoNewWindow
}
