# AI Unlocker - terminal mode in one command (Windows 10/11):
#
#   PowerShell:  irm https://raw.githubusercontent.com/confeden/Antigravity/main/tui.ps1 | iex
#   cmd:         powershell -NoProfile -c "irm https://raw.githubusercontent.com/confeden/Antigravity/main/tui.ps1 | iex"
#
# Fetches the latest release from GitHub into %LOCALAPPDATA%\AGUnlocker\AG.exe and
# runs it right in this console. Running the same command again downloads only
# when there is a newer version. Start it from an elevated console for the DNS
# half of the bypass; otherwise the program offers a restart with admin rights.
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
    $dir = Join-Path $env:LOCALAPPDATA 'AGUnlocker'
    $exe = Join-Path $dir 'AG.exe'
    $stamp = "$exe.version"

    # The newest tag from where /releases/latest redirects to: no API call, so
    # no rate limit.
    $tag = $null
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Method Head "https://github.com/$repo/releases/latest"
        $uri = $r.BaseResponse.ResponseUri                                  # Windows PowerShell 5.1
        if (-not $uri) { $uri = $r.BaseResponse.RequestMessage.RequestUri } # PowerShell 7
        $tag = $uri.AbsoluteUri.TrimEnd('/').Split('/')[-1]
    } catch {}
    $ver = if ($tag) { $tag.TrimStart('v') } else { '' }

    if ($ver -notmatch '^[0-9._]+$') {
        if (-not (Test-Path $exe)) { throw "Could not find the latest version on github.com/$repo." }
        Write-Host 'GitHub did not answer - starting the copy downloaded before.'
    } elseif (-not (Test-Path $exe) -or (Get-Content $stamp -ErrorAction SilentlyContinue) -ne $ver) {
        Write-Host "Downloading AI Unlocker $ver ..."
        New-Item -ItemType Directory -Force $dir | Out-Null
        # The tag spells a fourth number with a dot (v2.24.0.1), the asset with an
        # underscore (AG_2.24.0_1.exe): try both.
        $alt = $ver -replace '\.(\d+)$', '_$1'
        $got = $false
        $downloadError = $null
        foreach ($suffix in @('_portable', '')) {
            foreach ($cand in @($ver, $alt) | Select-Object -Unique) {
                try {
                    Invoke-WebRequest -UseBasicParsing "https://github.com/$repo/releases/download/$tag/AG_$cand$suffix.exe" -OutFile "$exe.part"
                    $kind = ([string][Diagnostics.FileVersionInfo]::GetVersionInfo("$exe.part").FileDescription).Trim()
                    if ($kind -eq 'AI Unlocker Setup') { throw "Windows portable asset is missing in release $tag." }
                    $got = $true
                    break
                } catch {
                    $downloadError = $_
                    if (!$_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 404) { throw }
                }
            }
            if ($got) { break }
        }
        if (!$got) { throw "No Windows program in release $tag. $downloadError" }
        try {
            Move-Item -Force "$exe.part" $exe
            Set-Content -Path $stamp -Value $ver
        } catch {
            # The old copy is running (another window of it): it cannot be
            # replaced now, but it can still be started.
            Remove-Item -Force "$exe.part" -ErrorAction SilentlyContinue
            if (-not (Test-Path $exe)) { throw }
            Write-Host 'The previous version is running and could not be replaced - starting it.'
        }
    }

    # -Wait: the exe is a window program, which a console does not wait for by
    # itself. Waiting is what lets it draw here (--inline) without the prompt
    # taking every other keystroke.
    Start-Process -FilePath $exe -ArgumentList '--tui', '--inline' -Wait -NoNewWindow
}
