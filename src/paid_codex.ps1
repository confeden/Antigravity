param(
    [ValidateSet('set', 'remove')][string]$Mode,
    [string]$Documents = [Environment]::GetFolderPath('MyDocuments')
)

if (!$Documents) { throw 'Windows did not return the Documents folder.' }

$start = '# BEGIN AI Unlocker PAID Codex'
$end = '# END AI Unlocker PAID Codex'
$pattern = '(?ms)\r?\n' + [regex]::Escape($start) + '\r?\n.*?^' + [regex]::Escape($end) + '\r?\n'
$hook = @'
if (!(Get-Command codex -CommandType Alias,Function -ErrorAction SilentlyContinue)) {
    function global:codex {
        $stateDir = Join-Path $env:LOCALAPPDATA 'AGUnlocker'
        $selection = Join-Path $stateDir 'paid-proxy-enabled'
        if (!(Test-Path -LiteralPath $selection)) {
            & (Get-Command codex.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source @args
            return
        }
        $active = Get-Content -LiteralPath $selection -Raw -Encoding UTF8 -ErrorAction Stop
        if ($active -notmatch '"codex-cli"') {
            & (Get-Command codex.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source @args
            return
        }
        $policyPath = Join-Path $stateDir 'paid-wfp-state.json'
        $policy = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ($policy.apps -notcontains 'codex-cli' -or $policy.port -lt 1 -or $policy.port -gt 65535) {
            throw 'AI Unlocker has not applied the PAID protection for Codex CLI.'
        }
        $target = Join-Path $env:LOCALAPPDATA 'Programs\OpenAI\Codex\bin\codex.exe'
        $proxy = 'http://127.0.0.1:' + [int]$policy.port
        $vars = @{
            HTTP_PROXY = $proxy
            HTTPS_PROXY = $proxy
            ALL_PROXY = $proxy
            WS_PROXY = $proxy
            WSS_PROXY = $proxy
            NO_PROXY = 'localhost,127.0.0.1,::1'
        }
        $previous = @{}
        foreach ($name in $vars.Keys) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        try {
            foreach ($name in $vars.Keys) {
                [Environment]::SetEnvironmentVariable($name, $vars[$name], 'Process')
            }
            $codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
            $daemonPid = Join-Path $codexHome 'app-server-daemon\daemon.pid'
            $daemonStamp = Join-Path $stateDir 'paid-codex-daemon.stamp'
            $isDaemonCmd = ($args.Count -ge 2 -and $args[0] -ieq 'app-server' -and $args[1] -ieq 'daemon')
            if (!$isDaemonCmd -and (Test-Path -LiteralPath $daemonPid)) {
                $pidTicks = (Get-Item -LiteralPath $daemonPid -ErrorAction SilentlyContinue).LastWriteTimeUtc.Ticks
                $expected = "$($policy.port):$pidTicks"
                $seen = if (Test-Path -LiteralPath $daemonStamp) {
                    (Get-Content -LiteralPath $daemonStamp -Raw -Encoding UTF8 -ErrorAction SilentlyContinue).Trim()
                } else { '' }
                if ($seen -cne $expected) {
                    $policyTicks = (Get-Item -LiteralPath $policyPath -ErrorAction SilentlyContinue).LastWriteTimeUtc.Ticks
                    if ($pidTicks -lt $policyTicks) {
                        & $target app-server daemon restart *> $null
                        if (Test-Path -LiteralPath $daemonPid) {
                            $pidTicks = (Get-Item -LiteralPath $daemonPid -ErrorAction SilentlyContinue).LastWriteTimeUtc.Ticks
                            $expected = "$($policy.port):$pidTicks"
                        }
                    }
                    try {
                        [IO.File]::WriteAllText($daemonStamp, $expected, [Text.UTF8Encoding]::new($false))
                    } catch {}
                }
            }
            & $target @args
        } finally {
            foreach ($name in $previous.Keys) {
                [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
            }
        }
    }
}
'@

foreach ($shell in 'WindowsPowerShell', 'PowerShell') {
    $dir = Join-Path $Documents $shell
    $file = Join-Path $dir 'profile.ps1'
    $exists = [IO.File]::Exists($file)
    $encoding = [Text.UTF8Encoding]::new($true, $true)
    $text = ''
    if ($exists) {
        $reader = [IO.StreamReader]::new($file, [Text.UTF8Encoding]::new($false, $true), $true)
        try {
            $text = $reader.ReadToEnd()
            $encoding = $reader.CurrentEncoding
        } finally {
            $reader.Dispose()
        }
    }
    $original = [regex]::Replace($text, $pattern, '')
    if ($original.Contains($start) -or $original.Contains($end)) {
        throw "The managed AI Unlocker block is incomplete in $file."
    }
    $next = $original
    if ($Mode -eq 'set') {
        $next += "`r`n$start`r`n$hook`r`n$end`r`n"
    }
    if ($next -ceq $text) { continue }

    [void][IO.Directory]::CreateDirectory($dir)
    $temp = Join-Path $dir ('.ai-unlocker-codex-' + [Guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temp, $next, $encoding)
        if ($exists) {
            [IO.File]::Replace($temp, $file, [NullString]::Value)
        } else {
            [IO.File]::Move($temp, $file)
        }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}
