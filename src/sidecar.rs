//! Reap Electron sidecar workers whose owning process has exited.
//!
//! Antigravity's Node sidecar uses the same image as the window. Matching the
//! image alone would kill real windows; require its exact loader and entrypoint,
//! a dead parent (including PID reuse), and a startup grace period.

#[cfg(windows)]
pub fn reap_orphans() -> Result<u32, String> {
    let out = crate::utils::powershell_within(SCRIPT, std::time::Duration::from_secs(15))
        .ok_or("sidecar inspection timed out")?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|_| "invalid sidecar cleanup result".into())
}

#[cfg(windows)]
const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$removed=0
$now=Get-Date
$workers=@(Get-CimInstance Win32_Process -Filter "Name='Antigravity.exe'")
foreach ($w in $workers) {
  if ($w.CommandLine -notmatch '(?i)--import=(?:"?file:///)[^\r\n"]*/sidecar_sdk/register_loader\.js"?\s+main\.mjs(?:\s|$)') { continue }
  if (($now-$w.CreationDate).TotalSeconds -lt 15) { continue }
  $parent=Get-CimInstance Win32_Process -Filter ("ProcessId="+$w.ParentProcessId)
  if ($parent -and $parent.CreationDate -le $w.CreationDate) {
    # agy-node.cmd waits for the Node child, so its own dead owner is the
    # lifetime boundary. An arbitrary live shell is never treated as ours.
    if ($parent.Name -ne 'cmd.exe' -or
        $parent.CommandLine -notmatch '(?i)[\\/]agy-node\.cmd"' -or
        $parent.CommandLine -notmatch '(?i)/sidecar_sdk/register_loader\.js.*\s+main\.mjs') { continue }
    $owner=Get-CimInstance Win32_Process -Filter ("ProcessId="+$parent.ParentProcessId)
    if ($owner -and $owner.CreationDate -le $parent.CreationDate) { continue }
  }
  $current=Get-CimInstance Win32_Process -Filter ("ProcessId="+$w.ProcessId)
  if (!$current -or $current.CreationDate -ne $w.CreationDate) { continue }
  try { Stop-Process -Id $w.ProcessId -Force; $removed++ }
  catch {
    if (Get-Process -Id $w.ProcessId -ErrorAction SilentlyContinue) { throw }
  }
}
$removed
"#;

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn reaper_preserves_live_owners_and_windows_but_reaps_dead_shell_owners() {
        // Mock every process lookup/termination: exercise the production script
        // without inspecting or killing a process on the developer's machine.
        let fixture = r#"
$now=Get-Date
$old=$now.AddMinutes(-5)
$loader='Antigravity.exe --import=file:///C:/sdk/sidecar_sdk/register_loader.js main.mjs'
$shell='cmd.exe /c ""C:\test\agy-node.cmd" --import=file:///C:/sdk/sidecar_sdk/register_loader.js main.mjs"'
$global:records=@{}
function Record($idValue,$parentId,$name,$command,$created) {
  $r=[pscustomobject]@{ProcessId=$idValue; ParentProcessId=$parentId; Name=$name; CommandLine=$command; CreationDate=$created}
  $global:records[$idValue]=$r
  $r
}
$global:workers=@(
  (Record 101 201 'Antigravity.exe' $loader $old),
  (Record 102 202 'Antigravity.exe' $loader $old),
  (Record 103 203 'Antigravity.exe' $loader $old),
  (Record 104 204 'Antigravity.exe' $loader $now),
  (Record 105 205 'Antigravity.exe' 'Antigravity.exe --type=renderer' $old),
  (Record 106 206 'Antigravity.exe' $loader $old),
  (Record 107 207 'Antigravity.exe' $loader $old)
)
$null=Record 201 301 'cmd.exe' $shell $old.AddSeconds(-1)
$null=Record 301 0 'language_server.exe' 'server' $old.AddSeconds(-2)
$null=Record 202 302 'cmd.exe' $shell $old.AddSeconds(-1)
$null=Record 203 0 'other.exe' 'reused PID' $now
$null=Record 206 0 'cmd.exe' 'cmd.exe /c unrelated.cmd' $old.AddSeconds(-1)
function Get-CimInstance { param($ClassName,$Filter)
  if ($Filter -eq "Name='Antigravity.exe'") { $global:workers }
  else { $global:records[[int]($Filter -replace '^ProcessId=','')] }
}
$global:stopped=@()
function Stop-Process { param($Id,[switch]$Force) $global:stopped += $Id }
"#;
        let script = format!("{fixture}\n$count=& {{ {SCRIPT} }}; if ($count -ne 3 -or ($global:stopped -join ',') -ne '102,103,107') {{ throw ('Unexpected kills: '+($global:stopped -join ',')) }}; 'ok'");
        let out = crate::utils::powershell(&script).expect("PowerShell completed");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
    }
}
