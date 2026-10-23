Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class U2 {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr FindWindowExA(IntPtr p, IntPtr a, string c, string n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  public static List<IntPtr> ForPid(uint want) {
    var r = new List<IntPtr>();
    EnumWindows((h,p) => { uint id; GetWindowThreadProcessId(h, out id); if (id==want) r.Add(h); return true; }, IntPtr.Zero);
    return r;
  }
}
"@
$p = Get-Process xpch_frontend -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) { Write-Output "no-process"; exit 1 }
$tops = [U2]::ForPid([uint32]$p.Id)
Write-Output ("tops=" + $tops.Count)
foreach ($t in $tops) {
  $sb = New-Object System.Text.StringBuilder 512
  [void][U2]::GetWindowTextW($t, $sb, 512)
  Write-Output ("top hwnd=" + $t + " title=[" + $sb.ToString() + "]")
  $c = [IntPtr]::Zero
  do {
    $c = [U2]::FindWindowExA($t, $c, $null, $null)
    if ($c -ne [IntPtr]::Zero) {
      $s2 = New-Object System.Text.StringBuilder 2048
      [void][U2]::GetWindowTextW($c, $s2, 2048)
      $txt = $s2.ToString()
      if ($txt.Length -gt 0) { Write-Output ("  id=" + [U2]::GetDlgCtrlID($c) + " [" + $txt + "]") }
    }
  } while ($c -ne [IntPtr]::Zero)
}
