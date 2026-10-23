Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class U {
  [DllImport("user32.dll")] public static extern IntPtr FindWindowA(string c, string n);
  [DllImport("user32.dll")] public static extern IntPtr FindWindowExA(IntPtr p, IntPtr a, string c, string n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
}
"@
$p = Get-Process xpch_frontend -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) { Write-Output "no-process"; exit 1 }
$top = $p.MainWindowHandle
Write-Output ("top=" + $top)
$child = [IntPtr]::Zero
do {
  $child = [U]::FindWindowExA($top, $child, $null, $null)
  if ($child -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 2048
    [void][U]::GetWindowTextW($child, $sb, 2048)
    $t = $sb.ToString()
    if ($t.Length -gt 0) {
      Write-Output ("id=" + [U]::GetDlgCtrlID($child) + "  " + $t)
    }
  }
} while ($child -ne [IntPtr]::Zero)
