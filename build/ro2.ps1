$ErrorActionPreference = 'SilentlyContinue'
Set-Location C:\Users\Public
Remove-Item C:\Users\Public\ro2.txt -ErrorAction SilentlyContinue
$cmds = Get-Content C:\Users\Public\safe_ro.txt | Where-Object { $_ -match '^0x' }
$sizes = @(4194304, 2097152, 1864, 1800, 1400, 1352, 7168, 2648, 4096, 96, 64, 16, 8, 4)
foreach ($cmd in $cmds) {
    & sc.exe stop XPCHunterDrv 2>&1 | Out-Null
    Start-Sleep -Milliseconds 700
    & sc.exe start XPCHunterDrv 2>&1 | Out-Null
    Start-Sleep -Milliseconds 1200
    $res = 'REJ'
    foreach ($s in $sizes) {
        $o = & .\xpch_probe.exe --live --cmd $cmd --dump $s 2>&1 | Select-String -Pattern '-> OK|-> REJ' | Select-Object -First 1
        if ($o -match 'OK') { $res = "OK:$s"; break }
    }
    Add-Content C:\Users\Public\ro2.txt "$cmd $res"
}
Add-Content C:\Users\Public\ro2.txt '# done'
