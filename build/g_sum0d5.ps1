$out = 'C:\Users\Public\sum0d5.txt'
$lines = @()
foreach ($f in @('out_0d5_orig.txt','out_0d5_orig2.txt','out_0d5_mine.txt','out_0d5_mine2.txt','out_0d5_mine3.txt')) {
    $p = "C:\Users\Public\$f"
    if (Test-Path $p) {
        $len = (Get-Item $p).Length
        $txt = Get-Content $p -TotalCount 40 -Encoding UTF8
        $hdr = ($txt | Select-String -Pattern '^\s+0000:').Line
        $lines += "$f size=$len hdr=[$hdr]"
    } else {
        $lines += "$f MISSING"
    }
}
$lines += 'SERVICES:'
$lines += (sc.exe query XPCHunterDrv | Select-String STATE)
$lines += (sc.exe query ViewPlusPlusByLinxer | Select-String STATE)
$lines += 'END'
$lines | Set-Content -Path $out -Encoding UTF8