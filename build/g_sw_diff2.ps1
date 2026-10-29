$out = 'C:\Users\Public\sw_diff2.txt'
function Parse-AB([string]$path) {
    $res = @{}
    $cur = $null
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^CMD\s+(0x[0-9A-Fa-f]+)\s+INSZ=(\d+)\s+OUTSZ=(\d+)\s+RES=(\S+)\s+(\S+)\s+ERR=(\S+)\s+HDRLEN=(\d+)') {
            $cur = $matches[1].ToUpper()
            $res[$cur] = @{ Res = $matches[4]; St = $matches[5]; Out = '' }
        } elseif ($line -match '^OUT\s+(\S+)' -and $cur) {
            $v = $matches[1]
            if ($v -ne '-') { $res[$cur].Out = $v }
            $cur = $null
        }
    }
    return $res
}
$a = Parse-AB 'C:\Users\Public\sw_orig.txt'
$b = Parse-AB 'C:\Users\Public\sw_orig2.txt'
Add-Content $out "orig-run1 cmds=$($a.Count)  orig-run2 cmds=$($b.Count)"
Add-Content $out ''
Add-Content $out ("{0,-8} {1,-6} {2,-6} {3,-8} {4,-8} {5}" -f 'CMD','res1','res2','len1','len2','verdict')
$nSame = 0; $nDiff = 0
foreach ($k in ($a.Keys | Sort-Object)) {
    if (-not $b.ContainsKey($k)) { Add-Content $out ("{0,-8} MISSING-IN-RUN2" -f $k); continue }
    $la = [int]($a[$k].Out.Length / 2)
    $lb = [int]($b[$k].Out.Length / 2)
    $verdict = ''
    if ($a[$k].Res -ne $b[$k].Res -or $a[$k].St -ne $b[$k].St) { $verdict = 'STATUS-DIFF' }
    elseif ($a[$k].Out -ceq $b[$k].Out) { $verdict = 'same'; $nSame++ }
    else { $verdict = 'DIFF'; $nDiff++ }
    if ($verdict -ne 'same') {
        Add-Content $out ("{0,-8} {1,-6} {2,-6} {3,-8} {4,-8} {5}" -f $k, $a[$k].Res, $b[$k].Res, $la, $lb, $verdict)
    }
}
Add-Content $out ''
Add-Content $out "SUMMARY same=$nSame diff=$nDiff"
Add-Content $out 'END'