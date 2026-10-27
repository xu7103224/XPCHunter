$out = 'C:\Users\Public\sw_diff3.txt'
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
$a = Parse-AB 'C:\Users\Public\sw_oA.txt'
$b = Parse-AB 'C:\Users\Public\sw_oB.txt'
Add-Content $out "orig-A cmds=$($a.Count)  orig-B cmds=$($b.Count)"
Add-Content $out ''
$nSame = 0; $nDiff = 0
foreach ($k in ($a.Keys | Sort-Object)) {
    if (-not $b.ContainsKey($k)) { Add-Content $out ("{0,-8} MISSING-IN-B" -f $k); continue }
    $la = [int]($a[$k].Out.Length / 2)
    $lb = [int]($b[$k].Out.Length / 2)
    $v = ''
    if ($a[$k].Res -ne $b[$k].Res -or $a[$k].St -ne $b[$k].St) { $v = 'STATUS-DIFF' }
    elseif ($a[$k].Out -ceq $b[$k].Out) { $v = 'same'; $nSame++ }
    else { $v = 'DIFF'; $nDiff++ }
    if ($v -ne 'same') { Add-Content $out ("{0,-8} resA={1,-6} resB={2,-6} lenA={3,-8} lenB={4,-8} {5}" -f $k, $a[$k].Res, $b[$k].Res, $la, $lb, $v) }
}
Add-Content $out ''
Add-Content $out "SUMMARY same=$nSame diff=$nDiff"
Add-Content $out 'END'