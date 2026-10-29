$out = 'C:\Users\Public\splitcmp.txt'
function Parse-Sweep([string]$path) {
    # 把 sweep 文本切成 {needle -> 全部输出行}
    $res = @{}
    $cur = $null
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^---------- ("[^"]+") ----------') {
            $cur = $matches[1]
            $res[$cur] = New-Object System.Collections.Generic.List[string]
            continue
        }
        if ($line -match '^=====') { $cur = $null; continue }
        if ($cur) { $res[$cur].Add($line) }
    }
    return $res
}
$t0 = Parse-Sweep 'C:\Users\Public\cli_base_t0.txt'
$t1 = Parse-Sweep 'C:\Users\Public\cli_base_t1.txt'
$p  = Parse-Sweep 'C:\Users\Public\cli_post_split.txt'
Add-Content $out "条目数: t0=$($t0.Count) t1=$($t1.Count) post=$($p.Count)"
$stable = @(); $volatile = @(); $bad = @()
foreach ($k in $t0.Keys) {
    if (-not $p.ContainsKey($k)) { $bad += "$k MISSING-IN-POST"; continue }
    $a = ($t0[$k] -join "`n")
    $b = ($t1[$k] -join "`n")
    $c = ($p[$k] -join "`n")
    if ($a -ceq $b) {
        if ($a -ceq $c) { $stable += $k } else { $bad += "$k POST-DIFFERS(基线稳定但拆分后不同)" }
    } else {
        $volatile += $k
        if ($b -ceq $c) { Add-Content $out "$k [时变: T0/T1 亦不同; 拆分后与 T1 一致]" }
        else { Add-Content $out "$k [时变: T0/T1 不同; 拆分后与 T0/T1 均不同]" }
    }
}
Add-Content $out ("严格逐字节一致(基线内稳定且拆分后相同): {0} 条" -f $stable.Count)
Add-Content $out ("天然时变条目: {0}" -f ($volatile -join ', '))
foreach ($b in $bad) { Add-Content $out "!! $b" }
Add-Content $out 'END'