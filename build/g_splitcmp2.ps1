$out = 'C:\Users\Public\splitcmp.txt'
function Parse-Sweep([string]$path) {
    $res = @{}
    $cur = $null
    foreach ($line in Get-Content $path) {
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
Add-Content $out ("counts: t0={0} t1={1} post={2}" -f $t0.Count, $t1.Count, $p.Count)
$stable = 0
foreach ($k in $t0.Keys) {
    if (-not $p.ContainsKey($k)) { Add-Content $out "$k MISSING-IN-POST"; continue }
    $a = ($t0[$k] -join "|")
    $b = ($t1[$k] -join "|")
    $c = ($p[$k] -join "|")
    if ($a -ceq $b) {
        if ($a -ceq $c) { $stable++ }
        else { Add-Content $out "$k POST-DIFFERS (baseline-stable)" }
    } else {
        if ($b -ceq $c) { Add-Content $out "$k VOLATILE post==t1" }
        elseif ($a -ceq $c) { Add-Content $out "$k VOLATILE post==t0" }
        else { Add-Content $out "$k VOLATILE post-unique" }
    }
}
Add-Content $out ("STABLE={0}" -f $stable)
Add-Content $out 'END'
