$ErrorActionPreference='Continue'
$out='C:\kd_tmp\result.txt'
"BEGIN" | Out-File -Encoding utf8 $out
& sc.exe stop RTZ35  *>> $out
& sc.exe delete RTZ35 *>> $out
Copy-Item 'C:\kd_tmp\drv.sys' 'C:\kd_tmp\XPCHunterDrv.sys' -Force
& sc.exe create RTZ35 type= kernel binPath= C:\kd_tmp\XPCHunterDrv.sys *>> $out
& sc.exe start RTZ35 *>> $out
Start-Sleep -Seconds 3
& sc.exe query RTZ35 *>> $out
"WDONE" | Out-File -Append -Encoding utf8 $out
