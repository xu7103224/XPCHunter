@echo off
whoami /groups > C:\Users\Public\s1.txt 2>&1
whoami /priv >> C:\Users\Public\s1.txt 2>&1
sc query RTZ14 >> C:\Users\Public\s1.txt 2>&1
echo SCRIPT_DONE >> C:\Users\Public\s1.txt
