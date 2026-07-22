with open("XPCHunterDrv.vcxproj", encoding="utf-8") as f:
    content = f.read()

backslash = chr(92)
newline = chr(10)

temp_files = [
    "Batch1.c", "Batch2.c", "Batch3.c", "Batch4.c",
    "MissingFuncs.c",
    "MissingFuncs_add1.c", "MissingFuncs_add2.c", "MissingFuncs_add3.c",
    "MissingFuncs_add4.c", "MissingFuncs_add5.c", "MissingFuncs_add6.c",
    "MissingFuncs_add7.c", "MissingFuncs_add8.c", "MissingFuncs_add_open.c",
]

for tf in temp_files:
    target = "src" + backslash + tf
    lines = content.split(newline)
    new_lines = [l for l in lines if not (target in l and "ClCompile" in l)]
    removed = len(lines) - len(new_lines)
    if removed > 0:
        print("Removed: " + tf + " (" + str(removed) + " lines)")
        content = newline.join(new_lines)
    else:
        print("NOT FOUND: " + tf)

with open("XPCHunterDrv.vcxproj", "w", encoding="utf-8") as f:
    f.write(content)
print("\nDone")
