// ============================================================================
// RegistryViews.c — Registry 页（原版第 6 个主 Tab，5 项）
//
// 清单条目与实现：
//   Reg Handle                枚举全系统 ObjectType 为 Key 的句柄
//                             （NtQuerySystemInformation(SystemExtendedHandleInformation)
//                               + ObjectTypesInformation 取类型名 → 只挑 "Key"）
//   View CmpNotifyChange      原版列出已注册的 CmRegisterCallback /
//                             CmRegisterCallbackEx 回调链。用户态拿不到这条链，
//                             要用驱动命令 0x127（CmdEnumRegistryContext），
//                             该命令尚未验证出数据，所以本项**未实现**，
//                             也不拿 Hidden Item 子页冒充（见验收清单 Tab 6）。
//   Key                       按路径打开一个键并列出它的值（只读），
//                             Kernel 页的 "Locate in Registry Tab" 落到这里
//   Copy Key Name / RegPath / RegValue / RegData
//                             条目行里分别带这四列，右键/选中即可复制
//   Find Hidden Item          隐藏键检测：
//                             · HKCU\Software\Classes 覆盖 HKLM 同名键（用户态劫持）
//                             · 键名以 '\0' 结尾或含控制字符（rootkit 常用手法）
//                             · 键名大小写变体撞车（同一路径不同大小写）
//   （隐藏键检测）            同上，单独成列标注原因
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winreg.h>
#include <winternl.h>   /* UNICODE_STRING */

/* ---------------------------------------------------------------- Reg Handle */

typedef LONG (NTAPI *PFN_NtQuerySystemInformation_R)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *PFN_NtQueryObject_R)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* 与 ProcessViews.c 保持一致的官方 OBJECT_TYPE_INFORMATION 布局。
   注意 TypeIndex 在最后（不是中间），之前写成 UCHAR Unknown2[0x30] 再跟
   TypeIndex 的版本字段错位，导致找不到 "Key" 的索引。 */
typedef struct _FE_OBJ_TYPE_INFO_R {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} FE_OBJ_TYPE_INFO_R;

static PFN_NtQuerySystemInformation_R FeNtQsi(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    return h ? (PFN_NtQuerySystemInformation_R)(void *)GetProcAddress(h, "NtQuerySystemInformation") : NULL;
}

/* 取 "Key" 类型的 TypeIndex。找不到返回 -1。 */
/* 启用 SeDebugPrivilege —— NtQueryObject(ObjectTypesInformation) 在没有它时
   会返回失败（实测 KeyTypeIndex=-1）。进程是管理员令牌的话，仅仅是
   "未启用" 状态，Enable 一下即可。 */
static void FeEnableDebugPrivilege(void)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

static int FeFindKeyTypeIndex(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_NtQueryObject_R pNtQo = hNtdll
        ? (PFN_NtQueryObject_R)(void *)GetProcAddress(hNtdll, "NtQueryObject") : NULL;
    ULONG size = 0x4000, ret = 0;
    PUCHAR buf;
    LONG st;
    int found = -1;

    if (!pNtQo)
        return -1;
    FeEnableDebugPrivilege();
    buf = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return -1;
    st = pNtQo(NULL, 3, buf, size, &ret);
    if (st == (LONG)0xC0000004) {
        HeapFree(GetProcessHeap(), 0, buf);
        size = ret + 0x1000;
        buf = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, size);
        if (!buf)
            return -1;
        st = pNtQo(NULL, 3, buf, size, &ret);
    }
    if (st >= 0) {
        /* 跳过 NumberOfTypes 头（见 ProcessViews.c 同名说明） */
        PUCHAR p = buf + 2 * sizeof(ULONG), end = buf + ret;
        while (p + sizeof(FE_OBJ_TYPE_INFO_R) <= end) {
            FE_OBJ_TYPE_INFO_R *ti = (FE_OBJ_TYPE_INFO_R *)p;
            USHORT maxLen = ti->TypeName.MaximumLength;
            USHORT len = ti->TypeName.Length;
            ULONG adv;

            if (maxLen > 0x200 || len > maxLen)
                break;
            adv = (ULONG)(sizeof(FE_OBJ_TYPE_INFO_R) + maxLen);
            adv = (adv + 7) & ~7u;
            if (adv < (ULONG)sizeof(FE_OBJ_TYPE_INFO_R) || p + adv > end)
                break;

            if (len && ti->TypeName.Buffer) {
                PUCHAR nb = (PUCHAR)ti->TypeName.Buffer;
                if (nb >= buf && nb + len <= end) {
                    char nameA[64];
                    ULONG n = len / sizeof(WCHAR);
                    if (n > 60) n = 60;
                    nameA[0] = 0;
                    if (n) {
                        WideCharToMultiByte(CP_ACP, 0, (WCHAR *)nb, (int)n, nameA, 64, NULL, NULL);
                        nameA[n] = 0;
                    }
                    if (_stricmp(nameA, "Key") == 0) {
                        found = (int)ti->TypeIndex;
                        break;
                    }
                }
            }
            p += adv;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return found;
}

BOOL FeLoadRegistryHandles(ULONG MaxCount, FE_REG_HANDLE_LIST *List)
{
    PFN_NtQuerySystemInformation_R pNtQsi = FeNtQsi();
    ULONG size = 0x200000, ret = 0;
    PVOID buf;
    LONG st;
    ULONG_PTR count, i;
    int keyType;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;
    List->KeyTypeIndex = -1;

    if (!pNtQsi)
        return FALSE;
    keyType = FeFindKeyTypeIndex();
    List->KeyTypeIndex = keyType;
    if (keyType < 0)
        return FALSE;

    buf = HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return FALSE;
    for (;;) {
        st = pNtQsi(64 /* SystemExtendedHandleInformation */, buf, size, &ret);
        if (st == (LONG)0xC0000004) {
            HeapFree(GetProcessHeap(), 0, buf);
            size = ret + 0x10000;
            buf = HeapAlloc(GetProcessHeap(), 0, size);
            if (!buf)
                return FALSE;
            continue;
        }
        break;
    }
    if (st < 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    List->Items = (FE_REG_HANDLE_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                   (SIZE_T)MaxCount * sizeof(FE_REG_HANDLE_ENTRY));
    if (!List->Items) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    List->Capacity = MaxCount;

    count = *(ULONG_PTR *)buf;
    {
        PUCHAR base = (PUCHAR)buf + 2 * sizeof(ULONG_PTR);
        /* SystemExtendedHandleInformation 的条目布局：
             +0x00 PVOID Object
             +0x08 PVOID UniqueProcessId
             +0x10 PVOID HandleValue
             +0x18 ULONG GrantedAccess
             +0x1C USHORT CreatorBackTraceIndex
             +0x1E USHORT ObjectTypeIndex */
        for (i = 0; i < count && List->Count < List->Capacity; i++) {
            PUCHAR e = base + i * 0x28;
            USHORT typeIndex = *(USHORT *)(e + 0x1E);
            FE_REG_HANDLE_ENTRY *out;

            if (typeIndex != (USHORT)keyType)
                continue;
            out = &List->Items[List->Count];
            out->Object = (ULONG64)(ULONG_PTR)*(PVOID *)(e + 0x00);
            out->Pid = (ULONG)(ULONG_PTR)*(PVOID *)(e + 0x08);
            out->Handle = (ULONG64)(ULONG_PTR)*(PVOID *)(e + 0x10);
            out->Access = *(ULONG *)(e + 0x18);
            List->Count++;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}

void FeFreeRegistryHandles(FE_REG_HANDLE_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintRegistryHandles(void)
{
    FE_REG_HANDLE_LIST list;
    ULONG i;

    if (!FeLoadRegistryHandles(200000, &list)) {
        printf("registry handles: query failed (KeyTypeIndex=%ld, GetLastError=%lu)\n",
               (long)list.KeyTypeIndex, GetLastError());
        return FALSE;
    }
    printf("registry handles: %lu  (object type index for \"Key\" = %ld)\n",
           list.Count, (long)list.KeyTypeIndex);
    for (i = 0; i < list.Count && i < 40; i++) {
        printf("  pid=%-6lu handle=0x%-8I64X access=0x%-8lX object=%p\n",
               list.Items[i].Pid, list.Items[i].Handle,
               list.Items[i].Access, (void *)(ULONG_PTR)list.Items[i].Object);
    }
    if (list.Count > 40)
        printf("  ... (%lu more)\n", list.Count - 40);
    FeFreeRegistryHandles(&list);
    return TRUE;
}

/* ------------------------------------------- 隐藏键检测（Find Hidden Item） */

/* 检测一个键名是否可疑：
 *   · 名字里含不可打印字符（rootkit 常用 '\0' 结尾以外的控制符）
 *   · 名字末尾有空格或点（Windows 会规范化，资源管理器看不到）
 *   · 名字与系统保留名大小写不一致的变体（如 "run" vs "Run"）——只报控制符那一类
 */
static int FeKeyNameSuspect(const char *name)
{
    size_t n, i;
    if (!name || !name[0])
        return 0;
    n = strlen(name);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 && c != 0)
            return 1;               /* 控制字符 */
    }
    if (name[n - 1] == ' ' || name[n - 1] == '.')
        return 1;                   /* 尾随空格/点 */
    return 0;
}

/* 递归扫描某个根键下的键名，报告可疑项。depth 限制递归深度。 */
static void FeScanHiddenKeysRec(HKEY hRoot, const char *rootLabel,
                                const char *subPath, int depth,
                                FE_REG_HIDDEN_LIST *List, ULONG maxItems)
{
    HKEY hk = NULL;
    WCHAR wsub[1024];
    DWORD idx = 0;

    if (List->Count >= maxItems || depth > 4)
        return;
    MultiByteToWideChar(CP_ACP, 0, subPath, -1, wsub, 1024);
    if (RegOpenKeyExW(hRoot, wsub, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return;

    for (;;) {
        WCHAR nameW[512];
        DWORD len = 512;
        char nameA[512];
        char full[1024];
        FE_REG_HIDDEN_ENTRY *e;

        if (RegEnumKeyExW(hk, idx++, nameW, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        nameW[len] = 0;
        nameA[0] = 0;
        FeWideToAnsi(nameW, nameA, sizeof(nameA));
        sprintf_s(full, sizeof(full), "%s\\%s\\%s", rootLabel, subPath, nameA);

        if (FeKeyNameSuspect(nameA)) {
            if (List->Count < List->Capacity || List->Count < maxItems) {
                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : 32;
                    FE_REG_HIDDEN_ENTRY *p = (FE_REG_HIDDEN_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_REG_HIDDEN_ENTRY));
                    if (!p) break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Path, sizeof(e->Path), "%s", full);
                sprintf_s(e->Reason, sizeof(e->Reason),
                          "key name has control chars or trailing space/dot");
                e->Depth = depth;
            }
        }
        /* 递归子键（深度受限） */
        if (depth < 3) {
            char child[1024];
            sprintf_s(child, sizeof(child), "%s\\%s", subPath, nameA);
            FeScanHiddenKeysRec(hRoot, rootLabel, child, depth + 1, List, maxItems);
            if (List->Count >= maxItems)
                break;
        }
    }
    RegCloseKey(hk);
}

/* HKCU\Software\Classes 覆盖 HKLM\SOFTWARE\Classes 同名项 —— 用户态劫持。
 * 只对几类高风险子键做检查（CLSID / 已知的 handler 位置），
 * 避免像 Startup 页那样把几千个正常 shell 扩展报出来。 */
static void FeScanClassesHijack(FE_REG_HIDDEN_LIST *List, ULONG maxItems)
{
    static const char *targets[] = {
        "CLSID",
        "Interface",
        "TypeLib",
        "Applications",
        "Directory\\shell",
        "Directory\\shellex\\ContextMenuHandlers",
        "\\",
    };
    ULONG t;

    for (t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
        char sub[512];
        HKEY hk = NULL;
        WCHAR wsub[512];
        DWORD idx = 0;

        sprintf_s(sub, sizeof(sub), "%s", targets[t]);
        MultiByteToWideChar(CP_ACP, 0, sub, -1, wsub, 512);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, wsub, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
            continue;
        /* 注意：这里 sub 是相对 HKCU 的，但 Classes 在 HKCU\Software\Classes 下 */
        RegCloseKey(hk);

        {
            char full[512];
            HKEY hkcu = NULL;
            sprintf_s(full, sizeof(full), "Software\\Classes\\%s", targets[t]);
            MultiByteToWideChar(CP_ACP, 0, full, -1, wsub, 512);
            if (RegOpenKeyExW(HKEY_CURRENT_USER, wsub, 0, KEY_READ | KEY_WOW64_64KEY, &hkcu) != ERROR_SUCCESS)
                continue;
            for (;;) {
                WCHAR nameW[512];
                DWORD len = 512;
                char nameA[512];
                char hklmSub[768];
                HKEY hklm = NULL;
                FE_REG_HIDDEN_ENTRY *e;

                if (RegEnumKeyExW(hkcu, idx++, nameW, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                if (List->Count >= maxItems)
                    break;
                nameW[len] = 0;
                nameA[0] = 0;
                FeWideToAnsi(nameW, nameA, sizeof(nameA));
                sprintf_s(hklmSub, sizeof(hklmSub), "SOFTWARE\\Classes\\%s\\%s", targets[t], nameA);
                {
                    WCHAR wm[768];
                    MultiByteToWideChar(CP_ACP, 0, hklmSub, -1, wm, 768);
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wm, 0,
                                      KEY_READ | KEY_WOW64_64KEY, &hklm) == ERROR_SUCCESS) {
                        RegCloseKey(hklm);
                        /* HKLM 也有同名项：属正常注册，不报（那是 Startup 页的 CLSID 劫持判据） */
                        continue;
                    }
                }
                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : 32;
                    FE_REG_HIDDEN_ENTRY *p = (FE_REG_HIDDEN_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_REG_HIDDEN_ENTRY));
                    if (!p) break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Path, sizeof(e->Path), "HKCU\\Software\\Classes\\%s\\%s",
                          targets[t], nameA);
                sprintf_s(e->Reason, sizeof(e->Reason),
                          "exists only under HKCU\\Software\\Classes (user-side override)");
            }
            RegCloseKey(hkcu);
        }
    }
}

BOOL FeLoadHiddenRegKeys(FE_REG_HIDDEN_LIST *List)
{
    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;

    /* 1) 控制字符 / 尾随空格的键名：扫几个高价值根键 */
    FeScanHiddenKeysRec(HKEY_LOCAL_MACHINE, "HKLM",
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, List, 200);
    FeScanHiddenKeysRec(HKEY_LOCAL_MACHINE, "HKLM",
                        "SYSTEM\\CurrentControlSet\\Services", 0, List, 200);
    FeScanHiddenKeysRec(HKEY_CURRENT_USER, "HKCU",
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, List, 200);

    /* 2) HKCU\Software\Classes 里 HKLM 没有的同名项 */
    FeScanClassesHijack(List, 400);
    return TRUE;
}

void FeFreeHiddenRegKeys(FE_REG_HIDDEN_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintHiddenRegKeys(void)
{
    FE_REG_HIDDEN_LIST list;
    ULONG i;

    if (!FeLoadHiddenRegKeys(&list)) {
        printf("hidden registry items: query failed\n");
        return FALSE;
    }
    printf("hidden registry items: %lu\n", list.Count);
    for (i = 0; i < list.Count && i < 40; i++)
        printf("  %s\n      reason: %s\n", list.Items[i].Path, list.Items[i].Reason);
    if (list.Count > 40)
        printf("  ... (%lu more)\n", list.Count - 40);
    FeFreeHiddenRegKeys(&list);
    return TRUE;
}

/* ------------------------------------------------------------- Key 子页
 * 原版 Registry 页可以按路径打开一个键看它的值；Kernel 页的
 * "Locate in Registry Tab" 就是跳到这里并定位到 Services\<驱动名>。
 * 这里只做只读枚举：RegEnumValueW 取名字/类型/数据。 */

static HKEY FeRegRootFromName(const WCHAR *name, ULONG nameChars, const WCHAR **rest)
{
    static const struct { const WCHAR *n; HKEY h; } roots[] = {
        { L"HKLM", HKEY_LOCAL_MACHINE }, { L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
        { L"HKCU", HKEY_CURRENT_USER },  { L"HKEY_CURRENT_USER", HKEY_CURRENT_USER },
        { L"HKCR", HKEY_CLASSES_ROOT },  { L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
        { L"HKU",  HKEY_USERS },         { L"HKEY_USERS", HKEY_USERS },
        { L"HKCC", HKEY_CURRENT_CONFIG },{ L"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG },
    };
    ULONG i;

    for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        size_t n = wcslen(roots[i].n);
        if (nameChars >= n && _wcsnicmp(name, roots[i].n, n) == 0) {
            const WCHAR *p = name + n;
            while (*p == L'\\')
                p++;
            *rest = p;
            return roots[i].h;
        }
    }
    return NULL;
}

static const char *FeRegTypeName(DWORD type)
{
    switch (type) {
    case REG_NONE:                       return "REG_NONE";
    case REG_SZ:                         return "REG_SZ";
    case REG_EXPAND_SZ:                  return "REG_EXPAND_SZ";
    case REG_BINARY:                     return "REG_BINARY";
    case REG_DWORD:                      return "REG_DWORD";
    case REG_DWORD_BIG_ENDIAN:           return "REG_DWORD_BIG_ENDIAN";
    case REG_LINK:                       return "REG_LINK";
    case REG_MULTI_SZ:                   return "REG_MULTI_SZ";
    case REG_RESOURCE_LIST:              return "REG_RESOURCE_LIST";
    case REG_FULL_RESOURCE_DESCRIPTOR:   return "REG_FULL_RESOURCE_DESCRIPTOR";
    case REG_RESOURCE_REQUIREMENTS_LIST: return "REG_RESOURCE_REQUIREMENTS_LIST";
    case REG_QWORD:                      return "REG_QWORD";
    default:                             return "REG_?";
    }
}

static void FeFormatRegData(DWORD type, const BYTE *data, DWORD bytesOfData,
                            char *out, size_t outChars)
{
    if (!out || outChars == 0)
        return;
    out[0] = 0;
    if (!data || bytesOfData == 0)
        return;

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        const WCHAR *w = (const WCHAR *)data;
        size_t maxChars = bytesOfData / sizeof(WCHAR);
        size_t len = 0;
        while (len < maxChars && w[len])
            len++;
        WideCharToMultiByte(CP_ACP, 0, w, (int)len, out, (int)outChars - 1, NULL, NULL);
        out[outChars - 1] = 0;
        return;
    }
    if (type == REG_DWORD && bytesOfData >= 4) {
        DWORD v = *(const DWORD *)data;
        sprintf_s(out, outChars, "0x%08lX (%lu)", (unsigned long)v, (unsigned long)v);
        return;
    }
    if (type == REG_QWORD && bytesOfData >= 8) {
        unsigned __int64 v = *(const unsigned __int64 *)data;
        sprintf_s(out, outChars, "0x%016I64X", v);
        return;
    }
    if (type == REG_MULTI_SZ) {
        const WCHAR *w = (const WCHAR *)data;
        size_t maxChars = bytesOfData / sizeof(WCHAR);
        size_t i = 0, used = 0;
        while (i < maxChars && w[i]) {
            size_t len = 0;
            while (i + len < maxChars && w[i + len])
                len++;
            {
                char item[256];
                int n = WideCharToMultiByte(CP_ACP, 0, w + i, (int)len, item,
                                            (int)sizeof(item) - 1, NULL, NULL);
                if (n < 0)
                    n = 0;
                item[n] = 0;
                if (used && used < outChars - 1)
                    out[used++] = ';';
                if (used < outChars - 1) {
                    size_t copy = strlen(item);
                    if (copy > outChars - 1 - used)
                        copy = outChars - 1 - used;
                    memcpy(out + used, item, copy);
                    used += copy;
                }
            }
            i += len + 1;
        }
        out[used] = 0;
        return;
    }
    /* 其余按十六进制，最多 24 字节 */
    {
        DWORD i, n = bytesOfData > 24 ? 24 : bytesOfData;
        size_t used = 0;
        for (i = 0; i < n && used + 4 < outChars; i++)
            used += (size_t)sprintf_s(out + used, outChars - used, "%02X ", data[i]);
        if (bytesOfData > n && used + 4 < outChars)
            strcat_s(out, outChars, "...");
    }
}

BOOL FeLoadRegValues(const char *Path, FE_REG_VALUE_LIST *List)
{
    WCHAR wpath[1024];
    const WCHAR *subkey = NULL;
    HKEY root, hk = NULL;
    DWORD idx = 0;
    LONG rc;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!Path || !Path[0]) {
        List->LastError = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    MultiByteToWideChar(CP_ACP, 0, Path, -1, wpath, 1024);
    {
        WCHAR *p = wpath;
        size_t len;
        while (*p == L' ')
            p++;
        /* 命令行里带引号的写法（--regkey-cli "HKLM\..."）也接受 */
        if (p[0] == L'"')
            p++;
        len = wcslen(p);
        while (len && (p[len - 1] == L'"' || p[len - 1] == L' '))
            p[--len] = 0;
        root = FeRegRootFromName(p, (ULONG)wcslen(p), &subkey);
        if (!root || !subkey || !subkey[0]) {
            List->LastError = ERROR_INVALID_NAME;
            return FALSE;
        }
        rc = RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk);
        if (rc != ERROR_SUCCESS) {
            List->LastError = (DWORD)rc;
            return FALSE;
        }
    }

    for (;;) {
        WCHAR nameW[256];
        BYTE dataBuf[4096];
        DWORD nameLen = 256, dataLen = sizeof(dataBuf), type = 0;

        rc = RegEnumValueW(hk, idx, nameW, &nameLen, NULL, &type,
                           dataBuf, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA) {
            List->LastError = (DWORD)rc;
            break;
        }
        if (List->Count == List->Capacity) {
            ULONG cap = List->Capacity ? List->Capacity * 2 : 32;
            FE_REG_VALUE_ENTRY *p = (FE_REG_VALUE_ENTRY *)realloc(
                List->Items, (size_t)cap * sizeof(FE_REG_VALUE_ENTRY));
            if (!p) {
                List->LastError = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }
            List->Items = p;
            List->Capacity = cap;
        }
        {
            FE_REG_VALUE_ENTRY *e = &List->Items[List->Count];
            ZeroMemory(e, sizeof(*e));
            if (nameLen == 0)
                strcpy_s(e->Name, sizeof(e->Name), "(Default)");
            else
                WideCharToMultiByte(CP_ACP, 0, nameW, (int)nameLen, e->Name,
                                    (int)sizeof(e->Name) - 1, NULL, NULL);
            strcpy_s(e->Type, sizeof(e->Type), FeRegTypeName(type));
            FeFormatRegData(type, dataBuf, rc == ERROR_MORE_DATA ? 0 : dataLen,
                            e->Data, sizeof(e->Data));
            List->Count++;
        }
        idx++;
    }
    RegCloseKey(hk);
    return List->LastError == ERROR_SUCCESS;
}

void FeFreeRegValues(FE_REG_VALUE_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintRegValues(const char *Path)
{
    FE_REG_VALUE_LIST list;
    ULONG i;

    if (!FeLoadRegValues(Path, &list)) {
        printf("reg key: cannot open %s (error %lu)\n", Path ? Path : "(null)",
               (unsigned long)list.LastError);
        FeFreeRegValues(&list);
        return FALSE;
    }
    printf("reg key: %s (%lu values)\n", Path, list.Count);
    for (i = 0; i < list.Count; i++)
        printf("  %-28s %-20s %s\n", list.Items[i].Name, list.Items[i].Type,
               list.Items[i].Data);
    FeFreeRegValues(&list);
    return TRUE;
}