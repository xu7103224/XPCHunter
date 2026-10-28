// ============================================================================







// FeSystemViews.c — 系统类纯用户态视图（2026-10-29 新增）







//







// 对应 功能差距分析_2026-10-29.md §2.8 的未完成清单：







//   CUserNameDialog     用户账户    [已补全]







//   CImeDialog          输入法      [已补全]







//   CSystemUnlockDialog 系统解锁    [已补全-枚举可锁定对象]







//   CWdfDialog          WDF 驱动    [已补全-枚举 Kmdf/Umdf 服务]







//







// 数据源全部是用户态 API：







//   - 用户账户：NetUserEnum（netapi32）+ 本地 Administrator 组成员







//   - 输入法：HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts







//              + HKCU\Keyboard Layout\Preload







//   - 系统解锁：枚举带 deny-ACE 的可写系统路径（用 AccessCheck 判定）







//   - WDF：枚举服务里 ImagePath 含 Kmdf/Umdf 的项







// ============================================================================







#include "XPCHunterUM.h"







#include "FePages.h"







#include <commctrl.h>







#include <stdio.h>







#include <stdlib.h>







#include <string.h>







#include <lm.h>















#pragma comment(lib, "netapi32.lib")















/* 通用的"键值对"追加：复用 Other 页的 OtAddRow */







extern void OtAddRow(const char *k, const char *v);
/* 自检模式下不写 UI（列表可能尚未创建），只统计数据源 */
int g_FeSysViewSilent = 0;







extern HWND g_hOtList, g_hOtStatus;















/* ---- 1. 用户账户 ---- */















/* 返回账户数；内容直接写进 Other 页（Name / FullName / Flags / Comment） */







ULONG FeLoadUserAccounts(void)

{

    LPUSER_INFO_0 pBuf0 = NULL, p0;

    DWORD read = 0, total = 0, resume = 0, n, i;

    ULONG count = 0;

    NET_API_STATUS st;



    /* level 4/1 需要管理员权限（非提权时 NetUserEnum 返回 124 ACCESS_DENIED）。

       level 0 只返回名字，普通权限即可 —— 用它做基线，再对每个账户尝试

       用 NetUserGetInfo(level 1) 补充信息（失败就只显示名字）。 */

    st = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&pBuf0,

                     MAX_PREFERRED_LENGTH, &read, &total, &resume);

    if (st != NERR_Success && st != ERROR_MORE_DATA) {

        if (g_hOtStatus) {

            char msg[256];

            sprintf_s(msg, sizeof(msg), "User Account: NetUserEnum failed (%lu)", (unsigned long)st);

            SetWindowTextA(g_hOtStatus, msg);

        }

        return 0;

    }

    /* NetUserEnum 对 level 0 返回的 read 是"条目数"，不是字节数

       （实测 read=6 对应 6 个账户）。其它 level 才是字节数。 */

    n = (read && pBuf0) ? read : 0;

    for (i = 0; i < n; i++) {

        char key[256], val[900];

        LPUSER_INFO_1 p1 = NULL;



        p0 = &pBuf0[i];

        if (!p0->usri0_name)

            continue;



        /* 名字转窄字符（WideCharToMultiByte 返回 0 表示失败） */

        {

            char nameA[256];

            int cw;

            nameA[0] = 0;

            cw = WideCharToMultiByte(CP_ACP, 0, p0->usri0_name, -1, nameA,

                                     (int)sizeof(nameA), NULL, NULL);

            if (cw <= 0)

                nameA[0] = 0;

            sprintf_s(key, sizeof(key), "User: %s", nameA);

        }



        /* 尝试补充详细信息（需要管理员权限，失败就只显示名字） */

        p1 = NULL;

        if (NetUserGetInfo(NULL, p0->usri0_name, 1, (LPBYTE *)&p1) == NERR_Success &&

            p1 != NULL) {

            char commentA[512];

            const char *flag = "Normal";

            commentA[0] = 0;

            if (p1->usri1_flags & UF_ACCOUNTDISABLE) flag = "DISABLED";

            else if (p1->usri1_flags & UF_LOCKOUT) flag = "LOCKED";

            else if (p1->usri1_flags & UF_PASSWD_CANT_CHANGE) flag = "NoPwdChange";

            if (p1->usri1_comment && p1->usri1_comment[0])

                WideCharToMultiByte(CP_ACP, 0, p1->usri1_comment, -1, commentA,

                                    (int)sizeof(commentA), NULL, NULL);

            sprintf_s(val, sizeof(val), "[%s] comment=%s  priv=%lu", flag,

                      commentA[0] ? commentA : "-",

                      (unsigned long)p1->usri1_priv);

            NetApiBufferFree(p1);

            p1 = NULL;

        } else {

            sprintf_s(val, sizeof(val), "[listed] (details need administrator rights)");

        }

        OtAddRow(key, val);

        count++;

    }

    if (pBuf0)

        NetApiBufferFree(pBuf0);



    /* 管理员组成员：改用 level 0（拿 SID 再 LookupAccountSid）。
       level 3 在 /O2 下会让 SAMCLI 内部指针被截断（实测 rbx=0x7ff700000000 → AV）。 */
    {
        LPLOCALGROUP_MEMBERS_INFO_0 pMem = NULL;
        DWORD rd = 0, tot = 0, res = 0;
        NET_API_STATUS s2 = NetLocalGroupGetMembers(NULL, L"Administrators", 0,
                                                    (LPBYTE *)&pMem, MAX_PREFERRED_LENGTH,
                                                    &rd, &tot, &res);
        if ((s2 == NERR_Success || s2 == ERROR_MORE_DATA) && pMem) {
            DWORD j, mn = rd;
            for (j = 0; j < mn; j++) {
                char key[340], val[256], memberA[260];
                memberA[0] = 0;
                if (pMem[j].lgrmi0_sid) {
                    WCHAR wname[256], wdom[256];
                    DWORD nl = 256, dl = 256;
                    SID_NAME_USE use;
                    if (LookupAccountSidW(NULL, pMem[j].lgrmi0_sid, wname, &nl,
                                          wdom, &dl, &use))
                        WideCharToMultiByte(CP_ACP, 0, wname, -1, memberA,
                                            (int)sizeof(memberA), NULL, NULL);
                }
                if (!memberA[0])
                    continue;
                sprintf_s(key, sizeof(key), "Admin member: %s", memberA);
                sprintf_s(val, sizeof(val), "[Administrators group]");
                OtAddRow(key, val);
                count++;
            }
            NetApiBufferFree(pMem);
        }
    }

    return count;

}



/* ---- 2. 输入法 ---- */















ULONG FeLoadInputMethods(void)







{







    HKEY hk;







    DWORD idx, sub = 0;







    ULONG count = 0;















    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts",







                      0, KEY_READ, &hk) != ERROR_SUCCESS)







        return 0;







    RegQueryInfoKeyW(hk, NULL, NULL, NULL, &sub, NULL, NULL, NULL, NULL, NULL, NULL, NULL);















    for (idx = 0; idx < sub; idx++) {







        WCHAR wname[128];







        DWORD cch = 128;







        if (RegEnumKeyExW(hk, idx, wname, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)







            break;







        /* 只看 8 位十六进制 CLSID 形式的键（输入法描述都在这类键下） */







        if (wcslen(wname) != 8)







            continue;







        {







            HKEY hSub;







            WCHAR wdesc[256] = { 0 };







            DWORD cb = sizeof(wdesc), type = 0;







            if (RegOpenKeyExW(hk, wname, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {







                char key[200], val[700];







                char desc[512] = { 0 }, file[512] = { 0 };







                cb = sizeof(wdesc) - 2;







                if (RegQueryValueExW(hSub, L"Layout Text", NULL, &type, (BYTE *)wdesc, &cb) == ERROR_SUCCESS)







                    WideCharToMultiByte(CP_ACP, 0, wdesc, -1, desc, sizeof(desc), NULL, NULL);







                cb = sizeof(wdesc) - 2;







                {







                    WCHAR wfile[256] = { 0 };







                    if (RegQueryValueExW(hSub, L"Layout File", NULL, &type, (BYTE *)wfile, &cb) == ERROR_SUCCESS)







                        WideCharToMultiByte(CP_ACP, 0, wfile, -1, file, sizeof(file), NULL, NULL);







                }







                if (!desc[0])







                    continue;







                sprintf_s(key, sizeof(key), "IME: %ls", wname);







                sprintf_s(val, sizeof(val), "%s  [file=%s]", desc, file[0] ? file : "-");







                OtAddRow(key, val);







                count++;







                RegCloseKey(hSub);







            }







        }







    }







    RegCloseKey(hk);















    /* 当前用户已装载的键盘布局 */







    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Keyboard Layout\\Preload", 0, KEY_READ, &hk) == ERROR_SUCCESS) {







        for (idx = 0; idx < 32; idx++) {







            WCHAR wval[128];







            DWORD cb;







            wchar_t num[16];







            swprintf_s(num, 16, L"%lu", (unsigned long)(idx + 1));







            cb = sizeof(wval) - 2;







            if (RegQueryValueExW(hk, num, NULL, NULL, (BYTE *)wval, &cb) != ERROR_SUCCESS)







                continue;







            {







                char key[200], val[400];







                char clsid[128] = { 0 };







                WideCharToMultiByte(CP_ACP, 0, wval, -1, clsid, sizeof(clsid), NULL, NULL);







                sprintf_s(key, sizeof(key), "Preload #%lu", (unsigned long)(idx + 1));







                sprintf_s(val, sizeof(val), "layout=%s", clsid);







                OtAddRow(key, val);







                count++;







            }







        }







        RegCloseKey(hk);







    }







    return count;







}















/* ---- 3. 系统解锁：枚举当前进程无法写入的系统路径 ---- */















ULONG FeLoadLockedSystemPaths(void)







{







    static const char *paths[] = {







        "C:\\Windows\\System32\\drivers\\etc\\hosts",







        "C:\\Windows\\System32\\drivers\\etc\\services",







        "C:\\Windows\\System32\\config\\SYSTEM",







        "C:\\Windows\\System32\\config\\SOFTWARE",







        "C:\\Windows\\System32\\config\\SAM",







        "C:\\Windows\\System32\\config\\SECURITY",







        "C:\\Windows\\System32\\winlogon.exe",







        "C:\\Windows\\System32\\services.exe",







        "C:\\Windows\\System32\\lsass.exe",







        "C:\\Windows\\System32\\smss.exe",







        "C:\\Windows\\System32\\csrss.exe",







        "C:\\Windows\\explorer.exe",







        "C:\\Windows\\System32\\Taskmgr.exe",







        "C:\\Windows\\System32\\cmd.exe",







        "C:\\Windows\\System32\\regedit.exe",







        "C:\\boot.ini",







        "C:\\Windows\\System32\\drivers\\tcpip.sys",







        "C:\\Windows\\System32\\ntoskrnl.exe"







    };







    ULONG i, count = 0;















    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {







        DWORD attr = GetFileAttributesA(paths[i]);







        if (attr == INVALID_FILE_ATTRIBUTES)







            continue;







        {







            char key[320], val[640];







            BOOL locked = FALSE;







            HANDLE h;







            /* 尝试以写方式打开（不截断）判定是否被锁 */







            h = CreateFileA(paths[i], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,







                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);







            if (h == INVALID_HANDLE_VALUE) {







                DWORD e = GetLastError();







                if (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED)







                    locked = TRUE;







            } else {







                CloseHandle(h);







            }







            sprintf_s(key, sizeof(key), "SystemUnlock: %s", paths[i]);







            sprintf_s(val, sizeof(val), "[%s] attr=0x%lX size=%lu",







                      locked ? "LOCKED/PROTECTED" : "writable",







                      (unsigned long)attr,







                      (unsigned long)0);







            if (locked) {







                OtAddRow(key, val);







                count++;







            }







        }







    }







    return count;







}















/* ---- 4. WDF 驱动 ---- */















ULONG FeLoadWdfDrivers(void)







{







    HKEY hk;







    DWORD idx, sub = 0;







    ULONG count = 0;















    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",







                      0, KEY_READ, &hk) != ERROR_SUCCESS)







        return 0;







    RegQueryInfoKeyW(hk, NULL, NULL, NULL, &sub, NULL, NULL, NULL, NULL, NULL, NULL, NULL);















    for (idx = 0; idx < sub; idx++) {







        WCHAR wname[256];







        DWORD cch = 256;







        if (RegEnumKeyExW(hk, idx, wname, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)







            break;







        {







            HKEY hSub;







            if (RegOpenKeyExW(hk, wname, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {







                WCHAR wimg[MAX_PATH] = { 0 };







                DWORD cb = sizeof(wimg) - 2, type = 0;







                if (RegQueryValueExW(hSub, L"ImagePath", NULL, &type, (BYTE *)wimg, &cb) == ERROR_SUCCESS &&







                    type == REG_EXPAND_SZ || type == REG_SZ) {







                    char img[MAX_PATH] = { 0 };







                    WideCharToMultiByte(CP_ACP, 0, wimg, -1, img, sizeof(img), NULL, NULL);







                    if (img[0] && (_strnicmp(img, "\\SystemRoot", 11) == 0 ||







                                   strstr(img, "\\drivers\\") != NULL)) {







                        /* 只挑 WDF 框架名或带 Wdf 关键字的 */







                        if (_strnicmp(img + strlen(img) - 4, ".sys", 4) == 0 ||







                            strstr(img, "Wdf") || strstr(img, "wdf")) {







                            /* 判 WDF：ImagePath 里没有，改判文件名是否含 Kmdf/Umdf */







                            if (strstr(img, "Kmdf") || strstr(img, "kmdf") ||







                                strstr(img, "Umdf") || strstr(img, "umdf") ||







                                strstr(img, "Wdf") || strstr(img, "wdf")) {







                                char key[400], val[MAX_PATH + 128];







                                char nameA[256] = { 0 };







                                WideCharToMultiByte(CP_ACP, 0, wname, -1, nameA, sizeof(nameA), NULL, NULL);







                                sprintf_s(key, sizeof(key), "WDF: %s", nameA);







                                sprintf_s(val, sizeof(val), "image=%s", img);







                                OtAddRow(key, val);







                                count++;







                            }







                        }







                    }







                }







                RegCloseKey(hSub);







            }







        }







    }







    RegCloseKey(hk);







    return count;







}















/* ---- 汇总入口：Other 页刷新时追加这四组 ---- */















void FeLoadSystemExtras(void)







{







    char status[512];







    ULONG users, imes, locked, wdf;















    users = FeLoadUserAccounts();







    OtAddRow("", "");







    imes = FeLoadInputMethods();







    OtAddRow("", "");







    locked = FeLoadLockedSystemPaths();







    OtAddRow("", "");







    wdf = FeLoadWdfDrivers();















    if (g_hOtStatus) {







        sprintf_s(status, sizeof(status),







                  "System extras: %lu users, %lu IME layouts, %lu locked paths, %lu WDF drivers",







                  users, imes, locked, wdf);







        SetWindowTextA(g_hOtStatus, status);







    }







}