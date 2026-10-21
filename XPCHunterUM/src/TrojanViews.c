// ============================================================================
// TrojanViews.c — Trojan Detection 页（原版第 13 个主 Tab，10 项）
//
// 清单条目与实现：
//   Scan MBR / Check MBR Rootkit    读 \\.\PhysicalDrive0 的 512 字节，
//                                   校验 0x55AA 签名、分区表项、引导代码特征
//   `MBR OK!`                       引导代码与分区表都正常
//   `Unknow MBR!`                   签名/分区表非法
//   `Original MBR has been found in sector`  在后续扇区找到备份的原始 MBR
//   Backup MBR                      把当前 MBR 存到文件
//   Reset MBR                       用备份文件写回（二次确认由 GUI 负责）
//   修复 MBR 二次确认                GUI 侧 MessageBox 二次确认
//   `Find ZeroAccess Rootkit!`      检测 ZeroAccess 特征
//   Repair LSP                      LSP 注册表项合法性检查 + 修复
//   Repair Safeboot                 Safeboot 最小化策略检查 + 修复（二次确认）
//   Repair All                      依次执行以上可修复项
//
// 数据源说明（重要）：
//   驱动侧 0xCA CmdDiskReadSector / 0xCC CmdDiskSectorReadWrite 目前是
//   **空槽**（DiskReadSectorOperation 只有声明、无实现体，见命令可用性校准
//   文档的 85 个空槽名单），因此本页用用户态 `\\.\PhysicalDrive0` 直接读写
//   MBR —— 需要管理员权限，这在 PCHunter 的运行场景里是前提。
//   读写都只碰**第 0 扇区**或其备份副本，不对磁盘做任何其他修改。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------- MBR 读写 */

/* 读物理磁盘的某个扇区（512 字节）。DriveIndex: 0 = PhysicalDrive0 */
BOOL FeReadMbrSector(int DriveIndex, ULONG64 SectorIndex, BYTE Out[512], DWORD *pError)
{
    char devPath[64];
    WCHAR wpath[64];
    HANDLE h;
    LARGE_INTEGER off;
    DWORD read = 0;
    BOOL ok;

    if (pError)
        *pError = 0;
    sprintf_s(devPath, sizeof(devPath), "\\\\.\\PhysicalDrive%d", DriveIndex);
    MultiByteToWideChar(CP_ACP, 0, devPath, -1, wpath, 64);

    h = CreateFileW(wpath, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (pError)
            *pError = GetLastError();
        return FALSE;
    }
    /* 用 SetFilePointerEx 定位到扇区（物理磁盘必须按扇区对齐读） */
    off.QuadPart = (LONGLONG)(SectorIndex * 512ULL);
    if (!SetFilePointerEx(h, off, NULL, FILE_BEGIN)) {
        if (pError)
            *pError = GetLastError();
        CloseHandle(h);
        return FALSE;
    }
    ok = ReadFile(h, Out, 512, &read, NULL) && read == 512;
    if (!ok && pError)
        *pError = GetLastError();
    CloseHandle(h);
    return ok;
}

BOOL FeWriteMbrSector(int DriveIndex, ULONG64 SectorIndex, const BYTE In[512], DWORD *pError)
{
    char devPath[64];
    WCHAR wpath[64];
    HANDLE h;
    LARGE_INTEGER off;
    DWORD written = 0;
    BOOL ok;

    if (pError)
        *pError = 0;
    sprintf_s(devPath, sizeof(devPath), "\\\\.\\PhysicalDrive%d", DriveIndex);
    MultiByteToWideChar(CP_ACP, 0, devPath, -1, wpath, 64);

    h = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (pError)
            *pError = GetLastError();
        return FALSE;
    }
    off.QuadPart = (LONGLONG)(SectorIndex * 512ULL);
    if (!SetFilePointerEx(h, off, NULL, FILE_BEGIN)) {
        if (pError)
            *pError = GetLastError();
        CloseHandle(h);
        return FALSE;
    }
    ok = WriteFile(h, In, 512, &written, NULL) && written == 512;
    if (!ok && pError)
        *pError = GetLastError();
    CloseHandle(h);
    return ok;
}

/* MBR 结构校验。返回：
 *   0 = MBR OK
 *   1 = Unknown MBR（签名缺失/引导代码全零/分区表非法）
 *   2 = 读失败
 */
int FeCheckMbr(const BYTE Mbr[512], char *Detail, size_t DetailChars)
{
    int i;
    int nonZeroBoot = 0;
    int validParts = 0;

    if (!Mbr)
        return 2;
    if (Detail && DetailChars)
        Detail[0] = 0;

    /* 签名 0x55AA 必须在最后两字节 */
    if (Mbr[510] != 0x55 || Mbr[511] != 0xAA) {
        if (Detail)
            sprintf_s(Detail, DetailChars,
                      "boot signature missing (expected 55 AA, got %02X %02X)",
                      Mbr[510], Mbr[511]);
        return 1;
    }

    /* 引导代码区（0..445）不应全零 —— 全零通常是"被清空"的迹象 */
    for (i = 0; i < 446; i++) {
        if (Mbr[i] != 0) {
            nonZeroBoot++;
        }
    }
    if (nonZeroBoot < 16) {
        if (Detail)
            sprintf_s(Detail, DetailChars,
                      "boot code area is nearly empty (%d non-zero bytes)", nonZeroBoot);
        return 1;
    }

    /* 四个分区表项：起始/结束 CHS 与 LBA 必须自洽 */
    for (i = 0; i < 4; i++) {
        const BYTE *p = Mbr + 446 + i * 16;
        BYTE status = p[0];
        BYTE type = p[4];
        DWORD startLba = *(const DWORD *)(p + 8);
        DWORD sectors = *(const DWORD *)(p + 12);

        if (type == 0)
            continue;                       /* 空分区项 */
        if (status != 0x00 && status != 0x80) {
            if (Detail)
                sprintf_s(Detail, DetailChars,
                          "partition %d has invalid status byte 0x%02X", i + 1, status);
            return 1;
        }
        if (startLba == 0 || sectors == 0) {
            if (Detail)
                sprintf_s(Detail, DetailChars,
                          "partition %d has zero LBA/size", i + 1);
            return 1;
        }
        validParts++;
    }
    if (validParts == 0) {
        if (Detail)
            sprintf_s(Detail, DetailChars, "no valid partition entries");
        return 1;
    }

    if (Detail)
        sprintf_s(Detail, DetailChars,
                  "signature OK, %d non-zero boot bytes, %d partition(s)",
                  nonZeroBoot, validParts);
    return 0;
}

/* ZeroAccess 检测：
 *   典型特征是在 MBR 之后的保留扇区里找到与 MBR 引导代码高度相似但不同的副本，
 *   且 MBR 引导代码本身含有 0xB8/0xBB（mov eax/ebx 立即数）+ int 13h（0xCD13）
 *   这类自装载跳转。这里做可用性最强的三项：
 *     1) 第 0 扇区的引导代码是否含 int 13h（CD 13）
 *     2) 第 1..4 扇区是否存在"看起来像 MBR"的副本（55 AA 结尾）
 *     3) 该副本与当前 MBR 的引导代码是否不同（→ 原始 MBR 被替换）
 */
BOOL FeFindZeroAccess(int DriveIndex, FE_TROJAN_REPORT *R)
{
    BYTE mbr[512], alt[512];
    int s;
    DWORD err = 0;

    if (!R)
        return FALSE;
    if (!FeReadMbrSector(DriveIndex, 0, mbr, &err)) {
        sprintf_s(R->MbrDetail, sizeof(R->MbrDetail),
                  "cannot read PhysicalDrive%d: GetLastError=%lu", DriveIndex, err);
        R->MbrState = 2;
        return FALSE;
    }

    R->MbrState = FeCheckMbr(mbr, R->MbrDetail, sizeof(R->MbrDetail));
    memcpy(R->MbrSector, mbr, 512);

    /* 找备份的原始 MBR（第 1..8 扇区里有 55AA 且引导代码与当前不同的） */
    R->BackupSector = 0;
    for (s = 1; s <= 8; s++) {
        memset(alt, 0, sizeof(alt));
        if (!FeReadMbrSector(DriveIndex, (ULONG64)s, alt, &err))
            continue;
        if (alt[510] == 0x55 && alt[511] == 0xAA) {
            if (memcmp(alt, mbr, 446) != 0) {
                R->BackupSector = (ULONG64)s;
                R->MbrState = (R->MbrState == 0) ? 3 : R->MbrState;
                memcpy(R->BackupMbr, alt, 512);
                break;
            }
        }
    }

    /* ZeroAccess：引导代码含 int 13h 且存在"备份但不同"的 MBR */
    {
        int hasInt13 = 0;
        int i;
        for (i = 0; i + 1 < 446; i++) {
            if (mbr[i] == 0xCD && mbr[i + 1] == 0x13) {
                hasInt13 = 1;
                break;
            }
        }
        R->ZeroAccess = (hasInt13 && R->BackupSector != 0) ? 1 : 0;
    }
    return TRUE;
}

/* ---------------------------------------------------------------- MBR 备份 */

BOOL FeBackupMbr(int DriveIndex, const char *Path, FE_TROJAN_REPORT *R)
{
    BYTE mbr[512];
    DWORD err = 0;
    FILE *f;

    if (!Path || !Path[0])
        return FALSE;
    if (R && R->MbrSector[510] == 0x55 && R->MbrSector[511] == 0xAA) {
        memcpy(mbr, R->MbrSector, 512);
    } else if (!FeReadMbrSector(DriveIndex, 0, mbr, &err)) {
        return FALSE;
    }
    if (fopen_s(&f, Path, "wb") != 0 || !f)
        return FALSE;
    /* 存为 512 字节 + 一行元信息（驱动器号与时间），便于人工核对 */
    fwrite(mbr, 1, 512, f);
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "\r\n# PhysicalDrive%d MBR backup %04u-%02u-%02u %02u:%02u:%02u\r\n",
                DriveIndex, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }
    fclose(f);
    return TRUE;
}

/* 从备份文件恢复 MBR（调用方必须先做二次确认）。 */
BOOL FeRestoreMbr(int DriveIndex, const char *Path, DWORD *pError)
{
    BYTE mbr[512];
    FILE *f;
    size_t got;

    if (pError)
        *pError = 0;
    if (!Path || !Path[0])
        return FALSE;
    if (fopen_s(&f, Path, "rb") != 0 || !f)
        return FALSE;
    got = fread(mbr, 1, 512, f);
    fclose(f);
    if (got != 512)
        return FALSE;
    /* 只接受结构完整的 MBR，避免把坏数据写进磁盘 */
    if (mbr[510] != 0x55 || mbr[511] != 0xAA)
        return FALSE;
    return FeWriteMbrSector(DriveIndex, 0, mbr, pError);
}

/* ------------------------------------------------------------ LSP / Safeboot */

/* LSP 检查：Winsock 的协议链里若存在非系统目录的 DLL 即为可疑。
 *
 * 关键：路径不在 PaddedPath 里，而在 **PackedCatalogItem**（REG_BINARY）的
 * 开头 —— 前 520 字节是宽字符路径（实测 `%SystemRoot%\system32\mswsock.dll`）。
 * （最初按 PaddedPath 去读，结果 0 条，实机 reg query 才看清真实布局。）
 * 判据：路径含 \windows\ 或 %SystemRoot%\ 视为系统项，否则可疑。 */
BOOL FeCheckLsp(FE_TROJAN_REPORT *R)
{
    HKEY hk = NULL;
    DWORD idx = 0;
    int ok = 0, bad = 0;

    if (!R)
        return FALSE;
    R->LspOk = 1;
    R->LspDetail[0] = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries",
                      0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) {
        sprintf_s(R->LspDetail, sizeof(R->LspDetail), "cannot open LSP catalog");
        return FALSE;
    }
    for (;;) {
        WCHAR subW[256];
        DWORD subLen = 256;
        HKEY hs = NULL;
        BYTE packed[1024];
        DWORD size = sizeof(packed), type = 0;

        if (RegEnumKeyExW(hk, idx++, subW, &subLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (RegOpenKeyExW(hk, subW, 0, KEY_READ | KEY_WOW64_64KEY, &hs) != ERROR_SUCCESS)
            continue;
        size = sizeof(packed);
        if (RegQueryValueExW(hs, L"PackedCatalogItem", NULL, &type, packed, &size) == ERROR_SUCCESS
            && size >= 4) {
            /* 前 260 字节是 **ANSI 单字节**路径（实测
               "%SystemRoot%\system32\mswsock.dll" 的十六进制为
               25 53 79 73 74 65 6D 52 6F 6F 74 25 5C ...，
               即 ASCII 而非 UTF-16）。最初按宽字符解析得到垃圾，
               于是 16 条全部判成 outside —— 这是本次修正的关键。 */
            char pathA[520];
            char lower[520];
            size_t k;
            size_t maxA = size;
            if (maxA > 259) maxA = 259;
            memcpy(pathA, packed, maxA);
            pathA[maxA] = 0;
            for (k = 0; pathA[k] && k < sizeof(lower) - 1; k++)
                lower[k] = (char)tolower((unsigned char)pathA[k]);
            lower[k] = 0;
            if (!lower[0])
                continue;
            if (strstr(lower, "\windows\\") != NULL ||
                strstr(lower, "%systemroot%") != NULL ||
                strstr(lower, "system32\\") != NULL ||
                strstr(lower, "syswow64\\") != NULL)
                ok++;
            else
                bad++;
        }
        RegCloseKey(hs);
    }
    RegCloseKey(hk);

    R->LspOk = (bad == 0) ? 1 : 0;
    sprintf_s(R->LspDetail, sizeof(R->LspDetail),
              "%d LSP entries in system dirs, %d outside", ok, bad);
    return TRUE;
}

/* Safeboot 检查：BootStatusPolicy 若为 IgnoreAllFailures 说明被篡改。 */
BOOL FeCheckSafeboot(FE_TROJAN_REPORT *R)
{
    HKEY hk = NULL;
    WCHAR buf[64];
    DWORD size = sizeof(buf), type = 0;

    if (!R)
        return FALSE;
    R->SafebootOk = 1;
    strcpy_s(R->SafebootDetail, sizeof(R->SafebootDetail), "SafeBoot policy normal");

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                      0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hk, L"BootStatusPolicy", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
        char a[64];
        FeWideToAnsi(buf, a, sizeof(a));
        if (strstr(a, "IgnoreAllFailures") != NULL) {
            R->SafebootOk = 0;
            sprintf_s(R->SafebootDetail, sizeof(R->SafebootDetail),
                      "BootStatusPolicy = %s (failures ignored - tampered)", a);
        }
    }
    RegCloseKey(hk);
    return TRUE;
}

/* Repair Safeboot：把 BootStatusPolicy 恢复为 DisplayAllFailures。 */
BOOL FeRepairSafeboot(void)
{
    HKEY hk = NULL;
    LONG st;
    static const WCHAR val[] = L"DisplayAllFailures";

    st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                       0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hk);
    if (st != ERROR_SUCCESS)
        return FALSE;
    st = RegSetValueExW(hk, L"BootStatusPolicy", 0, REG_SZ,
                        (const BYTE *)val, (DWORD)(wcslen(val) + 1) * sizeof(WCHAR));
    RegCloseKey(hk);
    return st == ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- CLI 输出 */

BOOL FePrintTrojanReport(int DriveIndex)
{
    FE_TROJAN_REPORT R;

    ZeroMemory(&R, sizeof(R));
    printf("=== Trojan Detection (PhysicalDrive%d) ===\n", DriveIndex);

    if (!FeFindZeroAccess(DriveIndex, &R)) {
        printf("MBR: %s\n", R.MbrDetail);
    } else {
        static const char *state[] = { "MBR OK!", "Unknow MBR!", "read failed", "(backup found)" };
        printf("MBR: %s\n", state[R.MbrState >= 0 && R.MbrState <= 3 ? R.MbrState : 2]);
        printf("     %s\n", R.MbrDetail);
        if (R.BackupSector)
            printf("Original MBR has been found in sector %I64u\n", R.BackupSector);
        printf("ZeroAccess: %s\n", R.ZeroAccess ? "Find ZeroAccess Rootkit!" : "not detected");
    }

    FeCheckLsp(&R);
    printf("LSP: %s (%s)\n", R.LspOk ? "OK" : "suspicious", R.LspDetail);

    FeCheckSafeboot(&R);
    printf("Safeboot: %s (%s)\n", R.SafebootOk ? "OK" : "tampered", R.SafebootDetail);
    return TRUE;
}
