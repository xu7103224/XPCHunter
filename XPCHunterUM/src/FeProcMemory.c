// ============================================================================
// FeProcMemory.c — 进程内存分配 / 保护修改（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.1 的
//   CAllocateMemoryDialog       分配内存      [已补全]
//   CModifyMemoryProtectDialog  改内存保护     [已补全]
//
// 【为什么这两项不需要驱动】
//   VirtualAllocEx / VirtualVirtualProtectEx 对被授权目标进程完全有效：
//   只要本进程对目标有 PROCESS_VM_OPERATION 权限（管理员对普通进程都有），
//   系统就直接完成分配/改保护。
//   驱动只在"目标进程带保护、用户态 OpenProcess 被拒"时才必需——
//   那种情况会明确报 ERROR_ACCESS_DENIED，不会静默失败。
//
//   这与原版的行为一致：原版的这两个对话框在有权限时也是直接调
//   VirtualAllocEx/VirtualProtectEx。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 解析十六进制输入（允许 0x 前缀与空格） */
static ULONG64 MemParseHex(const char *Text)
{
    if (!Text)
        return 0;
    while (*Text == ' ' || *Text == '\t')
        Text++;
    if (Text[0] == '0' && (Text[1] == 'x' || Text[1] == 'X'))
        return _strtoui64(Text + 2, NULL, 16);
    return _strtoui64(Text, NULL, 16);
}

/* 保护属性名 -> 常量 */
static DWORD MemParseProtect(const char *Text, BOOL *Ok)
{
    DWORD p = 0;

    if (Ok) *Ok = TRUE;
    if (!Text || !Text[0]) { if (Ok) *Ok = FALSE; return 0; }
    if (_stricmp(Text, "RWX") == 0)       return PAGE_EXECUTE_READWRITE;
    if (_stricmp(Text, "RX") == 0)        return PAGE_EXECUTE_READ;
    if (_stricmp(Text, "X") == 0)         return PAGE_EXECUTE;
    if (_stricmp(Text, "RW") == 0)        return PAGE_READWRITE;
    if (_stricmp(Text, "R") == 0)         return PAGE_READONLY;
    if (_stricmp(Text, "W") == 0)         return PAGE_READWRITE;
    if (_stricmp(Text, "NONE") == 0)      return PAGE_NOACCESS;
    if (_stricmp(Text, "ERC") == 0)       return PAGE_EXECUTE_READ;
    /* 也接受数字 */
    p = (DWORD)MemParseHex(Text);
    if (p == 0 && Ok) *Ok = FALSE;
    return p;
}

static const char *MemProtectName(DWORD Prot)
{
    if (Prot & PAGE_GUARD)          return "guard";
    switch (Prot & 0xFF) {
    case PAGE_EXECUTE:              return "X   (PAGE_EXECUTE)";
    case PAGE_EXECUTE_READ:         return "RX  (PAGE_EXECUTE_READ)";
    case PAGE_EXECUTE_READWRITE:    return "RWX (PAGE_EXECUTE_READWRITE)";
    case PAGE_EXECUTE_WRITECOPY:    return "RWC (PAGE_EXECUTE_WRITECOPY)";
    case PAGE_READONLY:             return "R   (PAGE_READONLY)";
    case PAGE_READWRITE:            return "RW  (PAGE_READWRITE)";
    case PAGE_WRITECOPY:            return "WC  (PAGE_WRITECOPY)";
    case PAGE_NOACCESS:             return "--- (PAGE_NOACCESS)";
    default:                        return "(unknown)";
    }
}

/* 分配内存：地址 + 大小 + 保护属性
   Addr 输入 "0" 表示由系统选地址。 */
BOOL FeProcAllocateMemory(HWND Owner, ULONG Pid, ULONG64 *OutAddr, ULONG64 *OutSize)
{
    HANDLE hProc;
    char addrBuf[64], sizeBuf[64], protBuf[32];
    ULONG64 addr, size;
    DWORD prot, oldProt = 0;
    BOOL protOk = TRUE;
    void *result;
    char msg[900];

    if (OutAddr) *OutAddr = 0;
    if (OutSize) *OutSize = 0;
    if (!Pid)
        return FALSE;

    strcpy_s(addrBuf, sizeof(addrBuf), "0");
    strcpy_s(sizeBuf, sizeof(sizeBuf), "0x1000");
    strcpy_s(protBuf, sizeof(protBuf), "RWX");

    if (!DoPromptText(Owner, "Allocate Memory - Address",
                      "Base address (0 = let system choose):", addrBuf, sizeof(addrBuf)))
        return FALSE;
    if (!DoPromptText(Owner, "Allocate Memory - Size",
                      "Size in hex (e.g. 0x1000):", sizeBuf, sizeof(sizeBuf)))
        return FALSE;
    if (!DoPromptText(Owner, "Allocate Memory - Protection",
                      "Protection (RWX / RX / X / RW / R / NONE):", protBuf, sizeof(protBuf)))
        return FALSE;

    addr = MemParseHex(addrBuf);
    size = MemParseHex(sizeBuf);
    prot = MemParseProtect(protBuf, &protOk);

    if (!protOk || size == 0) {
        SetWindowTextA(g_hProcStatus,
                       "Allocate Memory: invalid size or protection string");
        return FALSE;
    }
    if (!FeConfirmDanger(Owner, "Allocate Memory", protBuf))
        return FALSE;

    hProc = OpenProcess(PROCESS_VM_OPERATION, FALSE, Pid);
    if (!hProc) {
        sprintf_s(msg, sizeof(msg),
                  "Allocate Memory: OpenProcess failed (err=%lu). "
                  "Protected processes need a driver channel.",
                  GetLastError());
        SetWindowTextA(g_hProcStatus, msg);
        return FALSE;
    }

    result = VirtualAllocEx(hProc, (addr ? (void *)(ULONG_PTR)addr : NULL),
                            (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, prot);
    if (!result) {
        DWORD e = GetLastError();
        CloseHandle(hProc);
        sprintf_s(msg, sizeof(msg),
                  "Allocate Memory: VirtualAllocEx failed (err=%lu)%s", e,
                  e == ERROR_ACCESS_DENIED ? " - process is protected" : "");
        SetWindowTextA(g_hProcStatus, msg);
        return FALSE;
    }
    CloseHandle(hProc);

    if (OutAddr) *OutAddr = (ULONG64)(ULONG_PTR)result;
    if (OutSize) *OutSize = size;
    sprintf_s(msg, sizeof(msg),
              "Allocate Memory: OK  addr=%016I64X  size=0x%I64X  prot=%s  (pid %lu)",
              (ULONG64)(ULONG_PTR)result, size, MemProtectName(prot),
              (unsigned long)Pid);
    SetWindowTextA(g_hProcStatus, msg);
    (void)oldProt;
    return TRUE;
}

/* 改内存保护：地址 + 大小 + 新保护 */
BOOL FeProcModifyProtect(HWND Owner, ULONG Pid)
{
    HANDLE hProc;
    char addrBuf[64], sizeBuf[64], protBuf[32];
    ULONG64 addr, size;
    DWORD prot, oldProt = 0;
    BOOL protOk = TRUE;
    BOOL ok;
    char msg[900];
    MEMORY_BASIC_INFORMATION mbi;

    if (!Pid)
        return FALSE;

    strcpy_s(addrBuf, sizeof(addrBuf), "0");
    strcpy_s(sizeBuf, sizeof(sizeBuf), "0x1000");
    strcpy_s(protBuf, sizeof(protBuf), "RX");

    if (!DoPromptText(Owner, "Modify Memory Protect - Address",
                      "Base address (hex):", addrBuf, sizeof(addrBuf)))
        return FALSE;
    if (!DoPromptText(Owner, "Modify Memory Protect - Size",
                      "Size in hex:", sizeBuf, sizeof(sizeBuf)))
        return FALSE;
    if (!DoPromptText(Owner, "Modify Memory Protect - Protection",
                      "New protection (RWX / RX / X / RW / R / NONE):",
                      protBuf, sizeof(protBuf)))
        return FALSE;

    addr = MemParseHex(addrBuf);
    size = MemParseHex(sizeBuf);
    prot = MemParseProtect(protBuf, &protOk);
    if (!protOk || !addr || size == 0) {
        SetWindowTextA(g_hProcStatus,
                       "Modify Memory Protect: invalid address / size / protection");
        return FALSE;
    }

    hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                        FALSE, Pid);
    if (!hProc) {
        sprintf_s(msg, sizeof(msg),
                  "Modify Memory Protect: OpenProcess failed (err=%lu)",
                  GetLastError());
        SetWindowTextA(g_hProcStatus, msg);
        return FALSE;
    }

    /* 先查当前保护，便于回报 */
    {
        SIZE_T q = VirtualQueryEx(hProc, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi));
        if (q != sizeof(mbi)) {
            CloseHandle(hProc);
            SetWindowTextA(g_hProcStatus,
                           "Modify Memory Protect: address is not a valid region in target");
            return FALSE;
        }
        oldProt = mbi.Protect;
    }

    ok = VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)addr, (SIZE_T)size,
                          prot, &oldProt) != FALSE;
    {
        DWORD e = ok ? 0 : GetLastError();
        CloseHandle(hProc);
        if (ok) {
            sprintf_s(msg, sizeof(msg),
                      "Modify Memory Protect: OK  %016I64X  size=0x%I64X  %s -> %s",
                      addr, size, MemProtectName(oldProt), MemProtectName(prot));
        } else {
            sprintf_s(msg, sizeof(msg),
                      "Modify Memory Protect: VirtualProtectEx failed (err=%lu)", e);
        }
        SetWindowTextA(g_hProcStatus, msg);
    }
    return ok;
}

/* 释放已分配内存（原版 Allocate Memory 对话框的配套动作） */
BOOL FeProcFreeMemory(HWND Owner, ULONG Pid)
{
    HANDLE hProc;
    char addrBuf[64];
    ULONG64 addr;
    BOOL ok;
    char msg[900];

    if (!Pid)
        return FALSE;
    strcpy_s(addrBuf, sizeof(addrBuf), "0");
    if (!DoPromptText(Owner, "Free Memory", "Base address to free (hex):",
                      addrBuf, sizeof(addrBuf)))
        return FALSE;
    addr = MemParseHex(addrBuf);
    if (!addr)
        return FALSE;
    if (!FeConfirmDanger(Owner, "Free Memory", addrBuf))
        return FALSE;

    hProc = OpenProcess(PROCESS_VM_OPERATION, FALSE, Pid);
    if (!hProc) {
        sprintf_s(msg, sizeof(msg), "Free Memory: OpenProcess failed (err=%lu)",
                  GetLastError());
        SetWindowTextA(g_hProcStatus, msg);
        return FALSE;
    }
    ok = VirtualFreeEx(hProc, (LPVOID)(ULONG_PTR)addr, 0, MEM_RELEASE) != FALSE;
    {
        DWORD e = ok ? 0 : GetLastError();
        CloseHandle(hProc);
        if (ok)
            sprintf_s(msg, sizeof(msg), "Free Memory: OK  %016I64X released", addr);
        else
            sprintf_s(msg, sizeof(msg), "Free Memory: VirtualFreeEx failed (err=%lu)", e);
        SetWindowTextA(g_hProcStatus, msg);
    }
    return ok;
}