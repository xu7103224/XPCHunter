// ============================================================================
// ExaminationViews.c — Examination 页（原版第 10 个主 Tab，7 项）
//
// 这是"体检报告"——把各页的检测结果汇总成一份可导出的报告。
// 清单条目与实现：
//   Generate examination report        生成报告（逐项体检，进度可中断）
//   Terminate generating               中断（检查 g_ExamCancel 标志）
//   Export examination report          SaveFileDialog 导出为 .txt
//   Examination detail                 明细列表（每项：严重度 / 标题 / 说明）
//   Computer Examination               入口按钮
//   `PC Hunter Professional --- Computer Examination Report`  报告头
//   Examination Date / Examination Items                      报告头字段
//
// 体检项全部来自已落地页的数据层，不重复实现：
//   · 隐藏注册表键        FeLoadHiddenRegKeys
//   · 隐藏服务            FeLoadServices（HiddenCount）
//   · 可疑自启动          FeLoadStartupItems（CLSID 覆盖）
//   · 被占用/待删文件     FeLoadDirectory（对几个关键目录抽样）
//   · 内核模块数量        FeLoadKernelModules
//   · 注册表 Key 句柄数   FeLoadRegistryHandles
//   · 系统版本            FeLoadOsInfo
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 中断标志：GUI 里点 Terminate 时置 1，体检循环每步检查。 */
static volatile LONG g_ExamCancel = 0;

void FeExamCancel(void)
{
    InterlockedExchange(&g_ExamCancel, 1);
}

void FeExamResetCancel(void)
{
    InterlockedExchange(&g_ExamCancel, 0);
}

int FeExamIsCancelled(void)
{
    return InterlockedCompareExchange(&g_ExamCancel, 0, 0) != 0;
}

static void FeExamAdd(FE_EXAM_RESULT *R, int Severity, const char *Title, const char *Detail)
{
    FE_EXAM_ITEM *e;

    if (!R || R->Count >= FE_EXAM_MAX_ITEMS)
        return;
    if (R->Count >= R->Capacity) {
        ULONG newCap = R->Capacity ? R->Capacity * 2 : 32;
        FE_EXAM_ITEM *p = (FE_EXAM_ITEM *)realloc(R->Items, newCap * sizeof(FE_EXAM_ITEM));
        if (!p)
            return;
        R->Items = p;
        R->Capacity = newCap;
    }
    e = &R->Items[R->Count++];
    ZeroMemory(e, sizeof(*e));
    e->Severity = Severity;
    sprintf_s(e->Title, sizeof(e->Title), "%s", Title ? Title : "");
    sprintf_s(e->Detail, sizeof(e->Detail), "%s", Detail ? Detail : "");
    switch (Severity) {
    case 0: R->InfoCount++; break;
    case 1: R->WarnCount++; break;
    default: R->RiskCount++; break;
    }
}

/* 执行体检。progress/total 允许为 NULL（CLI 用）。 */
BOOL FeRunExamination(FE_EXAM_RESULT *R)
{
    if (!R)
        return FALSE;
    R->Count = 0;
    R->Capacity = 0;
    R->Items = NULL;
    R->RiskCount = 0;
    R->WarnCount = 0;
    R->InfoCount = 0;
    R->Cancelled = 0;

    FeExamResetCancel();

    /* 报告头：日期 */
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        sprintf_s(R->Date, sizeof(R->Date), "%04u-%02u-%02u %02u:%02u:%02u",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }

    /* 1) 系统版本 */
    if (!FeExamIsCancelled()) {
        FE_OS_INFO os;
        if (FeLoadOsInfo(&os))
            FeExamAdd(R, 0, "Operating system",
                      os.MarketName[0] ? os.MarketName : os.VersionString);
        else
            FeExamAdd(R, 1, "Operating system", "RtlGetVersion failed");
    }

    /* 2) 隐藏注册表键 */
    if (!FeExamIsCancelled()) {
        FE_REG_HIDDEN_LIST hl;
        if (FeLoadHiddenRegKeys(&hl)) {
            char detail[256];
            sprintf_s(detail, sizeof(detail), "%lu suspicious registry keys", hl.Count);
            FeExamAdd(R, hl.Count ? 2 : 0, "Hidden registry keys", detail);
            FeFreeHiddenRegKeys(&hl);
        }
    }

    /* 3) 隐藏服务 */
    if (!FeExamIsCancelled()) {
        FE_SERVICE_LIST sv;
        if (FeLoadServices(&sv)) {
            char detail[256];
            sprintf_s(detail, sizeof(detail),
                      "%lu services, %lu hidden (registry keys: %lu)",
                      sv.Count, sv.HiddenCount, sv.RegServiceCount);
            FeExamAdd(R, sv.HiddenCount ? 1 : 0, "Services", detail);
            FeFreeServices(&sv);
        }
    }

    /* 4) 自启动项 */
    if (!FeExamIsCancelled()) {
        FE_STARTUP_LIST su;
        if (FeLoadStartupItems(&su)) {
            ULONG clsid = 0, i;
            char detail[256];
            for (i = 0; i < su.Count; i++) {
                if (strstr(su.Items[i].Location, "CLSID") != NULL)
                    clsid++;
            }
            sprintf_s(detail, sizeof(detail),
                      "%lu startup entries, %lu CLSID overrides", su.Count, clsid);
            FeExamAdd(R, clsid ? 1 : 0, "Startup entries", detail);
            FeFreeStartupItems(&su);
        }
    }

    /* 5) 内核模块 */
    if (!FeExamIsCancelled()) {
        FE_KMODULE_LIST km;
        if (FeLoadKernelModules(&km)) {
            char detail[128];
            sprintf_s(detail, sizeof(detail), "%lu kernel modules loaded", km.Count);
            FeExamAdd(R, 0, "Kernel modules", detail);
            FeFreeKernelModules(&km);
        }
    }

    /* 6) 注册表 Key 句柄 */
    if (!FeExamIsCancelled()) {
        FE_REG_HANDLE_LIST rh;
        if (FeLoadRegistryHandles(200000, &rh)) {
            char detail[128];
            sprintf_s(detail, sizeof(detail), "%lu open Key handles system-wide", rh.Count);
            FeExamAdd(R, 0, "Registry handles", detail);
            FeFreeRegistryHandles(&rh);
        }
    }

    /* 7) 系统关键目录里的可疑文件（抽样 2 个目录） */
    if (!FeExamIsCancelled()) {
        static const char *dirs[] = { "C:\\Windows\\System32", "C:\\Windows\\Temp" };
        ULONG d;
        for (d = 0; d < 2 && !FeExamIsCancelled(); d++) {
            FE_FILE_LIST fl;
            if (FeLoadDirectory(dirs[d], &fl)) {
                if (fl.HiddenCount || fl.PendingCount) {
                    char detail[256];
                    sprintf_s(detail, sizeof(detail),
                              "%s: %lu suspect names, %lu delete-pending",
                              dirs[d], fl.HiddenCount, fl.PendingCount);
                    FeExamAdd(R, fl.HiddenCount ? 2 : 1, "Suspicious files", detail);
                } else {
                    char detail[160];
                    sprintf_s(detail, sizeof(detail), "%s: %lu files, clean",
                              dirs[d], fl.Count);
                    FeExamAdd(R, 0, "File scan", detail);
                }
                FeFreeDirectory(&fl);
            }
        }
    }

    R->Cancelled = FeExamIsCancelled() ? 1 : 0;
    return TRUE;
}

void FeFreeExamination(FE_EXAM_RESULT *R)
{
    if (!R)
        return;
    free(R->Items);
    R->Items = NULL;
    R->Count = 0;
    R->Capacity = 0;
}

/* 导出报告为文本（原版 Export examination report）。 */
BOOL FeExportExamination(const FE_EXAM_RESULT *R, const char *Path)
{
    FILE *f;
    ULONG i;

    if (!R || !Path || !Path[0])
        return FALSE;
    if (fopen_s(&f, Path, "wb") != 0 || !f)
        return FALSE;

    fprintf(f, "PC Hunter Professional --- Computer Examination Report\r\n");
    fprintf(f, "=====================================================\r\n");
    fprintf(f, "Examination Date: %s\r\n", R->Date);
    fprintf(f, "Examination Items: %lu (risk: %lu, warn: %lu, info: %lu)\r\n",
            R->Count, R->RiskCount, R->WarnCount, R->InfoCount);
    if (R->Cancelled)
        fprintf(f, "NOTE: examination was terminated by user.\r\n");
    fprintf(f, "\r\n");

    for (i = 0; i < R->Count; i++) {
        const char *sev = R->Items[i].Severity == 0 ? "INFO" :
                          R->Items[i].Severity == 1 ? "WARN" : "RISK";
        fprintf(f, "[%s] %s\r\n      %s\r\n", sev, R->Items[i].Title, R->Items[i].Detail);
    }
    fprintf(f, "\r\n--- end of report ---\r\n");
    fclose(f);
    return TRUE;
}

BOOL FePrintExamination(void)
{
    FE_EXAM_RESULT R;
    ULONG i;

    if (!FeRunExamination(&R)) {
        printf("examination: failed\n");
        return FALSE;
    }
    printf("PC Hunter Professional --- Computer Examination Report\n");
    printf("Examination Date: %s\n", R.Date);
    printf("Examination Items: %lu (risk: %lu, warn: %lu, info: %lu)\n",
           R.Count, R.RiskCount, R.WarnCount, R.InfoCount);
    for (i = 0; i < R.Count; i++) {
        const char *sev = R.Items[i].Severity == 0 ? "INFO" :
                          R.Items[i].Severity == 1 ? "WARN" : "RISK";
        printf("  [%s] %-28s %s\n", sev, R.Items[i].Title, R.Items[i].Detail);
    }
    FeFreeExamination(&R);
    return TRUE;
}