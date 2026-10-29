// ============================================================================
// FePages.h — 页面模块统一注册表（2026-10-28 由 frontend.c 拆分产出）
//   每个页面模块导出：控件句柄（extern）+ Create*/Refresh*/Op* 函数。
//   ShowPage（frontend.c）按主 Tab 编号调用对应 Fe<X>PageShow。
// ============================================================================
#ifndef XPCH_FEPAGES_H
#define XPCH_FEPAGES_H

#include "XPCHunterUM.h"
#include <commctrl.h>

/* commctrl.h 的 UNICODE 版展开成 W 通道，这里改走 ANSI；先 undef 消掉 C4005 */
#undef ListView_InsertColumn
#define ListView_InsertColumn(h, i, pc) FeInsertColumnA((h), (i), (pc))

#define IDC_CONNECT     1001
#define IDC_SCAN        1002
#define IDC_SEND        1003
#define IDC_CMD         1004
#define IDC_OUTSIZE     1005  /* not IDC_SIZE: winuser.h already defines IDC_SIZE */
#define IDC_LIST        1006
#define IDC_STATUS      1007
#define IDC_REFRESH     1008
#define IDC_PROCLIST    1009
#define IDC_PROCSTATUS  1010
#define IDC_TABS        1011
#define IDC_DETAIL      1012
#define IDC_KILL        1013
/* Kernel 页（现已收进主 Tab 容器） */
#define IDC_KERNEL      1014
#define IDC_KM_REFRESH  1020
#define IDC_KM_TABS     1021
#define IDC_KM_LIST     1022
#define IDC_KM_STATUS   1023
#define IDC_KM_KEXTRA   1028   /* Driver 页的"其他内核项"独立状态行 */
/* Driver 子页：只显示已加载 + 复制名/路径（原版右键菜单项） */
#define IDC_KM_ONLYLOADED 1024
#define IDC_KM_COPYNAME   1025
#define IDC_KM_COPYPATH   1026
#define IDC_KM_DRVOP      1027
#define IDC_KM_RESTORE    1066
#define IDC_KM_RESTOREALL 1067

/* Driver 子页操作（原版右键菜单 5 项；Locate in Registry Tab 走独立菜单项 4008） */
#define DRVOP_VERIFY      0
#define DRVOP_VERIFY_ALL  1
#define DRVOP_UNLOAD      2
#define DRVOP_DEL_FILE    3
#define DRVOP_DEL_FILE_REG 4
/* 14 个主 Tab 容器 */
#define IDC_MAIN_TABS   1030
#define IDC_PAGEHINT    1031
/* Startup Info 页 */
#define IDC_SU_REFRESH  1040
#define IDC_SU_LIST     1041
#define IDC_SU_STATUS   1042
#define IDC_SU_TABS     1043   /* 2026-10-29：Startup / Schedule Task 子 Tab */
/* Services 页 */
#define IDC_SV_REFRESH  1050
#define IDC_SV_LIST     1051
#define IDC_SV_STATUS   1052
/* Registry 页 */
#define IDC_RG_REFRESH  1060
#define IDC_RG_TABS     1061
#define IDC_RG_LIST     1062
#define IDC_RG_STATUS   1063
#define IDC_RG_PATH     1064
#define IDC_RG_GO       1065
#define IDC_RG_TREE     1066   /* 2026-10-29：Key 子页的树形导航 */
/* File 页 */
#define IDC_FL_DIR      1070
#define IDC_FL_GO       1071
#define IDC_FL_LIST     1072
#define IDC_FL_STATUS   1073
#define IDC_FL_DEL      1074
#define IDC_FL_VERIFY   1075
/* Other 页 */
#define IDC_OT_LIST     1080
#define IDC_OT_STATUS   1081
#define IDC_OT_PATH     1082
#define IDC_OT_VERIFY   1083
#define IDC_OT_QUERY    1084
/* Network 页（主 Tab 4） */
#define IDC_NW_TREE     1085
#define IDC_NW_LIST     1086
#define IDC_NW_STATUS   1087
/* Examination 页 */
#define IDC_EX_RUN      1090
#define IDC_EX_CANCEL   1091
#define IDC_EX_EXPORT   1092
#define IDC_EX_LIST     1093
#define IDC_EX_STATUS   1094
/* Fireeye 页 */
#define IDC_FE_PATH     1100
#define IDC_FE_ANALYSE  1101
#define IDC_FE_OPEN     1102
#define IDC_FE_RECORDS  1103
#define IDC_FE_CLEAR    1104
#define IDC_FE_LIST     1105
#define IDC_FE_STATUS   1106
/* Setting 页 */
#define IDC_ST_LIST     1110
#define IDC_ST_STATUS   1111
#define IDC_ST_APPLY    1112
#define IDC_ST_REFRESH  1113
#define IDC_ST_PROT_SSDT 1114
#define IDC_ST_PROT_SHADOW 1115
#define IDC_ST_TRAY     1116
/* Trojan Detection 页 */
#define IDC_TR_SCAN     1120
#define IDC_TR_BACKUP   1121
#define IDC_TR_RESTORE  1122
#define IDC_TR_REPAIR   1123
#define IDC_TR_LIST     1124
#define IDC_TR_STATUS   1125
/* Hooks 页（Ring0 = 主 Tab 2，Ring3 = 主 Tab 3） */
#define IDC_HK_REFRESH  1130
#define IDC_HK_LIST     1131
#define IDC_HK_STATUS   1132
/* Ring0 两项恢复操作（原版右键菜单项，这里做成按钮，便于实机验证） */
#define IDC_HK_RESTORE  1133
#define IDC_HK_CBTABLE  1134
/* 第二步增量：Process 页的 Auto Refresh 开关（1032 未被占用） */
#define IDC_PROC_AUTO   1032
/* 第二步增量2：Process 页的列过滤输入框 */
#define IDC_PROC_FILTER 1033
/* 第二步增量3：Process 页导出 CSV 按钮 */
#define IDC_PROC_EXPORT 1034

/* ---- 统一刷新模型：auto-refresh 共享定时器（frontend.c WM_TIMER 驱动；
   页面模块把本页刷新函数挂到 g_AutoRefFn，开关按钮各自实现） ---- */
#define FE_AUTOREF_TIMER_ID  0x0A01u
extern void (*g_AutoRefFn)(void);   /* 当前页的定时刷新入口；NULL = 未启用 */
extern BOOL g_ProcAutoOwnedTimer;   /* 定时器当前是否归 Process 页自管 */

/* 页面注册表：主 Tab 编号 -> 显隐/按需刷新入口（各页模块实现） */
typedef void (*FE_PAGE_SHOW_FN)(HWND hWnd, int page);

void FeProcPagePageShow(HWND hWnd, int page);   /* 主 Tab 0 (Process) */
void FeKernelPagePageShow(HWND hWnd, int page);   /* 主 Tab 1 (Kernel) */
void FeHookPagePageShow(HWND hWnd, int page);   /* 主 Tab 2 (Ring0) */
void FeHookPagePageShow(HWND hWnd, int page);   /* 主 Tab 3 (Ring3) */
void FeNetworkPagePageShow(HWND hWnd, int page);   /* 主 Tab 4 (Network) */
void FeRegistryPagePageShow(HWND hWnd, int page);   /* 主 Tab 5 (Registry) */
void FeStartupPagePageShow(HWND hWnd, int page);   /* 主 Tab 6 (Startup) */
void FeServicePagePageShow(HWND hWnd, int page);   /* 主 Tab 7 (Services) */
void FeFilePagePageShow(HWND hWnd, int page);   /* 主 Tab 8 (File) */
void FeExamPagePageShow(HWND hWnd, int page);   /* 主 Tab 9 (Exam) */
void FeSettingPagePageShow(HWND hWnd, int page);   /* 主 Tab 10 (Setting) */
void FeFireeyePagePageShow(HWND hWnd, int page);   /* 主 Tab 11 (Fireeye) */
void FeTrojanPagePageShow(HWND hWnd, int page);   /* 主 Tab 12 (Trojan) */
void FeOtherPagePageShow(HWND hWnd, int page);   /* 主 Tab 13 (Other) */

/* ---- FeExamPage.c ---- */
extern HWND g_hExList, g_hExStatus;
extern int g_ExamLoaded;
void ExSetText(HWND hList, int iItem, int iSub, const char *text);
void DoRefreshExamination(void);
void DoExportExamination(void);
void DoExaminationContextMenu(HWND hWnd, int X, int Y);
extern BOOL g_ExamHideSafe;
void DoExportExamination(void);

/* ---- FeFilePage.c ---- */
extern HWND g_hFlDir, g_hFlList, g_hFlStatus;
void FlSetText(HWND hList, int iItem, int iSub, const char *text);
void CreateFlColumns(HWND hList);
void DoRefreshFiles(void);

/* ---- FeFireeyePage.c ---- */
extern HWND g_hFePath, g_hFeList, g_hFeStatus;
extern int g_FeHasJob;
void FeSetText(HWND h, int iItem, int iSub, const char *text);
void DoFireeyeAnalyse(void);
void DoFireeyeRecords(void);

/* ---- FeHookPage.c ---- */
extern HWND g_hHkList, g_hHkStatus;
void HkSetText(HWND h, int iItem, int iSub, const char *text);
void DoRefreshHooks(void);
void DoHookContextMenu(HWND hWnd, int X, int Y);
extern BOOL g_HkOnlyHooks;
void DoRestoreOverHooks(void);
void DoRestoreCallbackTable(void);

/* ---- FeKernelPage.c ---- */
extern HWND g_hKmTabs, g_hKmList, g_hKmStatus, g_hKmKExtra;
extern int  g_KmTab;
extern int  g_KmOnlyLoaded;
void CreateKmColumns(HWND hList, int tab);
void KmSetText(HWND hList, int iItem, int iSub, const char *text);
void DoRefreshKernel(void);
void DoCopyKmColumn(int SubItem, const char *What);
BOOL KmSelectedDriverName(char *Out, size_t OutChars);
void DoDriverOp(int Op);
void DoModuleOp(int Op);
LRESULT CALLBACK PromptProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL DoPromptText(HWND Owner, const char *Title, const char *Prompt, char *Out, size_t OutChars);
void DoModuleSearch(int Op);
void DoModuleContextMenu(HWND hWnd, int X, int Y);
void DoLocateDriverInRegistry(void);
void DoDriverContextMenu(HWND hWnd, int X, int Y);

/* ---- FeNetworkPage.c ---- */
extern HWND g_hNwTree, g_hNwList, g_hNwStatus;
extern int  g_NwNode;
void CreateNwColumns(HWND hList, int node);
void NwAddRow(HWND hList, int row, const char *s0, const char *s1, const char *s2, const char *s3, const char *s4, const char *s5);
HTREEITEM NwInsertNode(HTREEITEM Parent, const char *Name, LPARAM Node);
HTREEITEM NwFindNode(HTREEITEM Parent, LPARAM Node);
void BuildNwTree(void);
const char *NwNodeName(int node);
void DoRefreshNetwork(void);
void NwRestoreTdi(void);
void NwSelectNode(int Node);

/* ---- FeOtherPage.c ---- */
extern HWND g_hOtList, g_hOtStatus, g_hOtPath;
void OtAddRow(const char *k, const char *v);
void DoRefreshOther(void);

/* ---- FeProcPage.c ---- */
extern HWND g_hList, g_hStatus, g_hCmd, g_hSize;
extern HWND g_hProc, g_hProcStatus, g_hTabs, g_hDetail;
extern int  g_DetailTab;
void CreateProcColumns(HWND h);
void DetailSetText(int row, int sub, const char *text);
void DetailAddRow(const char *c0, const char *c1, const char *c2, const char *c3);
void SetupDetailColumns(int tab);
void DoRefreshDetail(void);
void DoKillSelected(void);
void DoRefreshProcs(void);
void DoProcessOp(int Op);
void DoProcessContextMenu(HWND hWnd, int X, int Y);
ULONG64 DetailColumnQword(int Sel, int Sub);
BOOL DetailColumnText(int Sel, int Sub, char *Out, int OutChars);
/* 第二步增量：列头点击排序 + 定时自动刷新开关 */
void FeProcPageOnColumnClick(int col);
void FeProcPageToggleAuto(HWND hWnd);
/* 排序器状态（--selftest-sort-cli 在进程内直接驱动，见 CliMain.c） */
extern FE_PROCESS_LIST g_ProcCache;
extern unsigned char  *g_ProcAcc;
extern BOOL g_ProcCacheValid;
extern int  g_ProcSortCol;
extern int  g_ProcSortDesc;
int ProcCmp(const void *pa, const void *pb);
/* 第二步增量2：列过滤（空串 = 不过滤；任一拍中即保留） */
extern ULONG g_ProcShown;
extern char  g_ProcFilter[128];
void FeProcPageSetFilter(const char *filter);
/* 第二步增量3：CSV 导出（导出当前过滤+排序后的可见行） */
BOOL FeProcPageExportCsv(const char *Path, ULONG *OutRows);
void FeProcPageExport(void);
/* 第二步增量4：双击进程行下钻到当前子视图 */
BOOL FeProcPageDrillDown(void);
/* 第二步增量5：变更触发（指纹未变则不重绘） */
BOOL DoRefreshProcsIfChanged(void);
ULONG64 ProcComputeFingerprint(void);
BOOL ProcFilterMatch(const FE_PROCESS *it, unsigned char acc, const char *filter);

/* ---- FeRegistryPage.c ---- */
extern HWND g_hRgTabs, g_hRgList, g_hRgStatus, g_hRgTree;
extern int  g_RgTab;
extern char g_RgPath[512];
extern char g_RgCurKey[512];   /* Key 浏览子页的当前路径 */
extern int  g_RgKeyDepth;
void RgSetText(HWND hList, int iItem, int iSub, const char *text);
void CreateRgColumns(HWND hList, int tab);
void DoRefreshRegistry(void);
void DoRegistryContextMenu(HWND hWnd, int X, int Y);
/* 2026-10-29：Key 子页树形导航 */
void RgBuildRoots(void);
void RgTreeFreeAll(void);
void RgFillKeyViewPublic(const char *KeyPath);
void RgOnTreeExpanding(NMTREEVIEWA *nm);
void RgExpandTo(HWND hTree, HTREEITEM hItem);
void RgOnTreeSelChanged(void);

/* ---- FeSchedulePage.c（计划任务子页，原版 CScheduleTaskDialog） ---- */
extern HWND g_hSchList, g_hSchStatus;
extern ULONG g_SchCount;
void SchSetText(HWND hList, int iItem, int iSub, const char *text);
void CreateSchColumns(HWND hList);
void DoRefreshSchedule(void);
void DoScheduleContextMenu(HWND hWnd, int X, int Y);

/* ---- FeServicePage.c ---- */
extern HWND g_hSvList, g_hSvStatus;
void SvSetText(HWND hList, int iItem, int iSub, const char *text);
void CreateSvColumns(HWND hList);
void DoRefreshServices(void);
void DoServiceFireeye(int UseServiceDll);
BOOL SvGetSelectedEntry(FE_SERVICE_ENTRY *Out);
void DoServiceOp(int Op);
void DoServiceContextMenu(HWND hWnd, int X, int Y);

/* ---- FeSettingPage.c ---- */
extern HWND g_hStList, g_hStStatus;
extern int g_StObjReady;
void StSetText(HWND h, int iItem, int iSub, const char *text);
void DoRefreshSetting(void);
void DoApplyForbid(int Which);

/* ---- FeStartupPage.c ---- */
extern HWND g_hSuList, g_hSuStatus, g_hSuTabs;
extern int  g_SuTab;   /* 0=Startup Item 1=Schedule Task */
void SuSetText(HWND hList, int iItem, int iSub, const char *text);
void CreateSuColumns(HWND hList);
void DoRefreshStartup(void);
void DoStartupOp(int Op);
void DoStartupContextMenu(HWND hWnd, int X, int Y);

/* ---- FeTrojanPage.c ---- */
extern HWND g_hTrList, g_hTrStatus;
extern int g_TrLoaded;
void TrSetText(HWND h, int iItem, int iSub, const char *text);
void DoTrojanScan(void);
void DoTrojanBackup(void);

extern FE_EXAM_RESULT g_ExamResult;
extern FE_FIREEYE_JOB g_FeJob;
extern FE_OBJ_TYPES g_StObjTypes;
extern FE_TROJAN_REPORT g_TrReport;
extern XPCH_CLIENT g_Client;
extern HWND g_hMainWnd;
extern HWND g_hProcFilter;   /* 第二步增量2：Process 页列过滤框 */

/* 共享 UI 助手（frontend.c 实现，页面模块调用） */
int    FeInsertColumnA(HWND h, int i, const LVCOLUMNA *pc);
ULONG  GetSelectedPid(void);
extern HWND g_hMainTabs;
extern int g_MainTab;
extern char *g_PromptBuf;
extern size_t g_PromptChars;
extern BOOL g_PromptOk;

/* frontend.c：主窗口 ShowPage（页面模块的跨页跳转回调它） */
void ShowPage(HWND hWnd, int page);

/* ---- FeMenu.c：跨页共享的右键菜单与剪贴板/导出助手 ----
   原版每个列表都挂右键菜单（662 条多语言文案），本组函数避免各页重复实现。 */
HMENU FeMenuBegin(void);
void  FeMenuAdd(HMENU hMenu, UINT id, const char *Text);
void  FeMenuAddEx(HMENU hMenu, UINT id, const char *Text, BOOL Enabled);
void  FeMenuAddCheck(HMENU hMenu, UINT id, const char *Text, BOOL Checked);
void  FeMenuSep(HMENU hMenu);
void  FeMenuAddPopup(HMENU hMenu, HMENU hSub, const char *Text);
UINT  FeMenuEnd(HMENU hMenu, HWND hWnd, int X, int Y, int FallbackDx, int FallbackDy);
BOOL  FeClipCopyText(HWND Owner, const char *Text);
BOOL  FeListCopyCell(HWND hList, int Sel, int Sub, HWND StatusWnd, const char *What);
BOOL  FeListExportToFile(HWND hList, const char *Path, ULONG *OutRows);
BOOL  FeListExportDefault(HWND hList, HWND StatusWnd, const char *Name);
BOOL  FeConfirmDanger(HWND Owner, const char *Title, const char *Detail);
BOOL  FeListGetCellText(HWND hList, int Sel, int Sub, char *Out, int OutChars);
int   FeListGetSel(HWND hList);
int   FeListGetCount(HWND hList);
void  FeListSelectUnderCursor(HWND hList, int X, int Y);

/* ---- FeCommonMenu.c：剩余页面的通用右键菜单（Refresh / Export / Copy） ---- */
void DoNetworkContextMenu(HWND hWnd, int X, int Y);
void DoFileContextMenu(HWND hWnd, int X, int Y);

/* ---- FeFileTools.c：File 页纯用户态工具集（§2.7 补全） ---- */
ULONG FeSearchFiles(const char *RootDir, const char *Pattern, int MaxDepth,
                    ULONG64 MinSize, volatile LONG *Cancel);
const char *FeSearchFileAt(ULONG Index, ULONG64 *OutSize, DWORD *OutAttr);
BOOL  FeHashFile(const char *Path, unsigned int AlgId, char *OutHex, int OutChars);
BOOL  FeGetFileAssociation(const char *Ext, char *ProgId, int ProgIdChars,
                           char *Command, int CommandChars);
BOOL  FeQueryPendingFileOps(char *Out, int OutChars);
BOOL  FeScheduleDeleteOnReboot(const char *Path);
BOOL  FeScheduleRenameOnReboot(const char *From, const char *To);
BOOL  FeRenameFileNow(const char *From, const char *To);
BOOL  FeFileSearchDialog(HWND Owner, char *OutDir, int DirChars,
                         char *OutPattern, int PatChars, int *OutDepth, ULONG64 *OutMinSize);
BOOL  FeFilePendingView(HWND Owner);
BOOL  FeFileAssociationView(HWND Owner, const char *Path);
BOOL  FeFileHashView(HWND Owner, const char *Path);

/* ---- FeFileLocker.c：文件解锁（§2.7 最后一项） ---- */
ULONG FeFileLockerFindHolders(const char *TargetPath, void **Out, ULONG *OutCount);
BOOL  FeFileLockerGet(ULONG Index, ULONG *Pid, ULONG64 *Handle,
                      const char **ProcessName, const char **ObjectPath);
BOOL  FeFileLockerCloseHandle(XPCH_CLIENT *Client, ULONG Pid, ULONG64 Handle, UCHAR *OutResult);
void  FeFileLockerFree(void);
ULONG FeFileLockerCount(void);
extern ULONG g_FlkDiagHandles, g_FlkDiagSelfHandles, g_FlkDiagNameOk, g_FlkDiagNameFail;
void DoServiceCommonContextMenu(HWND hWnd, int X, int Y);
void DoOtherContextMenu(HWND hWnd, int X, int Y);
void DoSettingContextMenu(HWND hWnd, int X, int Y);
void DoFireeyeContextMenu(HWND hWnd, int X, int Y);
void DoTrojanContextMenu(HWND hWnd, int X, int Y);

/* ---- FeSystemViews.c：系统类纯用户态视图（§2.8 补全） ---- */
ULONG FeLoadUserAccounts(void);
ULONG FeLoadInputMethods(void);
ULONG FeLoadLockedSystemPaths(void);
ULONG FeLoadWdfDrivers(void);
void  FeLoadSystemExtras(void);

/* ---- FeNetRegistryViews.c：Network 页的两个纯注册表视图（§2.4 补全） ---- */
typedef void (*NRV_ADD_FN)(const char *Item, const char *Detail);
ULONG FeLoadIePlugins(NRV_ADD_FN Add);
ULONG FeLoadIfeoEntries(NRV_ADD_FN Add);

#endif /* XPCH_FEPAGES_H */
