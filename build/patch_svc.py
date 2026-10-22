import io

p = 'XPCHunterUM/src/frontend.c'
s = io.open(p, encoding='utf-8', newline='').read()
NL = '\r\n' if '\r\n' in s else '\n'

anchor = 'static void DoServiceContextMenu(HWND hWnd, int X, int Y)'
assert s.count(anchor) == 1, s.count(anchor)

func = r'''/* 取 Services 列表选中行的服务条目（重新查表以拿到完整字段）。 */
static BOOL SvGetSelectedEntry(FE_SERVICE_ENTRY *Out)
{
    int sel;
    char name[FE_SVC_NAME_CHARS];
    LVITEMA it;
    FE_SERVICE_LIST list;
    ULONG i;
    BOOL found = FALSE;

    if (!Out || !g_hSvList)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    sel = ListView_GetNextItem(g_hSvList, -1, LVNI_SELECTED);
    if (sel < 0)
        return FALSE;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.pszText = name;
    it.cchTextMax = (int)sizeof(name);
    if (!SendMessageA(g_hSvList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it))
        return FALSE;
    if (!FeLoadServices(&list))
        return FALSE;
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) == 0) {
            *Out = list.Items[i];
            found = TRUE;
            break;
        }
    }
    FeFreeServices(&list);
    return found;
}

/* Services 页右键。对应功能地图第 8 节列出的操作：
     Delete Service(Not Delete File) / Verify ServiceDll Signature /
     Find ImagePath Target / Find ServiceDll Target /
     Copy ImagePath / Copy ServiceDll Path /
     Locate in File Tab (ImagePath / ServiceDll)
   另有 Analyse ImagePath/ServiceDll by FireEye（DoServiceFireeye 单独实现）。 */
static void DoServiceOp(int Op)
{
    FE_SERVICE_ENTRY e;
    char msg[768];
    const char *path;

    if (!g_hSvStatus)
        return;
    if (!SvGetSelectedEntry(&e)) {
        SetWindowTextA(g_hSvStatus, "Select a service first");
        return;
    }
    path = e.ResolvedPath[0] ? e.ResolvedPath : e.ImagePath;

    switch (Op) {
    case 0:   /* Delete Service (Not Delete File) */
        {
            int r;
            sprintf_s(msg, sizeof(msg),
                      "Delete service \"%s\"?\n\nThe service registration is removed "
                      "but the file on disk is NOT deleted.", e.Name);
            r = MessageBoxA(g_hMainWnd, msg, "Delete Service",
                            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
            if (r != IDYES) {
                SetWindowTextA(g_hSvStatus, "Delete service cancelled");
                return;
            }
            if (FeDeleteService(e.Name))
                sprintf_s(msg, sizeof(msg),
                          "Delete Service(Not Delete File): %s removed (file kept: %s)",
                          e.Name, path[0] ? path : "(none)");
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Service(Not Delete File): %s failed", e.Name);
            SetWindowTextA(g_hSvStatus, msg);
            DoRefreshServices();
        }
        return;
    case 1:   /* Verify ImagePath Signature */
        sprintf_s(msg, sizeof(msg), "Verify ImagePath Signature: %s -> %s (%s)",
                  e.Name,
                  FeVerifyFileSignature(path) ? "valid and trusted"
                                              : "no signature or not trusted",
                  path[0] ? path : "(no ImagePath)");
        SetWindowTextA(g_hSvStatus, msg);
        return;
    case 2:   /* Verify ServiceDll Signature */
        if (!e.ServiceDll[0]) {
            sprintf_s(msg, sizeof(msg),
                      "Verify ServiceDll Signature: %s has no ServiceDll", e.Name);
        } else {
            sprintf_s(msg, sizeof(msg), "Verify ServiceDll Signature: %s -> %s (%s)",
                      e.Name,
                      FeVerifyFileSignature(e.ServiceDll) ? "valid and trusted"
                                                          : "no signature or not trusted",
                      e.ServiceDll);
        }
        SetWindowTextA(g_hSvStatus, msg);
        return;
    case 3:   /* Find ImagePath Target */
    case 4:   /* Find ServiceDll Target */
        {
            const char *t = (Op == 3) ? path : e.ServiceDll;
            const char *what = (Op == 3) ? "Find ImagePath Target" : "Find ServiceDll Target";
            if (!t || !t[0]) {
                sprintf_s(msg, sizeof(msg), "%s: %s has no %s", what, e.Name,
                          Op == 3 ? "ImagePath" : "ServiceDll");
            } else {
                WCHAR wt[MAX_PATH];
                MultiByteToWideChar(CP_ACP, 0, t, -1, wt, MAX_PATH);
                sprintf_s(msg, sizeof(msg), "%s: %s -> %s (%s)", what, e.Name, t,
                          GetFileAttributesW(wt) == INVALID_FILE_ATTRIBUTES
                          ? "FILE NOT FOUND" : "file exists");
            }
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    case 5:   /* Copy ImagePath */
    case 6:   /* Copy ServiceDll Path */
        {
            const char *t = (Op == 5) ? path : e.ServiceDll;
            if (!t || !t[0]) {
                SetWindowTextA(g_hSvStatus, "Selected service has no path to copy");
                return;
            }
            if (!OpenClipboard(g_hSvList))
                return;
            EmptyClipboard();
            {
                HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(t) + 1);
                if (h) {
                    void *q = GlobalLock(h);
                    if (q) {
                        memcpy(q, t, strlen(t) + 1);
                        GlobalUnlock(h);
                        SetClipboardData(CF_TEXT, h);
                    }
                }
            }
            CloseClipboard();
            sprintf_s(msg, sizeof(msg), "%s copied: %s",
                      Op == 5 ? "ImagePath" : "ServiceDll path", t);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    case 7:   /* Locate in File Tab (ImagePath) */
    case 8:   /* Locate in File Tab (ServiceDll) */
        {
            const char *t = (Op == 7) ? path : e.ServiceDll;
            char dir[FE_SVC_PATH_CHARS];
            char *slash;
            if (!t || !t[0]) {
                SetWindowTextA(g_hSvStatus, "Selected service has no path");
                return;
            }
            strcpy_s(dir, sizeof(dir), t);
            slash = strrchr(dir, '\\');
            if (slash)
                *slash = 0;
            if (g_hFlDir) {
                SetWindowTextA(g_hFlDir, dir);
                g_MainTab = 8;
                if (g_hMainTabs)
                    SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
                if (g_hMainWnd)
                    ShowPage(g_hMainWnd, 8);
                DoRefreshFiles();
            }
            sprintf_s(msg, sizeof(msg), "%s: located in File tab -> %s",
                      Op == 7 ? "Locate ImagePath" : "Locate ServiceDll", dir);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    default:
        return;
    }
}

'''

s = s.replace(anchor, func + anchor, 1)

old_menu = ('    AppendMenuA(hMenu, MF_STRING, 7001, "Analyse ImagePath by FireEye");' + NL +
            '    AppendMenuA(hMenu, MF_STRING, 7002, "Analyse ServiceDll by FireEye");')
assert s.count(old_menu) == 1, s.count(old_menu)
new_menu = (
    '    AppendMenuA(hMenu, MF_STRING, 7003, "Delete Service (Not Delete File)");' + NL +
    '    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7004, "Verify ImagePath Signature");' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7005, "Verify ServiceDll Signature");' + NL +
    '    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7006, "Find ImagePath Target");' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7007, "Find ServiceDll Target");' + NL +
    '    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7008, "Copy ImagePath");' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7009, "Copy ServiceDll Path");' + NL +
    '    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7010, "Locate in File Tab (ImagePath)");' + NL +
    '    AppendMenuA(hMenu, MF_STRING, 7011, "Locate in File Tab (ServiceDll)");' + NL +
    '    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);' + NL +
    old_menu)
s = s.replace(old_menu, new_menu)

old_disp = ('    if (cmd == 7001)' + NL + '        DoServiceFireeye(0);' + NL +
            '    else if (cmd == 7002)' + NL + '        DoServiceFireeye(1);')
assert s.count(old_disp) == 1, s.count(old_disp)
new_disp = old_disp + NL + '    else if (cmd >= 7003 && cmd <= 7011)' + NL + \
           '        DoServiceOp(cmd - 7003);'
s = s.replace(old_disp, new_disp)

io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('ok')