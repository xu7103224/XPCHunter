// CheckProcessAccess  0x1400812B0  97 bytes
// 检查进程访问权限——验证当前进程是否为驱动保护进程，授权则返回TRUE
// 检查进程访问权限
// 检查进程访问权限：检查当前进程是否有权限访问驱动
char CheckProcessAccess()
{
  struct _KPROCESS *v0; // rbx
  bool v1; // bl

  v0 = (struct _KPROCESS *)GtRead(GtEprocessField123|0x100);
  if ( !v0 || v0 == IoGetCurrentProcess() )
    return 1;
  v1 = ValidateProcessObject(v0, 0) == 0;
  GtWrite(GtCallbackField125, 0);
  return v1;
}
