# -*- coding: utf-8 -*-
import sys

def append_to_file(filepath, content):
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(content)
    print(f'Written to {filepath}')

# ====== IoctlDispatch.c ======
ioctl = """

// EnumServiceTableWin10 -- 枚举服务表(Win10 版)
__int64 EnumServiceTableWin10(__int64 *a1, __int64 a2, _DWORD *a3, int a4)
{
    __int64 (__fastcall *v7)(__int64 *) = (__int64 (__fastcall *)(__int64 *))GtRead(GtObjectTypeCheckFlag);
    unsigned int v8 = GtRead(GtProcessEprocess);
    unsigned int v9 = GtRead(GtProcessCreateTime);
    __int64 result = GtRead(GtProcessOffset);
    unsigned int v18 = result;
    if (v7 && v8 != -1 && v9 && (_DWORD)result != -1 && a1)
    {
        result = v7(a1);
        if ((_BYTE)result)
        {
            __int64 v11 = *a1;
            unsigned int v12 = 0;
            if (v11)
            {
                __int64 v13 = a2 + 8;
                do
                {
                    result = v7((__int64 *)v11);
                    if (!(_BYTE)result || !a4 || v12 > 0x10000)
                        break;
                    __int64 v14 = *(_QWORD *)(v11 + 40);
                    __int64 **v15 = v14 ? *(__int64 ***)(v14 + 16) : *(__int64 ***)(v11 + 48);
                    if (v15)
                    {
                        __int64 *v16 = *v15;
                        if (v16)
                        {
                            result = v7(v16);
                            if ((_BYTE)result)
                            {
                                --a4;
                                *(_QWORD *)(v13 + 8) = *(_QWORD *)(v11 + 80);
                                int v17 = *(_DWORD *)(v11 + 68);
                                *(_QWORD *)(v13 - 8) = v11;
                                *(_DWORD *)v13 = v17;
                                v13 += 48;
                                *(_QWORD *)(v13 - 16) = *(unsigned int *)((char *)v16 + v9);
                                result = v18;
                                *(_QWORD *)(v13 - 32) = *(unsigned int *)((char *)v16 + v8);
                                *(_QWORD *)(v13 - 24) = *(__int64 *)((char *)v16 + v18);
                                ++*a3;
                            }
                        }
                    }
                    v11 = *(_QWORD *)(v11 + 24);
                    ++v12;
                }
                while (v11);
            }
        }
    }
    return result;
}

// EnumServiceTableWin8 -- 枚举服务表(Win8 版)
__int64 EnumServiceTableWin8(_QWORD **a1, __int64 a2, _DWORD *a3, int a4)
{
    __int64 (__fastcall *v7)(_QWORD **) = (__int64 (__fastcall *)(_QWORD **))GtRead(GtObjectTypeCheckFlag);
    unsigned int v8 = GtRead(GtProcessEprocess);
    unsigned int v20 = v8;
    unsigned int v9 = GtRead(GtProcessCreateTime);
    unsigned int v19 = v9;
    __int64 result = GtRead(GtProcessOffset);
    unsigned int v21 = result;
    if (v7 && v8 != -1 && v9 && (_DWORD)result != -1 && a1)
    {
        result = v7(a1);
        if ((_BYTE)result)
        {
            _QWORD **v11 = (_QWORD **)*a1;
            unsigned int v12 = 0;
            if (*a1)
            {
                __int64 v13 = a2 + 8;
                do
                {
                    result = v7(v11);
                    if (!(_BYTE)result || v11 == a1 || !a4 || v12 > 0x10000)
                        break;
                    _QWORD **v14 = v11 - 3;
                    _QWORD *v15 = v14[5];
                    __int64 *v16 = v15 ? (__int64 *)v15[2] : v14[6];
                    if (v16)
                    {
                        _QWORD **v17 = (_QWORD **)*v16;
                        if (v17)
                        {
                            result = v7(v17);
                            if ((_BYTE)result)
                            {
                                --a4;
                                *(_QWORD *)(v13 + 8) = v14[10];
                                int v18 = *((_DWORD *)v14 + 17);
                                *(_QWORD *)(v13 - 8) = v14;
                                *(_DWORD *)v13 = v18;
                                v13 += 48;
                                *(_QWORD *)(v13 - 16) = *(_QWORD **)((char *)v17 + v19);
                                result = v21;
                                *(_QWORD *)(v13 - 32) = *(_QWORD **)((char *)v17 + v20);
                                *(_QWORD *)(v13 - 24) = *(_QWORD **)((char *)v17 + v21);
                                ++*a3;
                            }
                        }
                    }
                    v11 = (_QWORD **)*v11;
                    ++v12;
                }
                while (v11);
            }
        }
    }
    return result;
}

// EnumServiceTableWin7 -- 枚举服务表(Win7 版)
__int64 EnumServiceTableWin7(__int64 *a1, __int64 a2, _DWORD *a3, int a4)
{
    __int64 (__fastcall *v7)(__int64 *) = (__int64 (__fastcall *)(__int64 *))GtRead(GtObjectTypeCheckFlag);
    unsigned int v8 = GtRead(GtProcessEprocess);
    unsigned int v9 = GtRead(GtProcessCreateTime);
    __int64 result = GtRead(GtProcessOffset);
    unsigned int v18 = result;
    if (v7 && v8 != -1 && v9 && (_DWORD)result != -1 && a1)
    {
        result = v7(a1);
        if ((_BYTE)result)
        {
            __int64 v11 = *a1;
            unsigned int v12 = 0;
            if (v11)
            {
                __int64 v13 = a2 + 8;
                do
                {
                    result = v7((__int64 *)v11);
                    if (!(_BYTE)result || !a4 || v12 > 0x10000)
                        break;
                    __int64 v14 = *(_QWORD *)(v11 + 32);
                    __int64 **v15 = v14 ? *(__int64 ***)(v14 + 16) : *(__int64 ***)(v11 + 24);
                    if (v15)
                    {
                        __int64 *v16 = *v15;
                        if (v16)
                        {
                            result = v7(v16);
                            if ((_BYTE)result)
                            {
                                --a4;
                                *(_QWORD *)(v13 + 8) = *(_QWORD *)(v11 + 56);
                                int v17 = *(_DWORD *)(v11 + 48);
                                *(_QWORD *)(v13 - 8) = v11;
                                *(_DWORD *)v13 = v17;
                                v13 += 48;
                                *(_QWORD *)(v13 - 16) = *(unsigned int *)((char *)v16 + v9);
                                result = v18;
                                *(_QWORD *)(v13 - 32) = *(unsigned int *)((char *)v16 + v8);
                                *(_QWORD *)(v13 - 24) = *(__int64 *)((char *)v16 + v18);
                                ++*a3;
                            }
                        }
                    }
                    v11 = *(_QWORD *)(v11 + 8);
                    ++v12;
                }
                while (v11);
            }
        }
    }
    return result;
}

// EnumServiceTableWin1020H1 -- 枚举服务表(Win10 20H1+ 版)
__int64 EnumServiceTableWin1020H1(_QWORD **a1, __int64 a2, _DWORD *a3, int a4)
{
    __int64 (__fastcall *v7)(_QWORD **) = (__int64 (__fastcall *)(_QWORD **))GtRead(GtObjectTypeCheckFlag);
    unsigned int v8 = GtRead(GtProcessEprocess);
    unsigned int v20 = v8;
    unsigned int v9 = GtRead(GtProcessCreateTime);
    unsigned int v19 = v9;
    __int64 result = GtRead(GtProcessOffset);
    unsigned int v21 = result;
    if (v7 && v8 != -1 && v9 && (_DWORD)result != -1 && a1)
    {
        result = v7(a1);
        if ((_BYTE)result)
        {
            result = GtRead(GtWindowsBuildNumber);
            if ((unsigned int)result < 0x2800 || (a1 = (_QWORD **)*a1) != 0 && (result = v7(a1), (_BYTE)result))
            {
                _QWORD **v11 = (_QWORD **)*a1;
            }
            else
            {
                a1 = 0;
                _QWORD **v11 = 0;
            }
            unsigned int v12 = 0;
            if (v11)
            {
                __int64 v13 = a2 + 8;
                while (1)
                {
                    result = v7(v11);
                    if (!(_BYTE)result || !a4 || v11 == a1 || v12 > 0x10000)
                        return result;
                    _QWORD **v14 = v11 - 9;
                    unsigned __int64 v15 = (unsigned __int64)v14[11];
                    if (!v15)
                    {
                        _QWORD *v16 = v14[3];
                        goto LABEL_22;
                    }
                    result = (__int64)MmSystemRangeStart;
                    if (v15 >= (unsigned __int64)MmSystemRangeStart)
                    {
                        _QWORD *v16 = *(_QWORD **)(v15 + 16);
LABEL_22:
                        if (v16)
                        {
                            _QWORD **v17 = (_QWORD **)*v16;
                            if (v17)
                            {
                                result = v7(v17);
                                if ((_BYTE)result)
                                {
                                    --a4;
                                    *(_QWORD *)(v13 + 8) = v14[4];
                                    int v18 = *((_DWORD *)v14 + 10);
                                    *(_QWORD *)(v13 - 8) = v14;
                                    *(_DWORD *)v13 = v18;
                                    v13 += 48;
                                    *(_QWORD *)(v13 - 16) = *(_QWORD **)((char *)v17 + v19);
                                    result = v21;
                                    *(_QWORD *)(v13 - 32) = *(_QWORD **)((char *)v17 + v20);
                                    *(_QWORD *)(v13 - 24) = *(_QWORD **)((char *)v17 + v21);
                                    ++*a3;
                                }
                            }
                        }
                    }
                    v11 = (_QWORD **)*v11;
                    ++v12;
                    if (!v11)
                        return result;
                }
            }
        }
    }
    return result;
}
"""

append_to_file('src/IoctlDispatch.c', ioctl)