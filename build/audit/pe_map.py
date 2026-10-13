#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
软模拟 Windows 内核驱动的 PE 内存映射。

做四件真机加载器会做的事：
  1. 按 VirtualAddress 把各节映射到 SizeOfImage 大小的连续镜像；
  2. 应用 BASERELOC（模拟 ASLR：可指定任意 ImageBase）；
  3. 解析 IMPORT，把每个导入函数指向一个"桩地址"（可注入返回值）；
  4. 定位入口点，并可选择性地交给 Unicorn 执行。

用途：验证静态逆向结论（重定位目标、导入表、节区布局），
     并为后续在模拟器里执行指定函数提供可用的地址空间。
"""
import struct
import sys
import pefile

MASK64 = (1 << 64) - 1

# 内核 API -> 桩地址（放在镜像之外的高地址区，便于区分）
STUB_BASE = 0xFFFFF80000000000


class MappedImage:
    def __init__(self, path, image_base=None):
        self.path = path
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories()
        self.orig_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.base = image_base if image_base is not None else self.orig_base
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.image = bytearray(self.size)
        self.stubs = {}          # 名称 -> 桩地址
        self.stub_names = {}     # 桩地址 -> 名称
        self.relocs_applied = 0
        self._map_sections()
        self._apply_relocs()
        self._map_imports()

    # ---------- 1. 节映射 ----------
    def _map_sections(self):
        hdr_size = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        raw = self.pe.__data__[:hdr_size]
        self.image[:len(raw)] = raw
        self.sections = []
        for s in self.pe.sections:
            va = s.VirtualAddress
            vsz = s.Misc_VirtualSize
            data = s.get_data()
            self.image[va:va + len(data)] = data
            self.sections.append({
                'name': s.Name.rstrip(b'\0').decode('latin1'),
                'va': va, 'vsize': vsz,
                'raw_off': s.PointerToRawData, 'raw_size': s.SizeOfRawData,
                'chars': s.Characteristics,
            })

    # ---------- 2. 基址重定位 ----------
    def _apply_relocs(self):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            return
        delta = (self.base - self.orig_base) & MASK64
        if delta == 0:
            return
        for block in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for e in block.entries:
                if e.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    off = e.rva
                    cur = struct.unpack_from('<I', self.image, off)[0]
                    struct.pack_into('<I', self.image, off, (cur + delta) & 0xFFFFFFFF)
                    self.relocs_applied += 1
                elif e.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                    off = e.rva
                    cur = struct.unpack_from('<Q', self.image, off)[0]
                    struct.pack_into('<Q', self.image, off, (cur + delta) & MASK64)
                    self.relocs_applied += 1
                elif e.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                    pass  # 对齐填充
                else:
                    raise NotImplementedError(f'未知重定位类型 {e.type} @ {hex(e.rva)}')

    # ---------- 3. 导入解析（指向桩） ----------
    def _map_imports(self):
        self.import_thunks = {}   # (dll, func) -> IAT 的 RVA
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return
        idx = 0
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllname = dll.dll.decode('latin1')
            for imp in dll.imports:
                fname = imp.name.decode('latin1') if imp.name else f'ord_{imp.ordinal}'
                stub = STUB_BASE + idx * 0x100
                idx += 1
                self.stubs[fname] = stub
                self.stub_names[stub] = fname
                self.import_thunks[(dllname, fname)] = imp.address - self.orig_base
                if imp.address >= self.orig_base:
                    off = imp.address - self.orig_base
                    if off + 8 <= self.size:
                        struct.pack_into('<Q', self.image, off, stub)

    # ---------- 查询 ----------
    def rva_of(self, va):
        return va - self.base

    def va_of(self, rva):
        return self.base + rva

    def read(self, va, n):
        return bytes(self.image[self.rva_of(va):self.rva_of(va) + n])

    def u64(self, va):
        return struct.unpack_from('<Q', self.image, self.rva_of(va))[0]

    def u32(self, va):
        return struct.unpack_from('<I', self.image, self.rva_of(va))[0]

    def entry(self):
        return self.va_of(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def summary(self):
        lines = []
        lines.append(f'文件            : {self.path}')
        lines.append(f'原始 ImageBase  : {hex(self.orig_base)}')
        lines.append(f'本次加载基址     : {hex(self.base)}')
        lines.append(f'SizeOfImage     : {hex(self.size)} ({self.size} 字节)')
        lines.append(f'EntryPoint      : {hex(self.entry())} (RVA {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)})')
        lines.append(f'重定位已应用     : {self.relocs_applied} 条'
                     + ('（delta=0，无需修改）' if self.relocs_applied == 0 else ''))
        lines.append(f'导入函数        : {len(self.stubs)} 个')
        lines.append('节区：')
        for s in self.sections:
            lines.append('  %-8s VA=%08x VS=%08x RAW_OFF=%08x RAW_SZ=%08x ch=%08x'
                         % (s['name'], s['va'], s['vsize'], s['raw_off'],
                            s['raw_size'], s['chars']))
        return '\n'.join(lines)


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
    base = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
    img = MappedImage(path, base)
    print(img.summary())
    print()
    print('导入表（前 20）：')
    for i, (k, v) in enumerate(sorted(img.stubs.items())):
        if i >= 20:
            print(f'  ... 共 {len(img.stubs)} 个')
            break
        print(f'  {k:<40} -> {hex(v)}')