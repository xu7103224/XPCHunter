#include <stdio.h>
#include "gt_enum_standalone.h"
int main(void){
  printf("Field123|0x100    = 0x%X\n", (unsigned)(GtEprocessField123|0x100));
  printf("0x185             = 0x%X\n", 0x185);
  printf("FwpsBase|Field36  = 0x%X\n", (unsigned)(GtFwpsDispatchTableBase|GtEprocessField36));
  printf("ModEntrySize|F22  = 0x%X\n", (unsigned)(GtEprocessModuleEntrySize|GtEprocessField22));
  return 0;
}
