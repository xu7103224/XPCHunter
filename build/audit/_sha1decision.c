// 判定：原始驱动 SHA1 的输入是否做字节交换？
// 变体A = 输入不交换（当前实现，与 0 bswap 证据一致）
// 变体B = 输入交换（RFC1321 标准）
// 两者输出都做 RtlUlongByteSwap（0x1400764AC 的逐字节展开已证实）。
#include <stdio.h>
#include <string.h>
typedef unsigned int ULONG; typedef unsigned char UCHAR;
#define ROTL32(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define SWAP(x) ((((x)>>24)&0xFF)|(((x)>>8)&0xFF00)|(((x)&0xFF00)<<8)|(((x)&0xFF)<<24))

typedef struct { unsigned __int64 Count; ULONG State[5]; UCHAR Buffer[64]; } CTX;

static int g_swap = 0;   // 0=变体A(不交换输入) 1=变体B(交换输入)

static void Transform(ULONG S[5], UCHAR *B){
    ULONG w[80],a,b,c,d,e,t,i;
    for(i=0;i<16;i++) w[i]= g_swap ? SWAP(((ULONG*)B)[i]) : ((ULONG*)B)[i];
    for(i=16;i<80;i++) w[i]=ROTL32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    a=S[0];b=S[1];c=S[2];d=S[3];e=S[4];
    for(i=0;i<80;i++){
        if(i<20) t=ROTL32(a,5)+((b&c)|(~b&d))+e+w[i]+0x5A827999;
        else if(i<40) t=ROTL32(a,5)+(b^c^d)+e+w[i]+0x6ED9EBA1;
        else if(i<60) t=ROTL32(a,5)+((b&c)|(b&d)|(c&d))+e+w[i]+0x8F1BBCDC;
        else t=ROTL32(a,5)+(b^c^d)+e+w[i]+0xCA62C1D6;
        e=d;d=c;c=ROTL32(b,30);b=a;a=t;
    }
    S[0]+=a;S[1]+=b;S[2]+=c;S[3]+=d;S[4]+=e;
}
static void Init(CTX *C){
    memset(C,0,sizeof(*C));
    C->State[0]=0x67452301;C->State[1]=0xEFCDAB89;C->State[2]=0x98BADCFE;
    C->State[3]=0x10325476;C->State[4]=0xC3D2E1F0;
}
static void Update(CTX *C, UCHAR *In, ULONG Len){
    ULONG index=(ULONG)((C->Count>>3)&0x3F), partLen=64-index, i=0;
    C->Count += ((unsigned __int64)Len<<3);
    if(index+Len>0x3F){
        memmove(&C->Buffer[index],In,partLen);
        Transform(C->State,C->Buffer);
        for(i=partLen;i+63<Len;i+=64) Transform(C->State,&In[i]);
        index=0;
    }
    memmove(&C->Buffer[index],&In[i],Len-i);
}
static void Final(CTX *C, ULONG out[5]){
    UCHAR bits[8]; ULONG idx,padLen,i; UCHAR pad[64]={0x80};
    bits[0]=(UCHAR)(C->Count>>56);bits[1]=(UCHAR)(C->Count>>48);
    bits[2]=(UCHAR)(C->Count>>40);bits[3]=(UCHAR)(C->Count>>32);
    bits[4]=(UCHAR)(C->Count>>24);bits[5]=(UCHAR)(C->Count>>16);
    bits[6]=(UCHAR)(C->Count>>8); bits[7]=(UCHAR)(C->Count);
    idx=(ULONG)((C->Count>>3)&0x3F); padLen=(idx<56)?(56-idx):(120-idx);
    Update(C,pad,bits?padLen:padLen); Update(C,bits,8);
    for(i=0;i<5;i++) out[i]=SWAP(C->State[i]);
}

int main(void){
    struct { const char *m; const char *e; } T[] = {
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"abc","a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"The quick brown fox jumps over the lazy dog","2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
    };
    int n=sizeof(T)/sizeof(T[0]);
    char hex[41];
    for(int v=0; v<2; v++){
        g_swap=v; int pass=0;
        printf("=== 变体%s：%s ===\n", v?"B":"A", v?"交换输入":"不交换输入");
        for(int k=0;k<n;k++){
            CTX C; ULONG d[5]; Init(&C);
            Update(&C,(UCHAR*)T[k].m,(ULONG)strlen(T[k].m));
            Final(&C,d);
            sprintf(hex,"%08x%08x%08x%08x%08x",d[0],d[1],d[2],d[3],d[4]);
            int ok=!strcmp(hex,T[k].e); pass+=ok;
            printf("  len=%2d %s %s\n",(int)strlen(T[k].m),ok?"OK  ":"FAIL",hex);
        }
        printf("  -> %d/%d 与标准 SHA1 一致\n\n",pass,n);
    }
    return 0;
}