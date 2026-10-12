// 离线校验：按 Crypto.c 修正后的 MD5 实现逐字复刻，对照 RFC1321 标准测试向量。
// 覆盖两族：族2(State@0x00/Buffer@0x10/Count@0x50) 与 族1(Count@0x00/Buffer@0x08/State@0x48)
#include <stdio.h>
#include <string.h>
typedef unsigned int ULONG; typedef unsigned char UCHAR;
#define ROTL32(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define MD5_S11 7
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

static const ULONG Md5_K[64] = {
 0xD76AA478,0xE8C7B756,0x242070DB,0xC1BDCEEE,0xF57C0FAF,0x4787C62A,0xA8304613,0xFD469501,
 0x698098D8,0x8B44F7AF,0xFFFF5BB1,0x895CD7BE,0x6B901122,0xFD987193,0xA679438E,0x49B40821,
 0xF61E2562,0xC040B340,0x265E5A51,0xE9B6C7AA,0xD62F105D,0x02441453,0xD8A1E681,0xE7D3FBC8,
 0x21E1CDE6,0xC33707D6,0xF4D50D87,0x455A14ED,0xA9E3E905,0xFCEFA3F8,0x676F02D9,0x8D2A4C8A,
 0xFFFA3942,0x8771F681,0x6D9D6122,0xFDE5380C,0xA4BEEA44,0x4BDECFA9,0xF6BB4B60,0xBEBFBC70,
 0x289B7EC6,0xEAA127FA,0xD4EF3085,0x04881D05,0xD9D4D039,0xE6DB99E5,0x1FA27CF8,0xC4AC5665,
 0xF4292244,0x432AFF97,0xAB9423A7,0xFC93A039,0x655B59C3,0x8F0CCC92,0xFFEFF47D,0x85845DD1,
 0x6FA87E4F,0xFE2CE6E0,0xA3014314,0x4E0811A1,0xF7537E82,0xBD3AF235,0x2AD7D2BB,0xEB86D391};

/* 修正后的位移表：第1轮7,12,17,22 ×4；第2轮5,9,14,20 ×4；
   第3轮4,11,16,23 ×4；第4轮6,10,15,21 ×4 */
static const ULONG Md5_S[64] = {
 MD5_S11,MD5_S12,MD5_S13,MD5_S14, MD5_S11,MD5_S12,MD5_S13,MD5_S14,
 MD5_S11,MD5_S12,MD5_S13,MD5_S14, MD5_S11,MD5_S12,MD5_S13,MD5_S14,
 MD5_S21,MD5_S22,MD5_S23,MD5_S24, MD5_S21,MD5_S22,MD5_S23,MD5_S24,
 MD5_S21,MD5_S22,MD5_S23,MD5_S24, MD5_S21,MD5_S22,MD5_S23,MD5_S24,
 MD5_S31,MD5_S32,MD5_S33,MD5_S34, MD5_S31,MD5_S32,MD5_S33,MD5_S34,
 MD5_S31,MD5_S32,MD5_S33,MD5_S34, MD5_S31,MD5_S32,MD5_S33,MD5_S34,
 MD5_S41,MD5_S42,MD5_S43,MD5_S44, MD5_S41,MD5_S42,MD5_S43,MD5_S44,
 MD5_S41,MD5_S42,MD5_S43,MD5_S44, MD5_S41,MD5_S42,MD5_S43,MD5_S44};

static const ULONG Md5_Id[64] = {
 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
 1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
 5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
 0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9};

void Md5Transform(ULONG State[4], UCHAR *Block){
    ULONG a=State[0],b=State[1],c=State[2],d=State[3],x[16],i;
    for(i=0;i<16;i++)
        x[i]=((ULONG)Block[i*4])|(((ULONG)Block[i*4+1])<<8)|
             (((ULONG)Block[i*4+2])<<16)|(((ULONG)Block[i*4+3])<<24);
    for(i=0;i<64;i++){
        ULONG f;
        if(i<16) f=(b&c)|(~b&d);
        else if(i<32) f=(d&b)|(~d&c);
        else if(i<48) f=b^c^d;
        else f=c^(b|~d);
        ULONG g=Md5_Id[i], temp=d;
        d=c;c=b;
        b=b+ROTL32(a+f+Md5_K[i]+x[g],Md5_S[i]);
        a=temp;
    }
    State[0]+=a;State[1]+=b;State[2]+=c;State[3]+=d;
}

/* ---- 族 2 ---- */
typedef struct { ULONG State[4]; UCHAR Buffer[64]; unsigned __int64 Count; } MD5_CONTEXT;
void InitMd5Context(MD5_CONTEXT *C){
    memset(C,0,sizeof(*C));
    C->State[0]=0x67452301;C->State[1]=0xEFCDAB89;
    C->State[2]=0x98BADCFE;C->State[3]=0x10325476;
}
void Md5Transform2(ULONG S[4],UCHAR *B){ Md5Transform(S,B); }
void Md5Update(MD5_CONTEXT *C,UCHAR *In,ULONG Len){
    ULONG index=(ULONG)(C->Count&0x3F), partLen=64-index, i=0;
    C->Count+=Len;
    if(Len>=partLen){
        memmove(&C->Buffer[index],In,partLen);
        Md5Transform2(C->State,C->Buffer);
        for(i=partLen;i+63<Len;i+=64){ memmove(C->Buffer,&In[i],64); Md5Transform2(C->State,C->Buffer); }
        index=0;
    }
    memmove(&C->Buffer[index],&In[i],Len-i);
}
void Md5Final(MD5_CONTEXT *C,UCHAR *Digest){
    ULONG index=(ULONG)(C->Count&0x3F),i;
    C->Buffer[index]=0x80;
    for(i=index+1;i<64;i++) C->Buffer[i]=0;
    if(index>=56){ Md5Transform2(C->State,C->Buffer); for(i=0;i<56;i++) C->Buffer[i]=0; }
    *(ULONG*)&C->Buffer[56]=(ULONG)(C->Count<<3);
    *(ULONG*)&C->Buffer[60]=(ULONG)(C->Count>>29);
    Md5Transform2(C->State,C->Buffer);
    memcpy(Digest,C->State,16);
}

/* ---- 族 1 ---- */
typedef struct { unsigned __int64 Count; UCHAR Buffer[64]; ULONG State[4]; } MD5_CTX_L;
void Md5Init(MD5_CTX_L *C){
    memset(C,0,sizeof(*C));
    C->State[0]=0x67452301;C->State[1]=0xEFCDAB89;
    C->State[2]=0x98BADCFE;C->State[3]=0x10325476;
}
void Md5Update2(MD5_CTX_L *C,UCHAR *In,ULONG Len){
    ULONG index=(ULONG)(C->Count&0x3F), partLen=64-index, i=0;
    C->Count+=Len;
    if(Len>=partLen){
        memmove(&C->Buffer[index],In,partLen);
        Md5Transform(C->State,C->Buffer);
        for(i=partLen;i+63<Len;i+=64){ memmove(C->Buffer,&In[i],64); Md5Transform(C->State,C->Buffer); }
        index=0;
    }
    memmove(&C->Buffer[index],&In[i],Len-i);
}
void Md5Final2(MD5_CTX_L *C,UCHAR *Digest){
    ULONG index=(ULONG)(C->Count&0x3F),i;
    C->Buffer[index]=0x80;
    for(i=index+1;i<64;i++) C->Buffer[i]=0;
    if(index>=56){ Md5Transform(C->State,C->Buffer); for(i=0;i<56;i++) C->Buffer[i]=0; }
    *(ULONG*)&C->Buffer[56]=(ULONG)(C->Count<<3);
    *(ULONG*)&C->Buffer[60]=(ULONG)(C->Count>>29);
    Md5Transform(C->State,C->Buffer);
    memcpy(Digest,C->State,16);
}

static void hexify(const UCHAR *d,int n,char *out){
    for(int i=0;i<n;i++) sprintf(out+i*2,"%02x",d[i]);
    out[n*2]=0;
}

int main(void){
    struct { const char *m; const char *e; } T[] = {
        {"",            "d41d8cd98f00b204e9800998ecf8427e"},
        {"a",           "0cc175b9c0f1b6a831c399e269772661"},
        {"abc",         "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest","f96b697d7cb7938d525a2f31aaf161d0"},
        {"abcdefghijklmnopqrstuvwxyz","c3fcd3d76192e4007dfb496cca67e13b"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                        "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                        "57edf4a22be3c955ac49da2e2107b67a"},
    };
    int n=sizeof(T)/sizeof(T[0]), p2=0, p1=0;
    char hex[33];
    for(int k=0;k<n;k++){
        UCHAR d[16];
        MD5_CONTEXT C2; InitMd5Context(&C2);
        Md5Update(&C2,(UCHAR*)T[k].m,(ULONG)strlen(T[k].m));
        Md5Final(&C2,d); hexify(d,16,hex);
        int ok2 = strcmp(hex,T[k].e)==0; p2+=ok2;

        MD5_CTX_L C1; Md5Init(&C1);
        Md5Update2(&C1,(UCHAR*)T[k].m,(ULONG)strlen(T[k].m));
        Md5Final2(&C1,d); char hex1[33]; hexify(d,16,hex1);
        int ok1 = strcmp(hex1,T[k].e)==0; p1+=ok1;

        printf("len=%3d\n  exp %s\n  族2 %s %s\n  族1 %s %s\n",
            (int)strlen(T[k].m), T[k].e, hex, ok2?"OK":"FAIL", hex1, ok1?"OK":"FAIL");
    }
    printf("\n族2: %d/%d   族1: %d/%d\n", p2,n,p1,n);
    return 0;
}