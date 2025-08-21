// --- FINAL, C++ ORIENTED STUB, IMITATING THE SUCCESSFUL EXAMPLES ---

// 合并区段，使整个 stub 都在一个 .text 区段内
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

#include <Windows.h>

// --- 通信结构体 ---
// 与 packer.cpp 中的定义完全一致
typedef struct _StubConf
{
    DWORD oep;
    DWORD text_rva;
    DWORD text_size;
    DWORD key;
} StubConf;

// 由 packer 在内存中直接填充，我们的 stub 读取它
extern "C" __declspec(dllexport) StubConf g_conf = { 0 };

// --- 全局变量，用于保存我们动态获取的 API 函数指针 ---
// 使用 typedef 定义函数指针类型，使代码更清晰
typedef FARPROC(WINAPI* FnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI* FnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

FnGetProcAddress pGetProcAddress = nullptr;
FnVirtualProtect pVirtualProtect = nullptr;

// --- C++ 核心函数 ---

// 步骤 1: 获取必要的 API 函数地址
void GetApiAddresses()
{
    HMODULE hKernel32 = NULL;

    // [必要部分: 内联汇编]
    // 模仿成功案例，通过 PEB 硬编码顺序查找 kernel32.dll 基地址
    __asm
    {
        mov eax, fs: [0x30] ;     // PEB
        mov eax, [eax + 0x0c];  // LDR
        mov eax, [eax + 0x0c];  // InLoadOrderModuleList
        mov eax, [eax];         // -> ntdll
        mov eax, [eax];         // -> kernel32
        mov ebx, [eax + 0x18];  // kernel32.dll Base Address
        mov hKernel32, ebx;
    }

    // [必要部分: 内联汇编]
    // 模仿成功案例，解析 kernel32.dll 的导出表来查找 GetProcAddress
    __asm
    {
        mov ebx, hKernel32;     // ebx = kernel32.dll Base
        mov edi, [ebx + 0x3c];   // e_lfanew
        add edi, ebx;           // NT Headers VA
        mov edi, [edi + 0x78];   // Export Table RVA
        add edi, ebx;           // Export Table VA

        mov ecx, [edi + 0x20];   // AddressOfNames RVA
        add ecx, ebx;           // Name Table VA
        mov edx, [edi + 0x24];   // AddressOfNameOrdinals RVA
        add edx, ebx;           // Ordinal Table VA
        mov edi, [edi + 0x1c];   // AddressOfFunctions RVA
        add edi, ebx;           // Address Table VA
        xor esi, esi;           // index = 0

    find_gpa_loop:
        mov eax, [ecx + esi * 4];
        add eax, ebx;
        // 比较 "GetProcAddress" (小端)
        cmp dword ptr[eax], 0x50746547;
        jne next_gpa;
        cmp dword ptr[eax + 4], 0x41636f72;
        jne next_gpa;

        // 找到了
        movzx esi, word ptr[edx + esi * 2];
        mov eax, [edi + esi * 4];
        add eax, ebx;
        mov pGetProcAddress, eax;
        jmp found_gpa;

    next_gpa:
        inc esi;
        jmp find_gpa_loop;

    found_gpa:
        // GetProcAddress 地址已存入 pGetProcAddress
    }

    // [C++ 部分]
    // 一旦获得了 GetProcAddress，就立刻回到 C++ 来获取其他所有 API
    if (pGetProcAddress != nullptr)
    {
        pVirtualProtect = (FnVirtualProtect)pGetProcAddress(hKernel32, "VirtualProtect");
    }
}

// 步骤 2: 解密 .text 区段
void DecryptTextSection()
{
    // 检查上一步是否成功
    if (pVirtualProtect == nullptr)
    {
        return; // 如果找不到 API，则无法继续
    }

    // 计算 .text 区段在内存中的地址
    char* pText = (char*)(g_conf.text_rva + 0x400000);
    DWORD textSize = g_conf.text_size;
    DWORD oldProtect = 0;

    // 第一次调用：设置为可读可写
    pVirtualProtect(pText, textSize, PAGE_READWRITE, &oldProtect);

    // 执行解密循环
    for (DWORD i = 0; i < textSize; ++i)
    {
        pText[i] ^= (char)g_conf.key;
    }

    // 第二次调用：恢复原始的内存保护属性
    pVirtualProtect(pText, textSize, oldProtect, &oldProtect);
}

// Stub 的 C++ 主函数
void StubMain()
{
    GetApiAddresses();
    DecryptTextSection();
}

// --- Stub 入口点 ---
// 使用 naked 函数，以便我们干净地调用 C++ 主函数并跳转到 OEP
extern "C" __declspec(dllexport) __declspec(naked) void Start()
{
    __asm
    {
        // 保存所有寄存器状态
        pushad;

        // 调用我们的 C++ 主函数
        call StubMain;

        // 恢复所有寄存器状态
        popad;

        // 跳转到原始入口点 (OEP)
        mov eax, [g_conf + 0]; // g_conf.oep
        add eax, 0x400000;
        jmp eax;
    }
}