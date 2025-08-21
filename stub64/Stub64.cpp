// --- FINAL VERSION: stub.cpp ---

// --- 链接器指令 ---
// 这些指令对于将所有代码和数据合并到一个可读、可写、可执行的区段至关重要。
#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

// --- Windows API 头文件 ---
#include <Windows.h>

// --- 数据结构定义 ---
// 这个结构体是加壳器 (packer) 与存根 (stub) 之间通信的桥梁。
// 加壳器负责填充它, 存根在运行时读取它。
typedef struct _StubConf {
  DWORD oep;       // 原始程序入口点的 RVA (Relative Virtual Address)
  DWORD text_rva;  // 原始程序 .text 区段的 RVA
  DWORD text_size; // 原始程序 .text 区段的大小 (SizeOfRawData)
  DWORD key;       // 用于 XOR 解密的密钥
} StubConf;

// --- 导出的全局配置变量 ---
// 加壳器将通过 GetProcAddress 找到这个变量的地址, 并填充上述信息。
// extern "C" 确保 C++ 编译器不对此变量名进行修饰 (name mangling)。
extern "C" __declspec(dllexport) StubConf g_conf = {0};

// --- 函数指针类型定义 ---
// 为我们将要从 kernel32.dll 中获取的函数定义清晰的类型别名。
typedef void *(WINAPI *FnGetProcAddress)(HMODULE, const char *);
typedef void *(WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

// --- 外部变量声明 ---
// 这些变量的实体在 stub_x64.asm 中定义或被赋值, C++ 代码仅引用它们。
// extern "C" 确保链接器可以正确地将 C++ 代码的引用与汇编代码的定义匹配起来。

// MyGetProcAddress 和 MyVirtualProtect 将由 GetApis (在汇编中实现) 负责填充。
extern "C" FnGetProcAddress MyGetProcAddress;
extern "C" FnVirtualProtect MyVirtualProtect;

// g_ImageBase 是由 Start (在汇编中实现) 在运行时动态计算出的模块基地址。
extern "C" ULONGLONG g_ImageBase;

// --- C++ 函数实现 ---

/**
 * @brief 解密原始程序的 .text 区段。
 * 此函数在 GetApis 成功执行后被调用。
 */
void Decrypt() {
  // [!IMPROVEMENT!] 使用动态获取的 g_ImageBase, 不再硬编码任何地址。
  // 计算 .text 区段在内存中的确切起始地址。
  unsigned char *pText = (unsigned char *)(g_conf.textScnRVA + g_ImageBase);

  // 调用由 GetApis 获取的 VirtualProtect 函数, 将代码段内存临时设为可读写。
  DWORD oldProtection = 0;
  MyVirtualProtect(pText, g_conf.textScnSize, PAGE_READWRITE, &oldProtection);

  // 遍历整个加密的代码段, 用密钥进行逐字节的异或解密。
  for (DWORD i = 0; i < g_conf.textScnSize; i++) {
    pText[i] ^= g_conf.key;
  }

  // 解密完成后, 恢复内存区段原来的保护属性, 这是一个好的安全习惯。
  MyVirtualProtect(pText, g_conf.textScnSize, oldProtection, &oldProtection);
}

// --- 汇编函数外部声明 ---
// 告诉 C++ 编译器, 这两个函数的实现位于其他目标文件中 (我们的 stub_x64.obj)。
// 链接器 (link.exe) 在最后阶段会负责将这些引用链接到实际的函数体。

/**
 * @brief (在汇编中实现) 动态查找 kernel32.dll 并获取所需 API 函数的地址。
 */
extern "C" void GetApis();

/**
 * @brief (在汇编中实现) 程序的真正入口点。
 * 此函数被导出, 加壳器会将 PE 头的 AddressOfEntryPoint 指向它。
 * 它的职责是协调整个脱壳流程。
 */
extern "C" __declspec(dllexport) void Start();
