// --- FINAL, CORRECTED, AND COMPLETE VERSION: packer.cpp ---

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <system_error>
#include <cstdint>
#include <variant>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winnt.h>

using byte_vector = std::vector<std::byte>;
constexpr std::string_view kNewSectionName = ".stub";
constexpr std::byte kXorKey{ 0x15 };

typedef struct _StubConf {
    DWORD oep;
    DWORD text_rva;
    DWORD text_size;
    DWORD key;
} StubConf;

class PeException : public std::system_error {
public:
    PeException(const std::string& msg, const std::error_code& ec) : std::system_error(ec, msg) {}
    PeException(const std::string& msg) : std::system_error({}, msg) {}
};

struct HandleDeleter {
    using pointer = HANDLE;
    void operator()(HANDLE handle) const { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};
using UniqueHandle = std::unique_ptr<HANDLE, HandleDeleter>;

struct LibraryDeleter {
    using pointer = HMODULE;
    void operator()(HMODULE handle) const { if (handle) FreeLibrary(handle); }
};
using UniqueLibrary = std::unique_ptr<HMODULE, LibraryDeleter>;

struct StubInfo {
    UniqueLibrary module;
    uintptr_t base_address = 0;
    DWORD text_rva = 0;
    DWORD text_size = 0;
    uintptr_t start_proc_address = 0;
    StubConf* g_conf_ptr = nullptr; // [!!! 关键修正 !!!] 直接保存 g_conf 的指针
};

template<typename T, typename U> T* PtrAdd(U* base, size_t offset) {
    return reinterpret_cast<T*>(reinterpret_cast<std::byte*>(base) + offset);
}
template<typename T, typename U> const T* PtrAdd(const U* base, size_t offset) {
    return reinterpret_cast<const T*>(reinterpret_cast<const std::byte*>(base) + offset);
}

class PeHeaders {
    // ... 您的 PeHeaders 类无需修改，原样保留 ...
public:
    enum class PeFormat { PE32, PE32_PLUS };
    std::variant<IMAGE_NT_HEADERS32*, IMAGE_NT_HEADERS64*> nt_headers_;

    explicit PeHeaders(byte_vector& pe_data) : pe_data_(pe_data) {
        dos_header_ = GetDosHeaderInternal(pe_data_);
        auto nt_headers_common = PtrAdd<const IMAGE_NT_HEADERS>(dos_header_, dos_header_->e_lfanew);
        if (nt_headers_common->Signature != IMAGE_NT_SIGNATURE) throw PeException("Invalid NT signature");

        if (nt_headers_common->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            format_ = PeFormat::PE32;
            nt_headers_ = PtrAdd<IMAGE_NT_HEADERS32>(dos_header_, dos_header_->e_lfanew);
        }
        else if (nt_headers_common->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            format_ = PeFormat::PE32_PLUS;
            nt_headers_ = PtrAdd<IMAGE_NT_HEADERS64>(dos_header_, dos_header_->e_lfanew);
        }
        else {
            throw PeException("Unsupported PE format");
        }
    }

    PeFormat GetFormat() const { return format_; }
    ULONGLONG GetImageBase() const { return std::visit([](auto* p) { return static_cast<ULONGLONG>(p->OptionalHeader.ImageBase); }, nt_headers_); }
    DWORD GetAddressOfEntryPoint() const { return std::visit([](auto* p) { return p->OptionalHeader.AddressOfEntryPoint; }, nt_headers_); }
    void SetAddressOfEntryPoint(DWORD oep) { std::visit([oep](auto* p) { p->OptionalHeader.AddressOfEntryPoint = oep; }, nt_headers_); }
    DWORD GetSizeOfImage() const { return std::visit([](auto* p) { return p->OptionalHeader.SizeOfImage; }, nt_headers_); }
    void SetSizeOfImage(DWORD size) { std::visit([size](auto* p) { p->OptionalHeader.SizeOfImage = size; }, nt_headers_); }
    DWORD GetFileAlignment() const { return std::visit([](auto* p) { return p->OptionalHeader.FileAlignment; }, nt_headers_); }
    DWORD GetSectionAlignment() const { return std::visit([](auto* p) { return p->OptionalHeader.SectionAlignment; }, nt_headers_); }
    void DisableAslr() { std::visit([](auto* p) { p->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE; }, nt_headers_); }
    IMAGE_FILE_HEADER& GetFileHeader() { return std::visit([](auto* p) -> IMAGE_FILE_HEADER& { return p->FileHeader; }, nt_headers_); }
    const IMAGE_FILE_HEADER& GetFileHeader() const { return std::visit([](auto* p) -> const IMAGE_FILE_HEADER& { return p->FileHeader; }, nt_headers_); }
    IMAGE_SECTION_HEADER* GetFirstSectionHeader() { return std::visit([](auto* p) { return IMAGE_FIRST_SECTION(p); }, nt_headers_); }
    const IMAGE_SECTION_HEADER* GetFirstSectionHeader() const { return std::visit([](auto* p) { return IMAGE_FIRST_SECTION(p); }, nt_headers_); }
    const IMAGE_SECTION_HEADER* GetSectionHeader(std::string_view name) const {
        auto* section = GetFirstSectionHeader();
        for (WORD i = 0; i < GetFileHeader().NumberOfSections; ++i, ++section) {
            if (strncmp(reinterpret_cast<const char*>(section->Name), name.data(), IMAGE_SIZEOF_SHORT_NAME) == 0) return section;
        }
        return nullptr;
    }
private:
    static IMAGE_DOS_HEADER* GetDosHeaderInternal(byte_vector& data) {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) throw PeException("File too small for DOS header");
        auto* header = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
        if (header->e_magic != IMAGE_DOS_SIGNATURE) throw PeException("Invalid DOS signature");
        return header;
    }
    byte_vector& pe_data_;
    PeFormat format_;
    IMAGE_DOS_HEADER* dos_header_ = nullptr;
};

[[nodiscard]] UniqueHandle OpenFile(std::string_view file_path, bool write = false) {
    DWORD access = write ? GENERIC_WRITE : GENERIC_READ;
    DWORD creation = write ? CREATE_ALWAYS : OPEN_EXISTING;
    HANDLE handle = CreateFileA(file_path.data(), access, FILE_SHARE_READ, nullptr, creation, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw PeException("Failed to open file", std::error_code(GetLastError(), std::system_category()));
    return UniqueHandle(handle);
}

byte_vector ReadFileData(HANDLE file_handle) {
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file_handle, &size)) throw PeException("Failed to get file size", std::error_code(GetLastError(), std::system_category()));
    byte_vector buffer(static_cast<size_t>(size.QuadPart));
    DWORD bytes_read = 0;
    if (!ReadFile(file_handle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr) || bytes_read != buffer.size()) {
        throw PeException("Failed to read file", std::error_code(GetLastError(), std::system_category()));
    }
    return buffer;
}

void SavePeFile(const byte_vector& data, std::string_view path) {
    UniqueHandle file = OpenFile(path, true);
    DWORD bytes_written;
    if (!WriteFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &bytes_written, nullptr) || bytes_written != data.size()) {
        throw PeException("Failed to write to file", std::error_code(GetLastError(), std::system_category()));
    }
}

DWORD AlignValue(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

void EncryptTextSection(PeHeaders& headers, byte_vector& pe_data) {
    const auto* text_section = headers.GetSectionHeader(".text");
    if (!text_section) { return; }
    // [!!! 关键修正 !!!] 加密长度和解密长度必须一致，都使用 VirtualSize
    DWORD size_to_encrypt = text_section->Misc.VirtualSize;
    if (text_section->PointerToRawData + size_to_encrypt > pe_data.size()) {
        throw PeException(".text section data (VirtualSize) extends beyond file bounds");
    }
    std::byte* text_data = PtrAdd<std::byte>(pe_data.data(), text_section->PointerToRawData);
    for (DWORD i = 0; i < size_to_encrypt; ++i) {
        text_data[i] ^= kXorKey;
    }
}

// [!!! 修正后的 LoadStubInfo !!!]
StubInfo LoadStubInfo(PeHeaders::PeFormat format) {
    const char* stub_dll_name = (format == PeHeaders::PeFormat::PE32) ? "Stub32.dll" : "Stub64.dll";
    StubInfo si;
    HMODULE handle = LoadLibraryExA(stub_dll_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!handle) throw PeException(std::string("Failed to load ") + stub_dll_name, std::error_code(GetLastError(), std::system_category()));

    si.module = UniqueLibrary(handle);
    si.base_address = reinterpret_cast<uintptr_t>(si.module.get());

    auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(si.base_address);
    auto* nt_headers = PtrAdd<const IMAGE_NT_HEADERS32>(dos_header, dos_header->e_lfanew);

    const IMAGE_SECTION_HEADER* text_section = nullptr;
    auto* current_section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++current_section) {
        if (strncmp(reinterpret_cast<const char*>(current_section->Name), ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            text_section = current_section;
            break;
        }
    }
    if (!text_section) throw PeException(".text section not found in stub DLL");

    si.text_rva = text_section->VirtualAddress;
    si.text_size = text_section->SizeOfRawData; // 复制时使用文件对齐后的大小
    si.start_proc_address = reinterpret_cast<uintptr_t>(GetProcAddress(si.module.get(), "Start"));

    si.g_conf_ptr = reinterpret_cast<StubConf*>(GetProcAddress(si.module.get(), "g_conf"));
    if (!si.g_conf_ptr) throw PeException("'g_conf' variable not found in stub DLL");

    return si;
}

// --- [!!! 最终正确版 !!!] ---
void FixStubRelocationsInMemory(
    HMODULE stub_module_base,
    DWORD stub_text_rva,
    DWORD target_image_base,
    DWORD new_section_rva
) {
    auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stub_module_base);
    auto* nt_headers = PtrAdd<IMAGE_NT_HEADERS32>(dos_header, dos_header->e_lfanew);

    const auto& reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) return;

    auto* p_reloc = PtrAdd<IMAGE_BASE_RELOCATION>(dos_header, reloc_dir.VirtualAddress);
    const auto* reloc_end = PtrAdd<const IMAGE_BASE_RELOCATION>(p_reloc, reloc_dir.Size);

    while (p_reloc < reloc_end && p_reloc->SizeOfBlock > 0) {
        DWORD count = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* p_entries = PtrAdd<WORD>(p_reloc, sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; ++i) {
            if ((p_entries[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* p_fix_addr = PtrAdd<DWORD>(dos_header, p_reloc->VirtualAddress + (p_entries[i] & 0x0FFF));

                DWORD old_protect;
                if (!VirtualProtect(p_fix_addr, sizeof(DWORD), PAGE_READWRITE, &old_protect)) {
                    throw PeException("Failed to make stub memory writable for relocation", std::error_code(GetLastError(), std::system_category()));
                }

                *p_fix_addr -= reinterpret_cast<DWORD>(stub_module_base);
                *p_fix_addr -= stub_text_rva;
                *p_fix_addr += target_image_base;
                *p_fix_addr += new_section_rva;

                VirtualProtect(p_fix_addr, sizeof(DWORD), old_protect, &old_protect);
            }
        }
        p_reloc = PtrAdd<IMAGE_BASE_RELOCATION>(p_reloc, p_reloc->SizeOfBlock);
    }
}

// --- [!!! 全面修正的函数 !!!] ---
void ImplantStub(byte_vector& pe_data) {
    DWORD original_oep = 0;
    DWORD text_section_rva = 0, text_section_size = 0;
    DWORD last_section_va = 0, last_section_vsize = 0;
    DWORD last_section_raw_ptr = 0, last_section_raw_size = 0;
    DWORD file_alignment = 0, section_alignment = 0;
    DWORD image_base = 0;
    PeHeaders::PeFormat format;

    {
        PeHeaders headers(pe_data);
        format = headers.GetFormat();
        original_oep = headers.GetAddressOfEntryPoint();
        file_alignment = headers.GetFileAlignment();
        section_alignment = headers.GetSectionAlignment();
        image_base = static_cast<DWORD>(headers.GetImageBase());

        const auto* text_sec = headers.GetSectionHeader(".text");
        if (!text_sec) throw PeException("Target PE has no .text section");
        text_section_rva = text_sec->VirtualAddress;
        text_section_size = text_sec->Misc.VirtualSize;

        const auto* last_sec = headers.GetFirstSectionHeader() + (headers.GetFileHeader().NumberOfSections - 1);
        last_section_va = last_sec->VirtualAddress;
        last_section_vsize = last_sec->Misc.VirtualSize;
        last_section_raw_ptr = last_sec->PointerToRawData;
        last_section_raw_size = last_sec->SizeOfRawData;

        std::visit([&](auto* nt_headers) {
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            }, headers.nt_headers_);
    }

    StubInfo si = LoadStubInfo(format);

    // 关键步骤 1: 直接在内存中填充 g_conf
    std::cout << "  Filling g_conf in stub's memory...\n";
    si.g_conf_ptr->oep = original_oep;
    si.g_conf_ptr->text_rva = text_section_rva;
    si.g_conf_ptr->text_size = text_section_size;
    si.g_conf_ptr->key = static_cast<DWORD>(kXorKey);

    DWORD new_section_virtual_size = si.text_size; // 使用stub的原始大小
    DWORD new_section_raw_size = AlignValue(new_section_virtual_size, file_alignment);
    DWORD new_section_raw_ptr = AlignValue(last_section_raw_ptr + last_section_raw_size, file_alignment);
    DWORD new_section_rva = AlignValue(last_section_va + last_section_vsize, section_alignment);

    // 关键步骤 2: 直接在加载的 stub 模块内存中进行修复
    std::cout << "  Fixing stub relocations in memory...\n";
    FixStubRelocationsInMemory(reinterpret_cast<HMODULE>(si.base_address), si.text_rva, image_base, new_section_rva);

    pe_data.resize(new_section_raw_ptr + new_section_raw_size);
    PeHeaders new_headers(pe_data);
    auto& new_file_header = new_headers.GetFileHeader();
    auto* new_section_header_ptr = new_headers.GetFirstSectionHeader() + new_file_header.NumberOfSections;

    memcpy(new_section_header_ptr->Name, kNewSectionName.data(), kNewSectionName.size());
    new_section_header_ptr->Misc.VirtualSize = new_section_virtual_size;
    new_section_header_ptr->VirtualAddress = new_section_rva;
    new_section_header_ptr->SizeOfRawData = new_section_raw_size;
    new_section_header_ptr->PointerToRawData = new_section_raw_ptr;
    new_section_header_ptr->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

    new_file_header.NumberOfSections++;
    new_headers.SetSizeOfImage(AlignValue(new_section_rva + new_section_virtual_size, section_alignment));

    // 关键步骤 3: 从【修复并填充好数据】的 stub 内存镜像中复制 .text 区段
    const std::byte* stub_code_src = PtrAdd<const std::byte>(reinterpret_cast<void*>(si.base_address), si.text_rva);
    std::byte* new_section_dest = PtrAdd<std::byte>(pe_data.data(), new_section_raw_ptr);
    memcpy(new_section_dest, stub_code_src, new_section_virtual_size);

    uintptr_t start_rva_in_stub = si.start_proc_address - si.base_address;
    DWORD start_offset_in_text = static_cast<DWORD>(start_rva_in_stub - si.text_rva);
    new_headers.SetAddressOfEntryPoint(new_section_rva + start_offset_in_text);

    new_headers.DisableAslr();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PE file>\n";
        return 1;
    }
    try {
        const std::string target_file = argv[1];
        std::cout << "Packing " << target_file << "...\n";
        UniqueHandle file_handle = OpenFile(target_file);
        byte_vector pe_data = ReadFileData(file_handle.get());
        file_handle.reset();

        {
            PeHeaders headers(pe_data);
            std::cout << "Original entry point: 0x" << std::hex << headers.GetAddressOfEntryPoint() << std::dec << "\n";
            std::cout << "Encrypting .text section...\n";
            EncryptTextSection(headers, pe_data);
        }

        std::cout << "Implanting stub...\n";
        ImplantStub(pe_data);

        {
            PeHeaders new_headers(pe_data);
            std::cout << "New entry point: 0x" << std::hex << new_headers.GetAddressOfEntryPoint() << std::dec << "\n";
        }

        std::string packed_file = "packed_" + target_file;
        std::cout << "Saving packed file to " << packed_file << "...\n";
        SavePeFile(pe_data, packed_file);
        std::cout << "Packing completed successfully!\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}