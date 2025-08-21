; --- FINAL CORRECTED VERSION: stub_x64.asm ---

; ========================================================================
; ==                     外部和公共符号声明                             ==
; ========================================================================
EXTERN g_conf:BYTE
EXTERN MyGetProcAddress:QWORD
EXTERN MyVirtualProtect:QWORD
EXTERN Decrypt:PROC

PUBLIC g_ImageBase
PUBLIC GetApis
PUBLIC Start

; ========================================================================
; ==                     段定义与实现                                   ==
; ========================================================================

_DATA SEGMENT
    g_ImageBase dq 0
_DATA ENDS

CONST SEGMENT
    virtual_protect_str db 'VirtualProtect', 0
_TEXT SEGMENT

; ------------------------------------------------------------------------
; void GetApis();
; ------------------------------------------------------------------------
GetApis PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 28h

    mov rax, gs:[60h]
    mov rax, [rax + 18h]
    mov rax, [rax + 20h]
    mov rax, [rax]
    mov rax, [rax]
    mov rbx, [rax + 30h]

    mov edx, dword ptr [rbx + 3ch]
    add rdx, rbx

    mov edi, dword ptr [rdx + 88h]
    add rdi, rbx
    
    mov esi, dword ptr [rdi + 20h]
    add rsi, rbx

    xor rcx, rcx

find_getprocaddress_loop:
    mov edx, dword ptr [rsi + rcx * 4]
    add rdx, rbx
    
    ; 使用最原始、最不可能出错的逐字节比较
    cmp byte ptr [rdx], 'G'
    jne next_name
    cmp byte ptr [rdx+1], 'e'
    jne next_name
    cmp byte ptr [rdx+2], 't'
    jne next_name
    cmp byte ptr [rdx+3], 'P'
    jne next_name
    cmp byte ptr [rdx+4], 'r'
    jne next_name
    cmp byte ptr [rdx+5], 'o'
    jne next_name
    cmp byte ptr [rdx+6], 'c'
    jne next_name
    cmp byte ptr [rdx+7], 'A'
    jne next_name
    cmp byte ptr [rdx+8], 'd'
    jne next_name
    cmp byte ptr [rdx+9], 'd'
    jne next_name
    cmp byte ptr [rdx+10], 'r'
    jne next_name
    cmp byte ptr [rdx+11], 'e'
    jne next_name
    cmp byte ptr [rdx+12], 's'
    jne next_name
    cmp byte ptr [rdx+13], 's'
    jne next_name

    ; 找到了 "GetProcAddress"
    mov esi, dword ptr [rdi + 24h]
    add rsi, rbx
    mov cx, word ptr [rsi + rcx * 2]

    mov esi, dword ptr [rdi + 1ch]
    add rsi, rbx

    mov edx, dword ptr [rsi + rcx * 4]
    add rdx, rbx
    mov [MyGetProcAddress], rdx
    jmp found_getprocaddress

next_name:
    inc rcx
    jmp find_getprocaddress_loop

found_getprocaddress:
    mov rcx, rbx
    lea rdx, virtual_protect_str
    call qword ptr [MyGetProcAddress]
    mov [MyVirtualProtect], rax

    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
GetApis ENDP

; ------------------------------------------------------------------------
; void Start();
; ------------------------------------------------------------------------
Start PROC
    lea rax, GetIpLabel
GetIpLabel:
    sub rax, offset GetIpLabel
    mov g_ImageBase, rax

    call GetApis
    call Decrypt

    mov rax, g_ImageBase
    mov ecx, dword ptr [g_conf]
    add rax, rcx
    jmp rax
Start ENDP

_TEXT ENDS
END