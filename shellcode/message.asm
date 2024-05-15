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

        jmp .find_short             ; short jump

    .find_ret:
        pop esi                     ; $esi = return addr
        mov [ebp - 0x8], esi        ; var8 = .find_function
        jmp .symbol_kernel32        ; load function from kernel32

    .find_short:
        call .find_ret              ; relative call

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
        cld                         ; DF = 0

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

    .symbol_kernel32:
        push 0x8ee05933             ; TerminateProcess() hash
        call [ebp - 0x8]            ; call .find_function
        mov [ebp - 0xc], eax        ; var12 = ptr to TerminateProcess()

        push 0x583c436c             ; LoadLibraryA() hash
        call [ebp - 0x8]            ; call .find_function

    .load_user32:
        cdq                         ; $edx = 0x0
        mov dx, 0x6c6c              ; "ll"
        push edx                    ; "ll\x00\x00"
        push 0x642e3233             ; "32.d"
        push 0x72657375             ; "user"
        push esp                    ; "user32.dll"
        call eax                    ; call LoadLibraryA()

    .symbol_user32:
        mov ebx, eax                ; $ebx = user32 base

        push 0x1361c78e             ; MessageBoxA() hash
        call [ebp - 0x8]            ; call .find_function

    .call_messageboxa:
        push 0x65                   ; "e"
        push 0x646f636c             ; "lcod"
        push 0x6c656873             ; "shel"
        mov ebx, esp                ; $ebx = "shellcode"

        push 0x65                   ; "e"
        push 0x67617373             ; "ssag"
        push 0x656d2061             ; "a me"
        push 0x20736920             ; " is "
        push 0x73696854             ; "This"
        mov ecx, esp                ; $ecx = "This is a message"

        cdq                         ; $edx = 0x0
        mov dl, 0x41                ; $edx = 0x41
        push edx                    ; uType
        push ebx                    ; lpCaption
        push ecx                    ; lpText
        cdq                         ; $edx = 0x0
        push edx                    ; hWnd
        call eax                    ; call MessageBoxA()

    .exit:
        cdq                         ; $edx = 0x0
        push edx                    ; uExitCode
        push 0xffffffff             ; hProcess
        call [ebp - 0xc]            ; call TerminateProcess()

; shellcode = b"\x89\xe5\x83\xec\x28\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x14\x8b\x36\xad\x8b\x58\x10\xeb\x06\x5e\x89\x75\xf8\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x2f\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x33\x59\xe0\x8e\xff\x55\xf8\x89\x45\xf4\x68\x6c\x43\x3c\x58\xff\x55\xf8\x99\x66\xba\x6c\x6c\x52\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x89\xc3\x68\x8e\xc7\x61\x13\xff\x55\xf8\x6a\x65\x68\x6c\x63\x6f\x64\x68\x73\x68\x65\x6c\x89\xe3\x6a\x65\x68\x73\x73\x61\x67\x68\x61\x20\x6d\x65\x68\x20\x69\x73\x20\x68\x54\x68\x69\x73\x89\xe1\x99\xb2\x41\x52\x53\x51\x99\x52\xff\xd0\x99\x52\x6a\xff\xff\x55\xf4"
