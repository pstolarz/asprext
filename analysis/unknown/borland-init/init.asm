                        USE32

destructors:            push eax
                        push 4
                        jmp main
                        db 0x90,0x90,0x90           ; padding
constructors:           push eax                    ; offset: 0x08
                        push 0
main:                   call $+5
                        pop eax
                        add eax, init_tab-main-5
                        add [esp], eax
next:                   mov eax, [esp]
                        mov eax,[eax]
                        test eax, eax
                        je finish
                        add eax, destructors        ; base of code
                        call eax
                        add dword [esp], 8
                        jmp next
finish:                 pop eax
                        pop eax
                        ret
init_tab:               dd 0, 0                     ; offset: 0x30
