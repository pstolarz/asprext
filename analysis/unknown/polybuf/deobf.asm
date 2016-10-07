                         USE32
                         ORG 0x00590000+0x780               ; code base

main_proc:               push ebp
                         mov ebp,esp
                         add esp,byte -0x0c
                         push ebx
                         mov eax, 0x004f7ad4
                         call proc_01CB0BA3
                         mov ebx,0x00505230
                         mov ebx,[ebx]
                         mov eax,[ebx]
                         mov edx,0x004f7724
                         mov edx,dword [edx]
                         mov [eax+0xbc],edx
                         mov dword [eax+0xb8],0x004f53bc
                         mov eax,[ebx]
                         call proc_01CB039C
                         mov eax,[ebx]
                         mov edx,0x004f82a4
                         call 0x00451E44
                         mov ecx,0x00505100
                         mov ecx,[ecx]
                         mov eax,[ebx]
                         mov edx,0x004dc4c4
                         mov edx,[edx]
                         call proc_01CB0592
                         mov ecx,dword [0x005053ac]
                         mov eax,dword [ebx]
                         mov edx,0x004db988
                         mov edx,dword [edx]
                         call proc_01CB0592
                         mov eax,dword [ebx]
                         call 0x004522D8
                         pop ebx
                         call proc_01CB0450
                         push 0x004f8299
                         ret

proc_01CB0BA3:           push eax
                         push byte 0x00
                         call 0x00406A2C
                         mov edx,0x004f9108
                         push edx
                         mov [0x005064dc],eax
                         mov [edx+0x04],eax
                         mov dword [edx+0x08],0x00
                         mov dword [edx+0x0c],0x00
                         call 0x00406AE0
                         pop edx
                         pop eax
                         call 0x00403AAC
                         ret

proc_01CB039C:           push ebx
                         mov eax,0x0050514c
                         mov eax,[eax]
                         cmp dword [eax],0x00
                         je __01CB0573
                         mov ebx,0x0050514c
                         mov ebx, dword [ebx]
                         mov ebx,dword [ebx]
                         call ebx
__01CB0573:              pop ebx
                         ret

proc_01CB0592:           push ebp
                         mov ebp,esp
                         push ecx
                         push ebx
                         push esi
                         push edi
                         mov [ebp-0x04],ecx
                         mov ebx,edx
                         mov esi,eax
                         mov eax,ebx
                         call dword [eax-0x0c]
                         mov ebx,eax
                         mov eax,[ebp-0x04]
                         mov [eax],ebx
                         xor eax,eax
                         push ebp
                         push dword 0x00452296
                         push dword [fs:eax]
                         mov [fs:eax],esp
                         mov ecx,esi
                         or edx,byte -0x01
                         mov eax,ebx
                         mov edi,[eax]
                         call dword [edi+0x2c]                                  ; registration check
                         xor eax,eax
                         pop edx
                         pop ecx
                         pop ecx
                         mov [fs:eax],edx
                         cmp dword [esi+0x38],0x00
                         jnz __01CB0BB0
                         mov eax,ebx
                         mov edx,0x00448378
                         mov edx,[edx]
                         call 0x00403184
                         test al,al
                         je __01CB0BB0
                         mov edi,ebx
                         mov eax,edi
                         call 0x00439488
                         mov [esi+0x38],edi
__01CB0BB0:              pop edi
                         pop esi
                         pop ebx
                         pop ecx
                         pop ebp
                         ret

proc_01CB0450:           push ebx
                         push esi
                         push edi
                         push ebp
                         mov ebx,0x005064a4
                         mov esi,0x00506038
                         mov edi,0x0050603c
                         cmp byte [ebx+0x24],0x00
                         jne __01CB0C50
                         cmp dword [edi],0x00
                         je __01CB0C50
__01CB043A:              mov edx,dword [edi]
                         mov eax,edx
                         xor edx,edx
                         mov [edi],edx
                         mov ebp,eax
                         call ebp
                         cmp dword [edi],0x00
                         jne __01CB043A
__01CB0C50:              cmp dword [0x00506040],0x00
                         jz __01CB0CB1
                         call 0x00403B18
                         cmp byte [0x00506048],0x00
                         je __01CB049C
                         mov edx,0x004f9034
                         mov eax,0x0050621c
                         call 0x00406338
                         call 0x004062BB
                         jmp __01CB0CAA
__01CB049C:              cmp byte [0x004F9010],0x00
                         jne __01CB0CAA
                         push byte 0x00
                         push 0x004f9054
                         push 0x004f9034
                         push byte 0x00
                         call 0x004012A0
__01CB0CAA:              xor eax,eax
                         mov [0x00506040],eax
__01CB0CB1:              cmp byte [ebx+0x24],0x02
                         jne __01CB0D80
                         cmp dword [esi],0x00
                         jne __01CB0D80
                         xor eax,eax
                         mov [ebx+0x0c],eax
__01CB0D80:              call 0x004039EC
                         cmp byte [ebx+0x24],0x01
                         jna __01CB05FC
                         cmp dword [esi],0x00
                         je __01CB0C91
__01CB05FC:              mov eax,[ebx+0x10]
                         test eax,eax
                         jz __01CB0C91
                         call 0x00405BEC
                         mov eax,[ebx+0x10]
                         mov edx,[eax+0x10]
                         cmp edx,[eax+0x04]
                         je __01CB0C91
                         push edx
                         call 0x004012B8
__01CB0C91:              call 0x004039C4
                         cmp byte [ebx+0x24],0x01
                         jne __01CB05F3
                         call dword [ebx+0x28]
__01CB05F3:              cmp byte [ebx+0x24],0x00
                         je __01CB06A1
                         call 0x00403B68
__01CB06A1:              cmp dword [ebx],0x00
                         jne __01CB0C07
                         mov eax,[esi]
                         push eax
                         call 0x00401298
__01CB0C07:              mov eax,[ebx]
                         push esi
                         mov esi,eax
                         mov edi,ebx
                         mov ecx,0x0b
                         rep movsd
                         pop esi
                         jmp __01CB0CB1
; guessed
                         pop ebp
                         pop edi
                         pop esi
                         pop ebx
                         ret
