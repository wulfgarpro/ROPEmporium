from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = b"XXX"
p = process(bin)
gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

payload = b""

p.sendafter(b"> ", payload)
p.recvall()
