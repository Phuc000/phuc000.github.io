# HTB CTF 2026 Writeups


Writeup for **some** rev challenges in the event.

<!--more-->
## Overview
Better not get myself rusty so I participated in this year HTB together with my company team. Too bad work was so stressful I had to settle with 2 challenges.

## Cinderbound
{{< admonition note "Challenge Information" >}}
* **Given file:** `cinderbound.mpy`
{{< /admonition >}}

Warm up. Dump into bytecode with [Micropython](https://github.com/micropython/micropython) 
```Powershell
python3 mpy-tool.py -d cinderbound.mpy 
```

We obtain the easily encrypted code and we can obtain the flag by doing the reverse rotation.

```Python
TARGET = [
    57,129,154,31,
    199,192,73,243,
    43,176,255,173,
    54,203,67,15,
]

state = 90
flag = []

for i, enc in enumerate(TARGET):
    ch = enc ^ state ^ ((13 * i) & 0xff)
    flag.append(chr(ch))
    state = (state + ch) & 0xff

print("".join(flag))
```

**HTB{c1nd3rbound_v0w5}**

## Ringtrue
{{< admonition note "Challenge Information" >}}
* **Given file:** `ringtrue`
{{< /admonition >}}

okay I really had fun with this one. It makes me remember my Introduction to AI class.
The program required us to input 8 numbers. The code do something akin to a vector transformation and compare to static data **ECHO_S**, welp time for z3 to shine upon us once more. We just need to mimic the logic of what is done.

One of the issue I saw was how to dump the data from IDA with correct format. And this script might be useful for future dumping.

```Python
import struct
import json

def read_i8(addr, n):
    return list(struct.unpack(
        f"<{n}b",
        get_bytes(addr, n)
    ))

def read_i32(addr, n):
    return list(struct.unpack(
        f"<{n}i",
        get_bytes(addr, n * 4)
    ))

def read_i64(addr, n):
    return list(struct.unpack(
        f"<{n}q",
        get_bytes(addr, n * 8)
    ))

def matrix8(x):
    return [
        x[i:i + 8]
        for i in range(0, len(x), 8)
    ]

layers = {}

# 8x8 signed int8 weights
for name in [
    "L0_W",
    "L1_W",
    "L2_W"
]:
    addr = get_name_ea_simple(name)

    print(name, hex(addr))

    layers[name] = matrix8(
        read_i8(addr, 64)
    )

# 8 signed int32 biases
for name in [
    "L0_B",
    "L1_B",
    "L2_B"
]:
    addr = get_name_ea_simple(name)

    print(name, hex(addr))

    layers[name] = read_i32(addr, 8)

# 8 signed int64 values
addr = get_name_ea_simple("ECHO_S")

print("ECHO_S", hex(addr))

layers["ECHO_S"] = read_i64(addr, 8)

print(json.dumps(
    layers,
    indent=4
))
```

Now onto the solver using value obtained from the dumper.

```Python
from z3 import *

L0_W = [
    [5,13,10,14,1,0,-15,12],
    [4,4,3,1,11,-3,-10,-1],
    [10,3,1,-11,-12,5,12,14],
    [10,2,3,7,7,-6,-1,-4],
    [16,10,-10,12,5,6,2,-5],
    [15,-1,-7,-3,9,7,1,-5],
    [6,-12,-8,-10,0,7,-15,15],
    [4,-9,-4,12,-4,16,15,5]
]

L1_W = [
    [14,-1,13,-3,-15,10,1,-14],
    [16,16,12,-7,14,5,-8,-7],
    [-2,3,7,15,-12,11,1,12],
    [-9,-8,-14,-2,-3,3,-1,0],
    [-11,-13,6,7,-3,-4,0,16],
    [-4,2,-4,11,16,-10,5,-5],
    [-8,-4,1,8,3,-14,-12,6],
    [-13,-12,5,13,14,-15,15,5]
]

L2_W = [
    [9,-15,0,-16,2,-15,6,-6],
    [8,0,-5,-4,-1,10,-7,3],
    [-9,-15,-14,-7,-5,-4,-11,9],
    [9,-9,15,13,1,-8,1,-3],
    [-13,9,-8,4,-16,11,11,12],
    [-10,-12,-1,-10,-1,11,6,-4],
    [6,-4,-5,-13,-3,8,6,-4],
    [-2,-12,-15,4,16,-9,13,-13]
]

L0_B = [
    541,-548,1968,1610,68,-1078,-42,-2020
]

L1_B = [
    -1709,704,1565,304,-209,1690,-1151,245
]

L2_B = [
    506,-234,1551,1479,1058,1130,1320,330
]

ECHO_S = [1542223, 574187, -2694563, -3518303, 383776, 576877, 2637871, -2518822]

def dense_z3(W,B,x):

    result=[]

    for i in range(8):

        value=B[i]

        for j in range(8):
            value += W[i][j]*x[j]

        result.append(value)

    return result

def activate_z3(values):

    return [
        If(v < 0, v*2, v)
        for v in values
    ]

x=[
    Int(f"x{i}")
    for i in range(8)
]

solver=Solver()

for v in x:
    solver.add(v >= -2147483648)
    solver.add(v <= 2147483647)

y1=dense_z3(L0_W,L0_B,x)
y1=activate_z3(y1)

y2=dense_z3(L1_W,L1_B,y1)
y2=activate_z3(y2)

y3=dense_z3(L2_W,L2_B,y2)

for i in range(8):
    solver.add(
        y3[i]==ECHO_S[i]
    )

print(solver.check())


if solver.check()==sat:

    model=solver.model()

    solution=[
        model[x[i]]
        for i in range(8)
    ]

    print(solution)

    # 83 97 108 116 67 114 119 110
```

**HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}**
