# ImaginaryCTF_2024 Writeups


Writeup for rev challenges in the event.

<!--more-->
## Overview
The CTF was fun. I had the chance to apply new skills to solve the challenges.

## BF
{{< admonition note "Challenge Information" >}}
* **Given file:** `BF.txt`
* **Description:** Simple equations... but in BF?!!!
{{< /admonition >}}

We are given a Brainfuck source code in text file. Luckily, my friend has a site to execute the code in continuation or one command at a time. I infer that the code take one character at a time, adds it with the number of pluses in the first part multiply with the number of pluses in the second parts then subtracts with the number of minuses in the third part. (I know the real logic is not like that but this is my way of inferring it)

We now do a bit of scripting:

```Python
in_str = "<the BF code goes here>"

# split at [><]
in_str = in_str.split("[><]")
flag = ''

for ele in in_str:
    ele = ele.split("[")
    # count the number of + in the first 2 parts
    first = ele[0].count("+")
    second = ele[1].count("+")
    third = ele[2].count("-") - 1
    # print(first, second, third)
    char = chr(third - first * second)
    # print(char)
    flag += char
    print(flag)
    if flag[-1] == '}':
        break
```

**ictf{1_h4t3_3s0l4ng5_7d4f3a1b}**

## watchdog
{{< admonition note "Challenge Information" >}}
* **Given file:** `watchdog`
* **Description:** The keepers of the Watchdog vault have forgotten their password. Can you help them retrieve it?
{{< /admonition >}}

I heard that there is mathematical way to do it but I'm dumb. Time for some z3

```Python
from z3 import *
import pwn

def flag_to_num(input_string):
    return [ord(char) & 0x7F for char in input_string]

def my_pow(base, exp):
    if exp == 0:
        return 1
    if exp == 1:
        return base
    if exp % 2 == 0:
        half_pow = my_pow(base, exp // 2)
        return half_pow * half_pow
    else:
        return base * my_pow(base, exp - 1)


def solve_for_input(expected_answer, length):
    s = Solver()

    # Create a list of BitVec variables for the input string
    input_vars = [BitVec(f'input_{i}', 64) for i in range(length)]

    # Ensure that each character is a printable ASCII character
    for var in range(length):
        # except for the 5th and last character
        if var != 4 and var != length-1:
            s.add(Or(And(input_vars[var] >= 0x30, input_vars[var] <= 0x39), And(input_vars[var] >= 0x41, input_vars[var] <= 0x5A), And(input_vars[var] >= 0x61, input_vars[var] <= 0x7A), input_vars[var] == ord('_')))

    # the first character is 'ictf{
    s.add(input_vars[0] == ord('i'))
    s.add(input_vars[1] == ord('c'))
    s.add(input_vars[2] == ord('t'))
    s.add(input_vars[3] == ord('f'))
    s.add(input_vars[4] == ord('{'))
    #last character is }
    s.add(input_vars[length-1] == ord('}'))

    # Convert the input variables to coefficients using flag_to_num logic
    coefficients = [var & 0x7F for var in input_vars]
    
    # Evaluate the polynomial
    result_vector = []
    for i in range(2, len(coefficients) + 3):
        result = 0
        n = len(coefficients) - 1
        while n >= 0:
            result += coefficients[n] * my_pow(i, len(coefficients) - 1 - n)
            n -= 1
        result_vector.append(result)
    
    # Add constraints for the expected answer
    for idx, expected in enumerate(expected_answer):
        s.add(result_vector[idx] == expected)

    # Check for a solution
    if s.check() == sat:
        model = s.model()
        input_string = ''.join([chr(model[var].as_long()) for var in input_vars])
        return input_string
    else:
        return None


expected_answer = [
    0x348A627D10659, 0x27485A840365FE61, 0x9E735DADF26D31CD,
    0x82714BC9F9B579D9, 0x3DFB7CC801D16BC9, 0x602A04EFE5DAD659,
    0xEB801D915A30D3D, 0x217DBE10EDCB20A1, 0xADEE2637E875CA19,
    0xCD44AED238E9871, 0xD3BFF76AE6B504D, 0x7181426EFF59E789,
    0x477616CB20C2DAC9, 0xCE1206E1E46CE4A9, 0x946E7CB964A3F87D,
    0x499607CBF0C3291, 0x6871D4372347C759, 0x75412F56B7D8B01,
    0xF8E57C264786E34D, 0x194CA6020EC505B9, 0x3E1A22E34FE84949,
    0xA46DE25172742B79, 0xCD0E971BCBFE6E3D, 0x56561961138A2501,
    0x78D2B538AB53CA19, 0xA9980CA75AB6D611, 0x5F81576B5D4716CD,
    0x17B9860825B93469, 0xC012F75269298349, 0x17373EE9C7A3AAC9,
    0xB2E50798B11E1A7D, 0xADA5A6562E0FD7F1, 0xEC3D9A68F1C99E59,
    0x3D828B35505D79A1, 0xF76E5264F7BD16CD, 0xDD230B3EC48ED399,
    0x80D93363DCD354C9, 0x7031567681E76299, 0x8977338CD4E2A93D,
    0x8A5708A1D4C02B61, 0x2066296A21501019, 0x9E260D94A4D775B1,
    0xE7667BBD72280F4D, 0x12DF4035E1684349
]
input_length = 43 

input_string = solve_for_input(expected_answer, input_length)
if input_string:
    print("Found input string:", input_string)
else:
    print("No solution found")
```

**ictf{i_l0ve_interp0lati0n_2ca38d6ef0a709e0}**

## unconditional
{{< admonition note "Challenge Information" >}}
* **Given file:** `chal`
* **Description:** Can you reverse this flag mangler? 
The output is b4,31,8e,02,af,1c,5d,23,98,7d,a3,1e,b0,3c,b3,c4,a6,06,58,28,19,7d,a3,c0,85,31,68,0a,bc,03,5d,3d,0b

The input only contains lowercase letters, numbers, underscore, and braces .
{{< /admonition >}}

Analyzing the code in IDA, I see that each character in the input is processed and a value is print out idependently, further more the description said the input only contains lowercase letters, numbers, underscore, and braces. That means I should brute force it.

```Python
import itertools

# Initialize global variables to simulate the state
counter1 = 0
counter2 = 0

# Placeholder data for table1 and table2
# These should be set according to the actual values used in your original code
table1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76]
#  1, 3, 4, 2, 6, 5 
table2 = [1, 3, 4, 2, 6, 5]

# Expected output for each character in hex format
expected_output = [0xb4,0x31,0x8e,0x02,0xaf,0x1c,0x5d,0x23,0x98,0x7d,0xa3,0x1e,0xb0,0x3c,0xb3,0xc4,0xa6,0x06,0x58,0x28,0x19,0x7d,0xa3,0xc0,0x85,0x31,0x68,0x0a,0xbc,0x03,0x5d,0x3d,0x0b]
  # Replace with actual expected outputs

# The flag array
flag = [0] * 33

def iterate(a1):
    global counter1, counter2

    v3 = flag[a1]
    v4 = (a1 & 1) != 0
    v1 = 97 <= v3 <= 122

    if v1:
        rotated_value = (v3 >> table2[counter2] | (v3 << (8 - table2[counter2]))) & 0xFF
        new_value = rotated_value
    else:
        rotated_value = ((v3 << 6) | (v3 >> 2)) & 0xFF
        new_value = rotated_value ^ table1[counter1]

    if (a1 & 1) == 0:
        flag[a1] = new_value
    else:
        if v1:
            flag[a1] = v3 ^ table1[counter1]
        else:
            flag[a1] = ((4 * v3) | (v3 >> 6)) & 0xFF

    counter1 = (v4 + counter1) % 6
    counter2 = (v4 + counter2) % 6

    return flag[a1]

pre_counter1 = 0
pre_counter2 = 0

def brute_force_flag():
    global counter1, counter2
    global pre_counter1, pre_counter2
    x = ""

    for a1 in range(33):
        # guess only  lowercase letters, numbers, underscore, and braces 
        for guess in itertools.chain(range(48, 58), [95], range(97, 123), [123], [125]):
            flag[a1] = guess
            # counter1, counter2 = 0, 0  # Reset counters
            output = iterate(a1)
            if output == expected_output[a1]:
                print(f"Character {a1}: {chr(guess)}")
                pre_counter1 = counter1
                pre_counter2 = counter2
                x += chr(guess)
                break
            else:
                counter1, counter2 = pre_counter1, pre_counter2
    print(f"Flag: {x}")


# Call the brute force function
brute_force_flag()
```

**ictf{m0r3_than_1_ways_t0_c0n7r0l}**

## Absolute Flag Checker
{{< admonition note "Challenge Information" >}}
* **Given file:** `absolute flag checker.exe`
* **Description:** What's easier way than verifying flag contents more times than required?
{{< /admonition >}}

That's a lot of code in main. The code perform many "If" by adding and multiplying 47 characters of the flag (v52 to v98). I personally don't know any better ways to solve this. I just copy the whole logic and try to strip it "if" by "if" have z3 do the job. 

```Python
#open file save.txt and read it content
from z3 import *

# Create a solver instance
s = Solver()

# Define the flag variable as a list of 47 BitVec elements
flag = [BitVec(f"v{i}", 8) for i in range(52, 99)]

s.add(flag[0] == ord('i'))
s.add(flag[1] == ord('c'))
s.add(flag[2] == ord('t'))
s.add(flag[3] == ord('f'))
s.add(flag[4] == ord('{'))
s.add(flag[46] == ord('}'))

f = open("save.txt", "r")

content = f.read()


equation = content.split("{")
# remove final element
equation.pop()
# print(equation[0])

for element in equation:
    temp = element.split("if")
    number_part = temp[0]
    condition_part = temp[1]
    number_part = number_part.split("=")
    special_shit = 0
    if len(number_part) == 3:
        special_shit = 1
        number_part = number_part[2]
    else:
        number_part = number_part[1]
    number_part = number_part.split(";")[0]
    number_part = number_part.strip()
    number_part = number_part.split("+")
    # strip all whitespace
    number_part = [x.strip() for x in number_part]
    v = 0
    for i in range(len(number_part)):
        # if there is << in the string
        if "<<" in number_part[i]:
            small_part = number_part[i][1:-1].split("<<")
            # ['0x1E7 ', ' v82']
            # strip all whitespace
            small_part = [x.strip() for x in small_part]
            # ['0x1E7', 'v82']
            # parse the first element to int
            small_part[1] = int(small_part[1])
            # get number in the second element
            # if the second element is flag
            if small_part[0] == "flag":
                # z3 shift left operator
                v += flag[0] << small_part[1]
            else:
                v += flag[int(small_part[0][1:]) - 52] << small_part[1]
            continue
        small_part = number_part[i].split("*")
        # ['0x1E7 ', ' v82']
        # strip all whitespace
        small_part = [x.strip() for x in small_part]
        if len(small_part) == 1:
            if special_shit:
                v += 0x60 * flag[0] + 0x306 * flag[1]
            else:
                v += flag[int(small_part[0][1:]) - 52]
            continue
        # ['0x1E7', 'v82']
        # parse the first element to int
        small_part[0] = int(small_part[0], 16)
        # get number in the second element
        # if the second element is flag
        if small_part[1] == "flag":
            v += small_part[0] * flag[0]
        else:
            v += small_part[0] * flag[int(small_part[1][1:]) - 52]
    

    # condition part
    condition_part = condition_part.strip()
    # remove the first character and the last character
    condition_part = condition_part[1:-1]
    # split the condition part
    condition_part = condition_part.split("==")
    # strip all whitespace
    condition_part = [x.strip() for x in condition_part]
    # parse the second element to int
    condition_part[1] = int(condition_part[1], 16)
    final_value = condition_part[1]
    condition_part[0] = condition_part[0].split("+")
    # strip all whitespace
    condition_part[0] = [x.strip() for x in condition_part[0]]
    # print(condition_part[0])
    final_equation = 0
    for i in range(len(condition_part[0])):
        # if there is << in the string
        if "<<" in condition_part[0][i]:
            small_part = condition_part[0][i][1:-1].split("<<")
            # ['0x1E7 ', ' v82']
            # strip all whitespace
            small_part = [x.strip() for x in small_part]
            # ['0x1E7', 'v82']
            # parse the first element to int
            small_part[1] = int(small_part[1])
            # get number in the second element
            # if the second element is flag
            if small_part[0] == "flag":
                # z3 shift left operator
                final_equation += flag[0] << small_part[1]
            else:
                final_equation += flag[int(small_part[0][1:]) - 52] << small_part[1]
            continue
        small_part = condition_part[0][i].split("*")
        # ['0x1E7 ', ' v82']
        # strip all whitespace
        small_part = [x.strip() for x in small_part]
        # ['0x1E7', 'v82']
        # parse the first element to int
        if len(small_part) == 2:
            small_part[0] = int(small_part[0], 16)
        # get number in the second element
        # if the second element is flag
        if len(small_part) == 1:
            final_equation += v
        else:
            final_equation += small_part[0] * flag[int(small_part[1][1:]) - 52]
    s.add(final_equation == final_value)


if s.check() == sat:
    model = s.model()
    result = [model.evaluate(flag[i]) for i in range(47)]
    # create a string from the result
    result = "".join([chr(int(str(result[i]))) for i in range(47)])
    print("Solution found:", result)
else:
    print("No solution found")
```

**ictf{that_is_a_lot_of_equations_n2u1iye21azl21}**

## SVM Revenge
{{< admonition note "Challenge Information" >}}
* **Given file:** `svm_revenge`, `output.bin`
* **Description:** As foretold, the revenge of SVM from round 46 is here!
{{< /admonition >}}

The code seem confusing at first but it really just pushing and poping two queues, with the queue containing flag segment being dumped out in output.bin. Z3 should do the magic.

```Python
from z3 import *

# Create a solver instance
s = Solver()

# Define the flag variable as a list of 47 BitVec elements
flag = [BitVec(f"v{i}", 8) for i in range(64)]

s.add(flag[0] == ord('i'))
s.add(flag[1] == ord('c'))
s.add(flag[2] == ord('t'))
s.add(flag[3] == ord('f'))
s.add(flag[4] == ord('{'))
s.add(flag[63] == ord('}'))

instructions = [
    "copy the instruction from IDA"
]

#open output.bin file and read it
output = open("output/output.bin", "rb")
output = output.read()
print("output.bin file: ", output)

a128 = flag[0:16]


def perform(a128, array, ins1, ins2):
    if ins1 == 1:
        v9 = a128.pop(0)
        v6 = a128.pop(0)
        a128.insert(len(a128), (v6 * v9) & 0xff)
    elif ins1 == 2:
        a128.insert(len(a128), array[ins2])
    elif ins1 == 3:
        v8 = a128.pop(0)
        v5 = a128.pop(0)
        a128.insert(len(a128), (v8 + v5) & 0xff)
    elif ins1 == 4:
        v7 = a128.pop(0)
        array[ins2] = v7
    elif ins1 == 5:
        a128.insert(len(a128), ins2)
        


def obfuscate(flag_segment):
    a128 = flag_segment[0:16]
    temp = [0] * 999
    for i in range(0, len(instructions), 2):
        perform(a128, temp, instructions[i], instructions[i+1])
    return a128

for i in range(0, len(flag), 16):
    segment = flag[i:i+16]
    result = obfuscate(segment)
    for j in range(16):
        s.add(result[j] == output[i+j])
    

if s.check() == sat:
    model = s.model()
    result = [model.evaluate(flag[i]) for i in range(64)]
    # create a string from the result
    result = "".join([chr(int(str(result[i]))) for i in range(64)])
    print("Solution found:", result)
else:
    print("No solution found")
```

**ictf{S_d1dnt_5t4nd_f0r_5t4ck_b3c4u53_h3r3_I_us3d_4_L1nk3d_qu3u3}**
