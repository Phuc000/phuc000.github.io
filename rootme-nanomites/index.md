# Rootme ELF x64 - Nanomites Writeups


This challenge teached me some new knowledge so I just wanna write it down.

<!--more-->
## Overview
Nanomite is interesting since it prevents one of my favorite cheap trick: Debugging. Basically the process "father" spawns a "son" subprocess. The father has to attach to the son with debug APIs (on Linux : `ptrace`, on Window: `CreateProcess/DebugActiveProcess`), and you won't be able to attach yourself to the son (DebugBlocker). Also both processes communicate with each other during execution.

## Write Up
First, by looking around we find an interesting part after debug check.

```C
    signal(8, (__sighandler_t)handler);
    return 1 / 0;
```

Sets a custom signal handler for SIGFPE (signal 8)
**signal(8, handler)** ensures that when a SIGFPE occurs, the function **handler** is called, while the statement **1 / 0** raises a SIGFPE signal.

The **handler** load an encrypted function at `loc_400C60` and decrypt it by XOR with `0x42`, so we take the data and XOR with 0x42, then use `HexEd.it` to modify the 199 bytes with our new decrypted function, reopen it on IDA and hit **P** key to make it a readable function, too bad somehow I can't decompile it.

Next, looking back at the parent process there is Signal Handling for:

* Signal 8 (SIGFPE): resume normally

* Signal 11 (SIGSEGV): stand for Segmentation fault, calls `sub_4006EE` to handle the event, then resume

* Signal 5 (SIGTRAP): stand for Breakpoint (int3), calls `sub_4007DC` to handle the breakpoint, then resume

We can see alot of int3 and nop inside the child process, so it is the comumnication method between the parent and the child. The parent call `PTRACE_GETREGS` and `PTRACE_SETREGS` to modify the register of the child, store it inside the 4th argument, I saw on a flare-on challenge that the argument is a struct `user_regs_struct` so we will attempt to change the variable type with **Y** key on IDA.

With the struct now clear, it is very easy to view the exception flows.

```C
    base_addr = off_602090;
    result = ptrace(PTRACE_GETREGS, pid, 0LL, &regs);
    for ( i = 0; i <= 4; ++i )
    {
        result = lookup_table_SIGSEGV[4 * i];
        if ( regs.rip - (_QWORD)base_addr == result )
        {
            result = (unsigned int)v5++ + 1;
            if ( v5 )
            {
                regs.rcx = *(_QWORD *)&lookup_table_SIGSEGV[4 * i + 2];
                regs.rip += 0xALL;
                result = ptrace(PTRACE_SETREGS, pid, 0LL, &regs);
                break;
            }
        }
    }
```

Like the SIGSEGV handler will lookup the `RIP` to determine the 8 bytes data to assign into the register `RCX` that used to compare with the XOR result in the child proc. Meanwhile the SIGTRAP (int3) will lookup the next `RIP` addr to go. 

With that info, the challenge is now clear to solve. Going with the child proc from top down take me to **N0t_The_Fl4g_Sorry**, lol.

So I do some backtrace from the "Good." output and obtain the correct flag.

<!-- **doyoulikenanomite?** -->
