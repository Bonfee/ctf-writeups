# Un-machined Aerial System 
## Description

> We've recovered the rom of the crashed drone, and we need to extract a secret value (you'll know it when you see it). However, the rom is a bit wierd, and if you're tools can't understand it, you might have to write your own...  
Do the best you can!

We are given a 64 bit ELF.

```
$ file hard 
hard: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=51272a32b01c5527bab1b8c8b42bea75b45e1539, for GNU/Linux 4.4.0, stripped
```

Running the binary we get the following output:
```
$ ./hard
Fill in the rest of the flag: RS{
```

If we try to enter a wrong flag we get:
```
$ ./hard 
Fill in the rest of the flag: RS{testtest
The inputted flag was RS{testtest}

Sorry, that's not the flag. Try again!
```

This is the decompiled main function.
```c
undefined8 main(void)
{
    void *arg2;
    int64_t iVar1;
    uint64_t uVar2;
    int64_t in_FS_OFFSET;
    uint8_t var_8ah;
    void *ptr;
    int64_t var_80h;
    char *s1;
    int64_t canary;
    int64_t var_8h;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    arg2 = (void *)sym.imp.calloc(0x4000, 1);
    if (arg2 == (void *)0x0) {
        sym.imp.perror("Failed to allocate memory. Aborting...");
    }
    fcn.0000176e(&var_80h, arg2, 0x40a0, (uint64_t)(*(uint32_t *)0x4500 & 0xffff));
    sym.imp.printf("Fill in the rest of the flag: RS{");
    sym.imp.fgets(&s1, 0x14, _reloc.stdin);
    iVar1 = sym.imp.strcspn(&s1, 0x20da);
    *(undefined *)((int64_t)&s1 + iVar1) = 0;
    sym.imp.printf("The inputted flag was RS{%s}\n\n", &s1);
    var_8ah = 0;
    while( true ) {
        uVar2 = sym.imp.strlen(&s1);
        if (uVar2 <= var_8ah) break;
        *(undefined *)((int64_t)arg2 + (int64_t)(int32_t)(var_8ah + 0x80)) =
             *(undefined *)((int64_t)&s1 + (int64_t)(int32_t)(uint32_t)var_8ah);
        var_8ah = var_8ah + 1;
    }
    fcn.000016d8(&var_80h, arg2);
    if (*(char *)((int64_t)arg2 + 0x30) == '\a') {
        sym.imp.puts("YAY, you got the flag!");
    } else {
        sym.imp.puts("Sorry, that\'s not the flag. Try again!");
    }
    sym.imp.free(arg2);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return 0;
}
```

Analyzing the binary we find other functions.
I thought it was not the case to understand what those functions were doing so i just used angr.

```python
#!/usr/bin/env python3
import angr
import claripy

def main():
    p = angr.Project('hard')

    # The flag is 19 characters long
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(19)]

    # Add new line at the end of the flag
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    st = p.factory.full_init_state(
            args=['./hard'],
            add_options=angr.options.unicorn,
            stdin=flag
    )

    # Flag characters must be printable
    for k in flag_chars:
        st.solver.add(k >= 0x21)
        st.solver.add(k <= 0x7e)

    sm = p.factory.simulation_manager(st)
    sm.run()

    # Get the stdout of every path that reached an end
    for pp in sm.deadended:
        out = pp.posix.dumps(1)
        if b'YAY, you got the flag!' in out:
            return 'RS{' + pp.solver.eval(flag, cast_to=bytes).decode().strip() + '}'

    return ''


def test():
    assert main() == "RS{B4bys_1st_VMPr0tect}"


# Runs in ~ 1 minutes
if __name__ == "__main__":
    print(main())
```

Run the script and you get the flag. The script runs in ~1 minute.
```bash
$ python3 solve.py

...

RS{B4bys_1st_VMPr0tect}

```
