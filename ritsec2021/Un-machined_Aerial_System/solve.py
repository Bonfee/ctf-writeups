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
