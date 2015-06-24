import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

class DrillerRead(simuvex.SimProcedure):
    ''' 
    A custom version of read which has a symbolic return value.
    '''

    def run(self, fd, dst, length):
        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)

        if self.state.se.max_int(length) == 0:
            return self.state.se.BVV(0, self.state.arch.bits)

        sym_length = self.state.se.BV("sym_length", self.state.arch.bits)
        self.state.add_constraints(sym_length <= length)
        self.state.add_constraints(sym_length >= 0)

        data = self.state.posix.read(fd, length, dst_addr=dst)
        return sym_length

simprocedures = [("read", DrillerRead)]
