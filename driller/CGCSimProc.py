import angr
import simuvex

class DrillerTransmit(simuvex.SimProcedure):
    '''
    CGC's transmit simprocedure which supports errors
    '''

    def run(self, fd, buf, count, tx_bytes):

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            self.state.store_mem(tx_bytes, count, endness='Iend_LE')
            return self.state.se.BVV(0, self.state.arch.bits)

        if ABSTRACT_MEMORY in self.state.options:
            data = self.state.mem_expr(buf, count)
            self.state.posix.write(fd, data, count)

            self.state.store_mem(tx_bytes, count, endness='Iend_LE')

        else:
            if self.state.satisfiable(extra_constraints=[count != 0]):
                data = self.state.mem_expr(buf, count)
                self.state.posix.write(fd, data, count)
                self.data = data
            else:
                self.data = None

            self.size = count
            self.state.store_mem(tx_bytes, count, endness='Iend_LE', condition=tx_bytes != 0)

        # TODO: transmit failure
        transmit_return = self.state.se.BV("transmit_return", self.state.arch.bits)

        self.state.add_constraints(transmit_return >= -1) 
        self.state.add_constraints(transmit_return <= 0)

        return transmit_return

# disable simprocedures for CGC
simprocedures = []
