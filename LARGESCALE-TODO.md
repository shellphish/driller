* solve every single state transition regardless whether or not we have seen it before, use taint tracking to figure out which preconstraints need to be removed

* implement path caching

* audit driller-qemu to ensure the state is being dumped correctly especially that the XMM
registers are being dumped and restored correctly
