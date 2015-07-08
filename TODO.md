* Make qemu's and angr's randomness deterministic and the same

* Ditch tracing if it we've been tracing a while and we've already found some inputs

* Add detection of inputs AFL has trouble mutating

* Make driller spin up smarter
    - Do fuzzer syncing before invoking driller, if fuzzer syncing brings in a new, interesting input
      don't invoke driller

* Add timeout to QEMU tracing for binaries which don't terminate

* Make sure unconstrained dumping is working

* Use taint tracking to speed up tracing

* test cases for driller

* add binaries to angr repo
