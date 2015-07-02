* Add stricter checks for whether a state transition is worth dumping
    - Along with this a new experimental feature for keeping track of which state transitions AFL has
      trouble getting through, these could be found by looking at which state transitions we drilled
      into and seeing how many AFL inputs were able to build on top of these drilled inputs 
      successfully.

* Make driller spin up smarter
    - Do fuzzer syncing before invoking driller, if fuzzer syncing brings in a new, interesting input
      don't invoke driller

* Add timeout to QEMU tracing for binaries which don't terminate

* Make sure unconstrained dumping is working

* Use taint tracking to speed up tracing

* test cases for driller

* add binaries to angr repo

* Integrate with angr's logging
