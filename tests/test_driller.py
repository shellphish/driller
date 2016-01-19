import nose
import driller

import logging
l = logging.getLogger("driller.tests.test_driller")

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

def test_drilling_cgc():
    '''
    test drilling on the cgc binary, palindrome.
    '''

    binary = "cgc_scored_event_1/cgc/0b32aa01_01"
    # fuzzbitmap says every transition is worth satisfying
    d = driller.Driller(os.path.join(bin_location, binary), "AAAA", "\xff"*65535, "whatever~")

    new_inputs = d.drill()

    nose.tools.assert_equal(len(new_inputs), 7)

    # make sure driller produced a new input which hits the easter egg
    nose.tools.assert_true(any(filter(lambda x: x[1].startswith('^'), new_inputs)))

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    run_all()
