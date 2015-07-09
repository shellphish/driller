#!/usr/bin/env pypy

import angr
import string
import sys

'''
create AFL dictionary of string references found in the binary. should allow AFL to explore more paths
without having to request symbolic execution.
'''

def hexescape(s):
    out = [ ] 
    acceptable = string.letters + string.digits + " ."
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % ord(c))
        else:
            out.append(c)
            

    return ''.join(out)

def main(argc, argv):

    if (argc < 3):
        print "usage: %s <binary> <dictfile>" % argv[1]
        sys.exit(1)

    binary = argv[1] 
    dictfile = argv[2]

    b = angr.Project(binary)
    cfg = b.analyses.CFG(keep_input_state=True)

    string_references = [ ] 
    for f in cfg.function_manager.functions.values():
        try:
            string_references.append(f.string_references())
        except ZeroDivisionError:
            pass
            
    string_references = sum(string_references, []) 

    strings = [] if len(string_references) == 0 else zip(*string_references)[1]

    dictfp = open(dictfile, "w")
    for i, string in enumerate(strings):
        s = hexescape(string)
        dictfp.write("driller_%d=\"%s\"\n" % (i, s))

    dictfp.close()

    return 0


if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
