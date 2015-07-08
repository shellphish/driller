
import logging
logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s', level=logging.WARNING)
logging.getLogger("main").setLevel(logging.DEBUG)


color_name = True
color_msg = True
original_emit = logging.StreamHandler.emit
def emit_wrap(*args, **kwargs):
        #import ipdb; ipdb.set_trace()
        record = args[1]
        color = hash(record.name) % 8 + 30

        if color_name:
                try:
                        record.name = ("\x1b[%dm" % color) + record.name + "\x1b[0m"
                except Exception:
                        pass

        if color_msg:
                try:
                        record.msg = ("\x1b[%dm" % color) + record.msg + "\x1b[0m"
                except Exception:
                        pass

        original_emit(*args, **kwargs)

logging.StreamHandler.emit = emit_wrap

