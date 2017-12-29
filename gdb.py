import gdb
import gdb.printing

class MaliPtr:
    """ Print a GPU pointer """
    def __init__(self, val):
        self.val = val

    def to_string(self):
        return hex(self.val)

pp = gdb.printing.RegexpCollectionPrettyPrinter("panloader")
pp.add_printer('gpu_ptr', '^mali_ptr$', MaliPtr)
gdb.printing.register_pretty_printer(None, pp)
