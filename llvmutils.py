from llvmlite import ir  # type: ignore


class GlobalAlias(ir.GlobalValue):
    def __init__(self, module, aliasee, name):
        super().__init__(module, aliasee.type, name=name)
        self.aliasee = aliasee
        self.unnamed_addr = False
        self.addrspace = aliasee.addrspace
        self.parent.add_global(self)

    def descr(self, buf):
        if self.linkage:
            buf.append(self.linkage + " ")
        if self.storage_class:
            buf.append(self.storage_class + " ")
        if self.unnamed_addr:
            buf.append("unnamed_addr ")

        buf.append(
            "alias {type}, {aliasee}".format(
                type=self.aliasee.type, aliasee=self.aliasee.get_reference()
            )
        )

        if self.metadata:
            buf.append(self._stringify_metadata(leading_comma=True))

        buf.append("\n")
