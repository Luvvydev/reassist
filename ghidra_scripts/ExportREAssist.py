#@category REAssist
#@menupath Tools.REAssist.Export JSON

"""Export a small JSON summary of the current Ghidra program.

This is intentionally simple:
- function name and entry point
- decompiler text (best effort)

How to use:
1) Open a program in Ghidra and let analysis finish.
2) Script Manager -> run this script.
3) Choose an output file location.

The JSON can be merged into an existing REAssist analysis:
    reassist merge-ghidra analysis.json ghidra_export.json
"""

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def main():
    prog = currentProgram
    fm = prog.getFunctionManager()

    out_file = askFile("Save REAssist Ghidra export", "Save")

    iface = DecompInterface()
    iface.openProgram(prog)

    monitor = ConsoleTaskMonitor()

    functions = []
    it = fm.getFunctions(True)
    while it.hasNext():
        fn = it.next()
        entry = fn.getEntryPoint().toString()

        decomp = None
        try:
            res = iface.decompileFunction(fn, 30, monitor)
            if res and res.decompileCompleted():
                decomp = res.getDecompiledFunction().getC()
        except Exception:
            decomp = None

        functions.append({
            "name": fn.getName(),
            "entry": entry,
            "decomp": decomp,
        })

    data = {
        "tool": "ghidra",
        "program": prog.getName(),
        "language": str(prog.getLanguageID()),
        "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
        "function_count": len(functions),
        "functions": functions,
    }

    with open(out_file.getAbsolutePath(), "w") as f:
        json.dump(data, f, indent=2)

    print("Wrote: %s" % out_file.getAbsolutePath())


main()
