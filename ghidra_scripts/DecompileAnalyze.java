// Ghidra headless post-analysis script
// Decompiles all functions, extracts strings, imports, and writes a report
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

import java.io.*;
import java.util.*;

public class DecompileAnalyze extends GhidraScript {

    @Override
    public void run() throws Exception {
        String programName = currentProgram.getName();
        String outputDir = System.getenv("GHIDRA_OUTPUT_DIR");
        if (outputDir == null) {
            outputDir = "/root/cowrie/ghidra_output";
        }

        File outFile = new File(outputDir, programName + "_analysis.txt");
        PrintWriter pw = new PrintWriter(new FileWriter(outFile));

        pw.println("=============================================================");
        pw.println("ANALYSIS REPORT: " + programName);
        pw.println("=============================================================");
        pw.println();

        // Basic info
        pw.println("[BINARY INFO]");
        pw.println("  Format:       " + currentProgram.getExecutableFormat());
        pw.println("  Architecture: " + currentProgram.getLanguage().getProcessor());
        String endian = currentProgram.getLanguage().isBigEndian() ? "Big" : "Little";
        pw.println("  Endian:       " + endian);
        pw.println("  Compiler:     " + currentProgram.getCompilerSpec().getCompilerSpecID());
        pw.println("  Image Base:   " + currentProgram.getImageBase());
        pw.println();

        // Imports / External functions
        pw.println("[IMPORTS / EXTERNAL FUNCTIONS]");
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator extSyms = symTable.getExternalSymbols();
        List<String> imports = new ArrayList<>();
        while (extSyms.hasNext()) {
            Symbol s = extSyms.next();
            imports.add(s.getName());
        }
        Collections.sort(imports);
        for (String imp : imports) {
            pw.println("  " + imp);
        }
        pw.println("  Total: " + imports.size());
        pw.println();

        // Defined strings
        pw.println("[STRINGS]");
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        List<String> strings = new ArrayList<>();
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            DataType dt = data.getDataType();
            String dtName = dt.getName().toLowerCase();
            if (dtName.contains("string") || dtName.equals("ds") || dtName.equals("unicode")) {
                Object val = data.getValue();
                if (val != null) {
                    String s = val.toString();
                    if (s.length() >= 4) {
                        strings.add(data.getAddress() + ": " + s);
                    }
                }
            }
        }
        for (String s : strings) {
            pw.println("  " + s);
        }
        pw.println("  Total strings (len>=4): " + strings.size());
        pw.println();

        // Function listing
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        pw.println("[FUNCTIONS] (total: " + funcMgr.getFunctionCount() + ")");
        FunctionIterator funcIt = funcMgr.getFunctions(true);
        List<Function> allFuncs = new ArrayList<>();
        while (funcIt.hasNext()) {
            Function f = funcIt.next();
            allFuncs.add(f);
            pw.println("  " + f.getEntryPoint() + "  " + f.getName() + "  (size: " + f.getBody().getNumAddresses() + ")");
        }
        pw.println();

        // Decompile all functions
        pw.println("[DECOMPILED FUNCTIONS]");
        pw.println();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (Function f : allFuncs) {
            if (monitor.isCancelled()) break;

            DecompileResults results = decomp.decompileFunction(f, 30, monitor);
            if (results.decompileCompleted()) {
                DecompiledFunction df = results.getDecompiledFunction();
                if (df != null) {
                    pw.println("--- " + f.getName() + " @ " + f.getEntryPoint() + " ---");
                    pw.println(df.getC());
                    pw.println();
                } else {
                    pw.println("--- " + f.getName() + " @ " + f.getEntryPoint() + " --- [no decompiled output]");
                    pw.println();
                }
            } else {
                pw.println("--- " + f.getName() + " @ " + f.getEntryPoint() + " --- [decompile failed]");
                pw.println();
            }
        }

        decomp.dispose();

        pw.flush();
        pw.close();

        println("Analysis written to: " + outFile.getAbsolutePath());
    }
}
