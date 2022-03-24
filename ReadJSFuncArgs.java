//Iterates through all calls to registerJsFunction and
//outputs Markdown.
//@author Spotlight
//@category Wii

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ReadJSFuncArgs extends GhidraScript {
	public void run() throws Exception {
		// We hardcode 0x80091620 as it must not change.
		// This is the address of "registerJsFunc" in v21 of the Wii Shop Channel.
		Address registerFunc = toAddr(0x80091620);

		// We need to keep track of all invoking functions, as determined from our callers.
		List<Function> callers = new ArrayList<Function>();

		// Determine calling functions.
		Reference[] refs = getReferencesTo(registerFunc);
		for (Reference ref: refs) {
			Address callingAddress = ref.getFromAddress();
			Function callee = getFunctionContaining(callingAddress);
			callers.add(callee);
		}

		// Necessary for decompilation.
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

		DecompInterface ifc = new DecompInterface();
		ifc.toggleCCode(false);
		ifc.openProgram(currentProgram);

		// Decompile all calling functions.
		for (Function caller: callers) {
			DecompileResults res = ifc.decompileFunction(caller, 0, monitor);
		
			// Ensure no errors occurred
			if (!res.decompileCompleted()) {
				println(res.getErrorMessage());
				return;
			}

			HighFunction current = res.getHighFunction();
			Iterator<PcodeOpAST> funcOps = current.getPcodeOps();
			while (funcOps.hasNext()) {
				PcodeOpAST op = funcOps.next();

				// We only want to handle CALL pcodes.
				if (op.getOpcode() != PcodeOp.CALL) {
					continue;
				}

				// We only want to handle calls to our registration function.
				if (!op.getInput(0).getAddress().equals(registerFunc)) {
					continue;
				}
				
				handleCallArgs(op);
			}
		}
	}

	void handleCallArgs(PcodeOp op) throws Exception {
		// 0 holds the calling addres
		// 1 holds `paramCount`, nullable
		// 2 holds `paramData`, nullable
		// 3 holds `expectedArgs`, nullable
		// 4 holds `lowerArgCount`
		// 5 holds `upperArgCount`
		// 6 holds `name`


		// We can later access memory at this offset to determine our values.
		Address expectedArgs = traceVarnodeValue(op.getInput(3));

		// Determine calling count.
		long lowerArgCount = op.getInput(4).getOffset();
		long upperArgCount = op.getInput(5).getOffset();

		// Determine the function's name.
		String functionName = getString(op.getInput(6));

		// Our expectedArgs pointer will be null, and lower/upper args are both zero for arg-less functions.
		if (expectedArgs.getOffset() == 0 && lowerArgCount == 0 && upperArgCount == 0) {
			printf("Name %s\n", functionName);
			return;
		}

		printf("Name %s: lower %d, upper %d, expected arguments @ %s\n", functionName, lowerArgCount, upperArgCount, expectedArgs);

		println(expectedArgs + "");
		Data arguments = getDataAt(expectedArgs);
		println(arguments.getDataType().getName());
	}

	// I found this function while scouring about online.
	// I have absolutely no clue how it works - presumably just following the pointer?
	// I.. have no clue. I'm sorry :(
	// It works, at least
	private Address traceVarnodeValue(Varnode argument) throws IllegalArgumentException {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
			if (ins == null)
				break;
			switch (ins.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				argument = ins.getInput(0);
				break;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				argument = ins.getInput(1);
				break;
			case PcodeOp.INT_MULT:
			case PcodeOp.MULTIEQUAL:
				return Address.NO_ADDRESS;
			default:
				throw new IllegalArgumentException(String.format("Unknown opcode %s for variable copy at %08X",
						ins.getMnemonic(), argument.getAddress().getOffset()));
			}
		}
		return toAddr(argument.getOffset());
	}	

	// Traces for the Varnode's represented Address and returns the String of its Data.
	String getString(Varnode node) throws Exception {
		Address value = traceVarnodeValue(node);
		Data data = getDataAt(value);
		return (String)data.getValue();
	}
}
