//It's like SwitchOverride, but doesn't suck hours of your time.
//@author Spotlight
//@category Repair

import java.util.ArrayList;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;

public class ActuallyUsableSwitchOverride extends GhidraScript {

	public void run() throws Exception {		
		// Our branch instruction is 0x800aa8ac.
		Address branchInstruction = parseAddress("0x800aa8ac");
		
		// Our jump table begins at 0x8034329c, containing 1341 pointers.
		// We need to obtain all values within the table to create a JumpTable later on.
		ArrayList<Address> jumpTable = new ArrayList<Address>();
		Address tableAddress = parseAddress("0x8034329c");

		for (int i = 0; i < 1341; i++) {
			println("Out here at iter " + i);
			println("Currently processing " + tableAddress.toString());
			
			// Resolve our current entry's value.
			Data currentEntry = getDataAt(tableAddress);
			if (currentEntry == null) {
				println("There is no data defined at " + tableAddress.toString() + ". Verify you have the table address configured properly.");
				return;
			}
			
			
			// Determine what our pointer is, er, pointing to.
			Reference[] references = currentEntry.getReferencesFrom();
			if (references.length == 0) {
				println("The pointer at " + tableAddress.toString() + " does not reference a value. Is it a pointer?");
				return;
			} else if (references.length != 1) {
				println("The pointer at " + tableAddress.toString() + " references multiple values. Is it properly set up?");
				return;
			}
						
			// Track this reference.
			jumpTable.add(references[0].getToAddress());
			
			
			// Move on to the next pointer.
			tableAddress = tableAddress.add(4);
		}
		
		// Determine what function holds our branching instruction.
		Function function = this.getFunctionContaining(branchInstruction);
		if (function == null) {
			println("Computed jump instruction must be in a Function body.");
			return;
		}
		
		Instruction instr = currentProgram.getListing().getInstructionAt(branchInstruction);
		for (Address address : jumpTable) {
			instr.addOperandReference(0, address, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
		}

		// Allocate an override jumptable.
		JumpTable jumpTab = new JumpTable(branchInstruction, jumpTable, true);
		jumpTab.writeOverride(function);
		
		// Fix up the body now that there are jump references.
		CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
	}

}
