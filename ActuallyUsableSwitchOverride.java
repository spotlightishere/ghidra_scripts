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
	// TODO(spotlightishere): Migrate from hardcoded addresses to something intrinsics-based
	// e.g. use branch searching logic in FindUnrecoveredSwitchesScript
	static String BRANCH_INSTRUCTION = "0x800aa8ac";
	// TODO(spotlightishere): determine table address based on current cursor? or, from selected branch instr?
	static String TABLE_ADDRESS = "0x8034329c";
	// TODO(spotlightishere): Find clean way to determine table length
	static int TABLE_LENGTH = 1341;
	
	public void run() throws Exception {		
		// Our branch instruction is provided by the user.
		Address branchInstruction = parseAddress(BRANCH_INSTRUCTION);
		
		// Our jump table begins at 0x8034329c, containing 1341 pointers.
		// We need to obtain all values within the table to create a JumpTable later on.
		ArrayList<Address> jumpTable = new ArrayList<Address>();
		Address tableAddress = parseAddress(TABLE_ADDRESS);

		// Used to determine functions.
		FunctionManager manager = currentProgram.getFunctionManager();
		
		for (int i = 0; i < TABLE_LENGTH; i++) {
			// Resolve our current entry's value.
			Data currentEntry = getDataAt(tableAddress);
			if (currentEntry == null) {
				println("There is no data defined at " + tableAddress.toString() + ".");
				println("Verify you have the table address configured properly.");
				return;
			}
			
			
			// Determine what our pointer is, er, pointing to.
			Reference[] references = currentEntry.getReferencesFrom();
			if (references.length == 0) {
				println("The pointer at " + tableAddress.toString() + " does not reference a value.");
				println("Is it a pointer?");
				return;
			} else if (references.length != 1) {
				println("The pointer at " + tableAddress.toString() + " references multiple values.");
				println("Is it properly set up?");
				return;
			}
			
			Address pointerValue = references[0].getToAddress();
			
			// Ghidra may mistakenly analyze larger routines as their own function.
			// We need to remove this as a function in order to add it to our table.
			if (manager.isInFunction(pointerValue)) {
				manager.removeFunction(pointerValue);
			}
			
			
			// Track this reference.
			jumpTable.add(pointerValue);
			
			
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
