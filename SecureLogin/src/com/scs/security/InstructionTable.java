package com.scs.security;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

public class InstructionTable {
	private List<InstructionTableEntry> entries = new ArrayList<InstructionTableEntry>(Constants.M); /* Instruction Table */
	
	public enum Position{
		ALPHA,
		BETA;
	};
	
	public static InstructionTable loadTable(String filePath) {
		final InstructionTable iTable = new InstructionTable();
		
		IOUtils.readFile(filePath, new IOUtils.Callback() {
			int count = 0;
			
			@Override
			public void processData(String data) {
				/* each line in the instruction table has "i alpha(i) beta(i)" */
				String[] tokens = data.split("\\s+");
				InstructionTableEntry entry = new InstructionTableEntry(Integer.valueOf(tokens[0]), 
						new BigDecimal(tokens[1]), new BigDecimal(tokens[2]));
				iTable.addEntry(entry);
			}
		});
		
		return iTable;
	}
	
	public static Position getPosition(long feature){
		return Position.ALPHA;
	}
	
	public boolean addEntry(InstructionTableEntry entry){
		return entries.add(entry);
	}
	
	public InstructionTableEntry get(int i){
		return entries.get(i);
	}
	
}


class InstructionTableEntry{
	private int index; /* feature index */
	private BigDecimal alpha; /* alpha entry for feature */
	private BigDecimal beta; /* beta entry for feature */
	
	public InstructionTableEntry(int index, BigDecimal alpha, BigDecimal beta) {
		this.index = index;
		this.alpha = alpha;
		this.beta = beta;
	}
	public int getIndex() {
		return index;
	}
	public void setIndex(int index) {
		this.index = index;
	}
	public BigDecimal getAlpha() {
		return alpha;
	}
	public void setAlpha(BigDecimal alpha) {
		this.alpha = alpha;
	}
	public BigDecimal getBeta() {
		return beta;
	}
	public void setBeta(BigDecimal beta) {
		this.beta = beta;
	}
}
