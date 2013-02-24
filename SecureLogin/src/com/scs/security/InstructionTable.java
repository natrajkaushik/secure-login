package com.scs.security;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import com.scs.security.functions.P_Function;

public class InstructionTable {
	private List<InstructionTableEntry> entries = new ArrayList<InstructionTableEntry>(
			Constants.M); /* Instruction Table */

	public enum Position {
		ALPHA, BETA, BOTH;
	};

	/* load instruction table from file */
	public static InstructionTable loadTable(String filePath) {
		final InstructionTable iTable = new InstructionTable();

		IOUtils.readFile(filePath, new IOUtils.Callback() {
			@Override
			public void processLine(String data) {
				/* each line in the instruction table has "i alpha(i) beta(i)" */
				String[] tokens = data.split("\\s+");
				InstructionTableEntry entry = new InstructionTableEntry(Integer
						.valueOf(tokens[0]), new BigDecimal(tokens[1]),
						new BigDecimal(tokens[2]));
				iTable.addEntry(entry);
			}
		});

		return iTable;
	}

	/* write the Instruction Table to a file */
	public void writeToFile(String filePath){
		List<String> lines = new ArrayList<String>(entries.size());
		for (InstructionTableEntry ite : entries) {
			String entry = new String(ite.getIndex() + " " + ite.getAlpha()
					+ " " + ite.getBeta());
			lines.add(entry);
		}
		IOUtils.writeToFile(lines, filePath);
	}

	/* generate Instruction Table from distinguishing features and a randomly generated polynomial */
	public static InstructionTable generateInstructionTable(Position[] positions, Polynomial poly) {
		InstructionTable iTable = new InstructionTable();
		
		for (int i = 0; i < positions.length; i++) {
			Position position = positions[i];
			
			int index = i + 1;
			BigDecimal alpha = poly.evaluate(new BigDecimal(Authenticator.p_function.execute(2 * index)));
			BigDecimal beta = poly.evaluate(new BigDecimal(Authenticator.p_function.execute(2 * index + 1)));
			
			switch (position) {
			case ALPHA:
				beta = Generator.getRandomBigDecimal();
				break;
				
			case BETA:
				alpha = Generator.getRandomBigDecimal();
				break;
				
			case BOTH:
				break;
			}
			
			iTable.addEntry(new InstructionTableEntry(index, alpha, beta));
		}

		return iTable;
	}

	public static Position getPosition(long feature) {
		return Position.ALPHA;
	}

	public boolean addEntry(InstructionTableEntry entry) {
		return entries.add(entry);
	}

	public InstructionTableEntry get(int i) {
		return entries.get(i);
	}

}

class InstructionTableEntry {
	private int index; /* feature index 1 to m */
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
