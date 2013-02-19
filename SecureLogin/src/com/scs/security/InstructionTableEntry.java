package com.scs.security;

import java.math.BigDecimal;

/* Instruction Table will be an array of InstructionTableEntry objects */
public class InstructionTableEntry {
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
