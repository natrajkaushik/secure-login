package com.scs.security;

import java.io.File;
import java.math.BigInteger;

public class Authenticator {
	
	public static boolean authenticate(String password, long[] features){
		Polynomial recoveredPolynomial = computePolynomial(features, password);
		BigInteger hpwd = recoveredPolynomial.getZerothCoefficient();
		
		File historyFile = new File(Constants.HISTORY_FILE_PATH);
		
		HistoryData historyData = HistoryData.loadHistory(historyFile, hpwd);
		if(historyData == null){
			return false;
		}
		
		//TODO If History File is successfully decrypted, add feature entries to file and encrypt it again 
		//TODO and write to disk
		historyData.addEntry(features);
		historyData.persist(historyFile, hpwd);
		
		return true;
	}
	
	/* determines polynomial from feature vector and password */
	private static Polynomial computePolynomial(long[] features, String password) {
		Polynomial.Point[] points = new Polynomial.Point[features.length];
		for (long feature : features) {
			switch (InstructionTable.getPosition(feature)) {
			case ALPHA:
				/* do something */
				break;
			case BETA:
				/* do something */
				break;
			}
		}
		Polynomial p = Polynomial
				.generatePolynomialFromPoints(points);
		return p;
	}
}
