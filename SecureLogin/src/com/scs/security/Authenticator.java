package com.scs.security;

import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.scs.security.InstructionTable.Position;
import com.scs.security.functions.P_Function;
import com.scs.security.functions.G_Function;
import com.scs.security.misc.CryptoException;

public class Authenticator {

	public static P_Function p_function = null;
	public static G_Function g_function = null;

	/* Handle two workflows - 1) First time login 2) nth time login (n > 1) */
	public static boolean authenticate(String password, long[] features){
		return _authenticate(password, features);
	}
	
	/* check if password scheme is initialized */
	public static boolean isSchemeInitialized(){
		return Boolean.valueOf(LoginHandler.getPreferences().get(Constants.PREF_INITIALIZED, "false"));
	}
	
	private static void initFunctions(String password){
		try {
			p_function = new P_Function(Generator.R);
		} catch (CryptoException e) {
			e.printStackTrace();
		}
		
		try {
			g_function = new G_Function(Generator.R, password);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/* Initialize scheme for first time login */
	public static boolean initScheme(String password){
		Position[] positions = new Position[Constants.M];
		Arrays.fill(positions, Position.BOTH);
		BigInteger hpwd = Generator.getHPWD(Constants.Q);
		initFunctions(password);
		generateScheme(hpwd, positions);
		
		LoginHandler.getPreferences().put(Constants.PREF_INITIALIZED, "true");
		return true;
	}

	/**
	 * 
	 * @param password
	 * @param features : array of current login features
	 * @return true if successfully authenticated
	 */
	private static boolean _authenticate(String password, long[] features) {
		initFunctions(password);
		BigInteger hpwd = extractHardenedPwd(features, password);

		File historyFile = new File(Constants.HISTORY_FILE_PATH);

		HistoryData historyData = HistoryData.loadHistory(historyFile, hpwd); 
		if (historyData == null) { /* returns null if decryption of history file fails*/
			return false;
		}

		historyData.addEntry(features);
		Position[] positions = computeFeatures(historyData);
		
		historyData.persist(historyFile, hpwd);
		generateScheme(hpwd, positions);
		
		return true;
	}

	/* extracts hardened password from feature vector and password */
	private static BigInteger extractHardenedPwd(long[] features,
			String password) {
		List<Point> points = new LinkedList<Point>();
		InstructionTable iTable = InstructionTable
				.loadTable(Constants.INSTRUCTION_TABLE_FILE_PATH);

		for (int i = 0; i < features.length; i++) {
			int index = iTable.get(i).getIndex();
			BigDecimal x = null, y = null;

			switch (InstructionTable.getPosition(features[i])) {
			case ALPHA:
			case BOTH:
				x = new BigDecimal(p_function.execute(2 * index));
				y = iTable.get(i).getAlpha().subtract(new BigDecimal(g_function.execute(2 * index)));
				break;
			case BETA:
				x = new BigDecimal(p_function.execute(2 * index + 1));
				y = iTable.get(i).getBeta().subtract(new BigDecimal(g_function.execute(2 * index + 1)));
				break;
			}
			points.add(new Point(x, y));
		}

		BigInteger hpwd = Polynomial
				.generateZerothCoefficientFromPoints(points);
		return hpwd;
	}
	
	/* computes the distinguishing features from History File Data  */
	private static Position[] computeFeatures(HistoryData histData){
		Position[] positions = new Position[Constants.M];
		
		if(histData == null || histData.numEntries() < Constants.H){
			Arrays.fill(positions, Position.BOTH); /* If num of entries in history file < 10 */
		}else{
			double mean, sd;
			for(int i = 0; i < Constants.M; i++){
				mean = histData.getMean(i);
				sd = histData.getStandardDeviation(i);
				if(Constants.THRESHOLD_FEATURE_VALUES[i] - sd >= mean){
					positions[i] = Position.ALPHA;
				}
				else if(Constants.THRESHOLD_FEATURE_VALUES[i] + sd <= mean){
					positions[i] = Position.BETA;
				}
				else{
					positions[i] = Position.BOTH;
				}
			}
		}
		
		return positions;
	}
	
	/* generate a new 1) Random Polynomial 2) R value 3) Instruction Table and persist it to disk */
	private static void generateScheme(BigInteger hpwd, Position[] positions){
		Polynomial newPoly = Polynomial.getRandomPolynomial(Constants.M - 1, hpwd);
		Generator.R = Generator.getRandomInteger(Generator.BIT_LENGTH);
		LoginHandler.getPreferences().put(Constants.PREF_R, Generator.R.toString());
		
		InstructionTable iTable = InstructionTable.generateInstructionTable(positions, newPoly);
		iTable.writeToFile(Constants.INSTRUCTION_TABLE_FILE_PATH);
	}
}
