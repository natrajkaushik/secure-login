package com.scs.security;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.scs.security.InstructionTable.Position;
import com.scs.security.functions.P_Function;
import com.scs.security.functions.G_Function;
import com.scs.security.misc.CryptoException;

/***
 * Handles the authentication of a user as specified by the password hardening scheme 
 */
public class Authenticator {

	public static P_Function p_function = null;
	public static G_Function g_function = null;

	/***
	 * 
	 * @param password user given password
	 * @param features user features for current session
	 * @return true if user is authenticated
	 */
	public static boolean authenticate(String password, long[] features){
		return _authenticate(password, features);
	}
	
	/***
	 * Checks if scheme is initialized
	 * @return true is scheme is initialized
	 */
	public static boolean isSchemeInitialized(){
		return Boolean.valueOf(LoginHandler.getPreferences().get(Constants.PREF_INITIALIZED, "false"));
	}
	
	/***
	 * reset the scheme by clearing the initialization flag and R value
	 */
	public static void reset(){
		LoginHandler.getPreferences().put(Constants.PREF_INITIALIZED, "false");
		LoginHandler.getPreferences().put(Constants.PREF_R, Generator.ZERO);
	}
	
	/***
	 * initializes P and G functions
	 * @param password user given password
	 */
	private static void initFunctions(String password){
		try {
			p_function = new P_Function(Generator.R);
		} catch (CryptoException e) {
			e.printStackTrace();
		}
		
		try {
			g_function = new G_Function(Generator.R, password);
		} catch (CryptoException e) {
			e.printStackTrace();
		}
	}
	
	/***
	 * Initializes the scheme
	 * @param password user given password
	 * @return
	 */
	public static boolean initScheme(String password, long[] features){
		Position[] positions = new Position[Constants.M];
		Arrays.fill(positions, Position.BOTH); /* Initially both Alpha and Beta positions are filled with correct entries */
		BigInteger hpwd = Generator.getHPWD(Constants.Q); /* generate a random hardened password */
	
		initFunctions(password);
		
		HistoryData histData = new HistoryData(features);
		histData.persist(new File(Constants.HISTORY_FILE_PATH), hpwd);
		generateScheme(hpwd, positions, password);
		
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
		Position[] positions = computeDistFeatures(historyData);
		
		historyData.persist(historyFile, hpwd);
		generateScheme(hpwd, positions, password);
		
		return true;
	}

	/***
	 * extracts hardened password from features and password
	 * @param features
	 * @param password
	 * @return hardened password
	 */
	private static BigInteger extractHardenedPwd(long[] features,
			String password) {
		List<Point> points = new LinkedList<Point>();
		InstructionTable iTable = InstructionTable.loadTable(Constants.INSTRUCTION_TABLE_FILE_PATH);

		for (int i = 0; i < features.length; i++) {
			int index = iTable.get(i).getIndex();
			BigInteger x = null, y = null;
			
			switch (InstructionTable.getPosition(features[i], i)) {
			case ALPHA:
			case BOTH:
				x = p_function.execute(2 * index);
				y = iTable.get(i).getAlpha().subtract(g_function.execute(2 * index)).mod(Constants.Q);
				break;
			case BETA:
				x = p_function.execute(2 * index + 1);
				y = iTable.get(i).getBeta().subtract(g_function.execute(2 * index + 1)).mod(Constants.Q);
				break;
			}
			points.add(new Point(x, y));
		}

		BigInteger hpwd = Polynomial.generateZerothCoefficientFromPoints(points);
		return hpwd;
	}
	
	/***
	 * computes the distinguishing features from History File Data
	 * @param histData
	 * @return Position[] containing which features are distinguishing
	 */
	private static Position[] computeDistFeatures(HistoryData histData){
		Position[] positions = new Position[Constants.M];
		
		if(histData == null || histData.numEntries() < Constants.H) {
			Arrays.fill(positions, Position.BOTH); /* If num of entries in history file < 10 */
		} else {
			double mean, sd;
			for(int i = 0; i < Constants.M; i++){
				mean = histData.getMean(i);
				sd = histData.getStandardDeviation(i);
				if ((Constants.THRESHOLD_FEATURE_VALUES[i] - (Constants.K * sd)) > mean) {
					positions[i] = Position.ALPHA;
				}
				else if ((Constants.THRESHOLD_FEATURE_VALUES[i] + (Constants.K * sd)) < mean) {
					positions[i] = Position.BETA;
				}
				else {
					positions[i] = Position.BOTH;
				}
			}
		}
		
		return positions;
	}
	
	/***
	 * generate password scheme either a) during initialization or b) after successful login  
	 * @param hpwd
	 * @param positions
	 * @param password
	 */
	private static void generateScheme(BigInteger hpwd, Position[] positions, String password){
		/* generate new random polynomial */
		Polynomial newPoly = Polynomial.getRandomPolynomial(Constants.M - 1, hpwd);
		
		/* generate new R value and persist */
		Generator.R = Generator.getRandomInteger(Generator.BIT_LENGTH);
		LoginHandler.getPreferences().put(Constants.PREF_R, Generator.R.toString());
		
		/* reinitialize P and G functions with new R value */
		initFunctions(password);
		
		/* generate new Instruction Table and write to file */
		InstructionTable iTable = InstructionTable.generateInstructionTable(positions, newPoly);
		iTable.writeToFile(Constants.INSTRUCTION_TABLE_FILE_PATH);
	}
}
