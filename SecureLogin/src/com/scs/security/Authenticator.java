package com.scs.security;

import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

import com.scs.security.functions.P_Function;
import com.scs.security.functions.G_Function;
import com.scs.security.misc.CryptoException;

public class Authenticator {

	public static P_Function p_function;
	public static G_Function g_function = null;

	/* statically initialize p_function */
	static {
		try {
			p_function = new P_Function(Constants.R);
		} catch (CryptoException e) {
			e.printStackTrace();
		}
	}

	public static boolean authenticate(String password, long[] features) {
		if (g_function == null) {
			try {
				g_function = new G_Function(Constants.R, password);
			} catch (CryptoException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		BigInteger hpwd = extractHardenedPwd(features, password);

		File historyFile = new File(Constants.HISTORY_FILE_PATH);

		HistoryData historyData = HistoryData.loadHistory(historyFile, hpwd);
		if (historyData == null) {
			return false;
		}

		int historyFileSize = historyData.addEntry(features);
		historyData.persist(historyFile, hpwd);

		return true;
	}

	/* determines polynomial from feature vector and password */
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
}
