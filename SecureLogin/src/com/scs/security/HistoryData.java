package com.scs.security;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Random;

import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;

import com.scs.security.misc.BadPasswordException;
import com.scs.security.misc.CryptoException;
import com.scs.security.misc.InvalidHmacException;

public class HistoryData {
	
	private static final String FILE_WRITE_ERR 	= "Error writing to file!";
	private static final String FILE_READ_ERR 	= "Error reading from file!";
	private static final String ENC_FAIL_ERR 	= "Encryption failed! %s\nFile not saved.\n";
	private static final String DEC_FAIL_ERR 	= "Decryption failed! %s\n";
	private static final String VALID_ERR 		= "Validation failed! Invalid hardened password.";
	private static final String CORRUPT_ERR		= "History data corrupted!";
	
	/**
	 * Contains M feature values of the previous H 
	 * successful login attempts
	 */
	private ArrayList<long[]> history;
	
	private DescriptiveStatistics[] stats;
	
	/**
	 * Creates a new HistoryData object for new user
	 * @param features first time feature values.
	 */
	public HistoryData(long[] features) {
		history = new ArrayList<long[]>();
		initStats();
		addEntry(features);
	}
	
	/**
	 * Creates new HistoryData object from successfully
	 * decrypted history file data.
	 * @param data decrypted contents
	 * @throws BadPasswordException if given incorrect hardened password.
	 */
	private HistoryData(byte[] data) throws BadPasswordException {
		history = new ArrayList<long[]>();
		initStats();
		if (!fromByteArray(data)) {
			throw new BadPasswordException();
		}
	}
	
	/**
	 * Initializes the statistics counter with window size equal to maximum
	 * size of the history file.
	 */
	private void initStats() {
		stats = new DescriptiveStatistics[Constants.M];
		for (int i = 0; i < Constants.M; i++) {
			stats[i] = new DescriptiveStatistics(Constants.H);
		}
	}
	
	/**
	 * @return number of feature vectors in HistoryData object
	 */
	public int numEntries(){
		return history.size();
	}
	
	/**
	 * Attempts to create a new HistoryData object from
	 * data a file.
	 * @param file the file that is to be read
	 * @param hpwd_prime hardened password with which
	 * to decrypt the file
	 * @return new HistoryData object, or null if decryption fails.
	 */
	public static HistoryData loadHistory(File file, BigInteger hpwd_prime) {
		DataInputStream in = null;
		
		try {
			in = new DataInputStream(new FileInputStream(file));
			byte[] data = new byte[(int)file.length()];
			in.readFully(data);
			
			byte[] decData = Crypto.decrypt(data, hpwd_prime);
			if (peekTotem(decData)) {
				return new HistoryData(decData);
			} else {
				System.err.println(VALID_ERR);
			}
		} catch (FileNotFoundException e) {
			System.err.println(FILE_READ_ERR);
		} catch (IOException e) {
			System.err.println(FILE_READ_ERR);
		} catch (CryptoException e) {
			System.err.printf(DEC_FAIL_ERR, e.getMessage());
		} catch (InvalidHmacException e) {
			System.err.printf(DEC_FAIL_ERR, e.getMessage());
		} catch (BadPasswordException e) {
			System.err.println(VALID_ERR);
		} finally {
			try {
				in.close();
			} catch (Exception e) {}
		}
		
		return null;
	}
	
	/**
	 * Adds a features vector to the history data, removing the last 
	 * entry, if necessary. The last entry to be added is the first 
	 * entry in the history file.
	 * @param features vector to be added
	 * @return number of feature vectors in the history data after 
	 * adding this vector.
	 */
	public int addEntry(long[] features) {
		while (history.size() >= Constants.H){
			history.remove(history.size() - 1);
		}
		history.add(0, features);
		for (int i = 0; i < Constants.M; i++) {
			stats[i].addValue(features[i]);
		}
		return history.size();
	}
	
	/**
	 * Encrypts and saves the history data contents to disk.
	 * @param file file where data is saved
	 * @param hpwd hardened password with which to encrypt the file
	 */
	public void persist(File file, BigInteger hpwd) {
		FileOutputStream  out = null;
		try {
			out = new FileOutputStream(file, false);
			byte[] data = toByteArray();
			byte[] encData = Crypto.encrypt(data, hpwd);
			out.write(encData);
		} catch (CryptoException e) {
			System.err.printf(ENC_FAIL_ERR, e.getMessage());
		} catch (IOException e) {
			System.err.println(FILE_WRITE_ERR);
		} finally {
			try {
				out.close();
			} catch (Exception e) {}
		}
	}
	
	/**
	 * Checks if the given data contains the correct Totem in the front.
	 * @param data input array
	 * @return true if valid Totem present, false otherwise.
	 */
	private static boolean peekTotem(byte[] data) {
		return Constants.TOTEM.equals(new String(data, 0, Constants.TOTEM.length()));
	}
	
	/**
	 * Builds the history data object back from the provided data.
	 * @param in input array.
	 */
	private boolean fromByteArray(byte[] in) {
		String header = new String(in, 0, Constants.TOTEM.length());
		if (!Constants.TOTEM.equals(header)) {
			System.err.println(VALID_ERR);
			return false;
		}
		
		int offset = header.length();
		int numEntries = ByteBuffer.wrap(in, offset, 4).getInt();
		offset += 4;
		int size = numEntries * 8 * Constants.M;
		if ((numEntries <= Constants.H) && (in.length < (offset + size))) {
			System.err.println(CORRUPT_ERR);
			return false;
		}
		
		ByteBuffer buf = ByteBuffer.wrap(in, offset, size);
		for (int i = 0; i < numEntries; i++) {
			long[] vector = new long[Constants.M];
			for (int j = 0; j < Constants.M; j++) {
				vector[j] = buf.getLong();
			}
			addEntry(vector);
		}
		return true;
	}
	
	/**
	 * Converts the history data object to byte array.
	 * @return the created array.
	 */
	private byte[] toByteArray() {
		byte[] totem = Constants.TOTEM.getBytes();
		byte[] numEntries = ByteBuffer.allocate(4).putInt(history.size()).array();
		
		int size = totem.length + 4 + (Constants.H * 8 * Constants.M);
		byte[] data = new byte[size];
		int offset = 0;
		
		System.arraycopy(totem, 0, data, offset, totem.length);
		offset += totem.length;
		System.arraycopy(numEntries, 0, data, offset, 4);
		offset += 4;
		
		for (int i = history.size()-1; i >= 0; i--) {
			long[] entry = history.get(i);
			for (int j = 0; j < Constants.M; j++) {
				byte[] feature = ByteBuffer.allocate(8).putLong(entry[j]).array();
				System.arraycopy(feature, 0, data, offset, 8);
				offset += 8;
			}
		}
		for (; offset < size; offset++) {
			data[offset] = 0;
		}
		
		return data;
	}
	
	/**
	 * Returns the mean value for the given index over all history data.
	 * @param index the feature to get mean for
	 * @return value the mean value
	 */
	public double getMean(int index){
		return stats[index].getMean();
	}
	
	/**
	 * Returns the standard deviation for the given index over all history data.
	 * @param index the feature to get mean for
	 * @return standard deviation of feature value
	 */
	public double getStandardDeviation(int index){
		return stats[index].getStandardDeviation();
	}
	
	public static void main(String args[]) {
		File file1 = new File("C:\\Users\\Sameer\\Desktop\\history1.file");
		BigInteger b = new BigInteger(255, new Random());
		Random r = new Random(System.currentTimeMillis());
		long[] first = {1, 2, 3, 4, 5, 6};
		long[][] val = new long[12][6];
		System.out.println("0:\t1	2	3	4	5	6");
		for (int i = 0; i < 12; i++) {
			System.out.print(i+1 + ":\t");
			for (int j = 0; j < 6; j++) {
				val[i][j] = Math.abs(r.nextLong()) % 100;
				System.out.print(val[i][j] + "\t");
			}
			System.out.println();
		}
		System.out.println();
		HistoryData h = new HistoryData(first);
		for (int i = 0; i < 5; i++) {
			h.addEntry(val[i]);
		}
		h.persist(file1, b);
		
		System.out.println("Read 1:");
		HistoryData l = HistoryData.loadHistory(file1, b);
		if (l != null) {
			l.print();
		}
		
		for (int i = 5; i < 12; i++) {
			l.addEntry(val[i]);
		}
		l.persist(file1, b);
		
		System.out.println("Read 2:");
		HistoryData d = HistoryData.loadHistory(file1, b);
		if (d != null) {
			d.print();
		}
	}
	
	public void print() {
		int i = 0;
		for (long[] entry : history) {
			System.out.print(++i + ":\t");
			for (int j = 0; j < Constants.M; j++) {
				System.out.print(entry[j] + "\t");
			}
			System.out.println();
		}
		System.out.print("AV:\t");
		for (int j = 0; j < Constants.M; j++) {
			System.out.print(stats[j].getMean() + "\t");
		}
		System.out.println();
		System.out.print("SD:\t");
		for (int j = 0; j < Constants.M; j++) {
			System.out.print(stats[j].getStandardDeviation() + "\t");
		}
		System.out.println();
	}
}