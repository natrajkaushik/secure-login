package com.scs.security;

import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class HistoryData {
	
	/**
	 * Contains M feature values of the previous H 
	 * successful login attempts
	 */
	private ArrayList<long[]> history;
	
	/**
	 * Creates a new HistoryData object for new user
	 * @param features First time feature values.
	 */
	public HistoryData(long[] features) {
		history = new ArrayList<long[]>();
		history.add(features);
	}
	
	/**
	 * Creates new HistoryData object from successfully
	 * decrypted history file data.
	 * @param data
	 */
	private HistoryData(byte[] data) {
		// TODO reverse of toByteArray
		// ByteBuffer buffer = ByteBuffer.wrap(bytes);
		// long l = buffer.getLong();
	}
	
	/**
	 * Attempts to create a new HistoryData object from
	 * data a file.
	 * @param file The file that is to be read
	 * @param hpwd_prime The hardened password with which
	 * to decrypt the file
	 * @return The new HistoryData object, or null if 
	 * decryption fails due to wrong password
	 */
	public static HistoryData loadHistory(File file, BigInteger hpwd_prime) {
		// TODO Read file contents into memory
		// TODO decrypt data with hpwd_prime
		// TODO if decrypts successfully, 
		HistoryData data = new HistoryData(new byte[0] /* file data goes here */);
		return data;
		// TODO else if decrypt fails,
		// return null;
	}
	
	public int addEntry(long[] features) {
		while (history.size() >= Constants.H){
			history.remove(history.size() - 1);
		}
		history.add(features);
		return history.size();
	}
	
	public void persist(File file, BigInteger hpwd) {
		byte[] data = toByteArray();
		// TODO encrypt data with hpwd
		// TODO write contents out to file
	}
	
	private byte[] toByteArray() {
		byte[] totem = Constants.TOTEM.getBytes();
		byte[] numEntries = ByteBuffer.allocate(4).putInt(history.size()).array();
		
		/* Total byte length is sum of following:
		 * 1. Size of totem
		 * 2. 4 bytes to write number of good entries
		 * 3. (M*8) bytes for each good entry
		 */
		int size = totem.length + 4 + (history.size() * 8 * Constants.M);
		byte[] data = new byte[size];
		int i = 0;
		
		// Add totem
		System.arraycopy(totem, 0, data, i, totem.length);
		i += totem.length;
		
		// Add number of good entries
		System.arraycopy(numEntries, 0, data, i, 4);
		i += 4;
		
		// Add good entries
		for (long[] entry : history) {
			for (int j = 0; j < Constants.M; j++) {
				byte[] feature = ByteBuffer.allocate(8).putLong(entry[j]).array();
				System.arraycopy(feature, 0, data, i, 8);
				i += 8;
			}
		}
		
		// Pad rest of the data
		for (; i < data.length; i++) {
			data[i] = 0;
		}
		
		return data;
	}
}