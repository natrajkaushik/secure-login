package com.scs.security;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

public class FileUtils {

	public static boolean fileExists(String filePath) {
		return (new File(filePath)).isFile();
	}
	
	interface Callback {
		public void processData(byte[] data);
	}

	
	public static void readFile(String filePath, Callback c) {
		
	}

	
	public static void writeToFile(byte[] data, String filePath) {
	
	}

	public static void close(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	public static void main(String[] args) {

	}

}

