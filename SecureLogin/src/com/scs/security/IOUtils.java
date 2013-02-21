package com.scs.security;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

public class IOUtils {

	public static boolean fileExists(String filePath) {
		return (new File(filePath)).isFile();
	}
	
	public interface Callback {
		public void processData(String data);
	}

	
	public static void readFile(String filePath, Callback c) {
		
	}

	
	public static void writeToFile(byte[] data, String filePath) {
	
	}
	
	/* read a line from the console */
	public static String readFromConsole(){
		String line = null;
		BufferedReader br = null;
		InputStreamReader isr = null;
		try{
			isr = new InputStreamReader(System.in);
		    br = new BufferedReader(isr);
		    line = br.readLine();
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}finally{
			//close(br); /* this is causing a IOException : Stream closed on multiples calls to function */
		}
		return line;
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

