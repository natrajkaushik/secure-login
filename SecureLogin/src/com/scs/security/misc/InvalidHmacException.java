package com.scs.security.misc;

@SuppressWarnings("serial")
public class InvalidHmacException extends Exception {
	public InvalidHmacException(String msg) {
		super(msg);
	}
}