package com.scs.security;

import java.util.prefs.Preferences;

/* main workflow of handling user login */
public class LoginHandler {
	
	private String password;
	private long[] features = new long[Constants.M];
	
	private static Preferences prefs;
	
	static{
		prefs = Preferences.userNodeForPackage(LoginHandler.class);
	}
	
	public static Preferences getPreferences(){
		return prefs;
	}
	
	/* interact with the user and fetch the feature vector for the session */
	private void getUserFeatures(){
		System.out.println("******** SECURE LOGIN ********");
		System.out.print("Password : ");
		password = IOUtils.readFromConsole();
		
		String answer;
		for(int i = 0; i < Constants.QUESTIONS.length; i++){
			System.out.println(Constants.QUESTIONS[i]);
			answer = IOUtils.readFromConsole();
			if(answer == null || answer.isEmpty()){
				features[i] = Constants.THRESHOLD_FEATURE_VALUES[i];
			}else{
				try{
					features[i] = Long.valueOf(answer);
				}catch(NumberFormatException e){
					features[i] = Constants.THRESHOLD_FEATURE_VALUES[i];;
				}
			}
		}
	}
	
	/* interact with the user and fetch password for scheme initialization */
	private void getPassword(){
		System.out.println("******** SECURE LOGIN SETUP ********");
		System.out.print("Set Password : ");
		password = IOUtils.readFromConsole();
	}
	
	/* returns true if user is successfully authenticated */
	public boolean authenticate(){
		getUserFeatures();
		return Authenticator.authenticate(password, features);
	}
	
	public boolean initScheme(){
		getPassword();
		return Authenticator.initScheme(password);
	}
	
	/* display features - test method */
	private void displayFeatures(){
		for(int i = 0; i < features.length; i++){
			System.out.println(features[i]);
		}
	}
	
	public static LoginHandler getLoginHandler(){
		return new LoginHandler();
	}
	
	public static void main(String[] args){
		//Authenticator.reset();
		LoginHandler lHandler = getLoginHandler();
		if(Authenticator.isSchemeInitialized()){
			boolean check = lHandler.authenticate();
			if(check){
				System.out.println("You have been successfully authenticated");
			}else{
				System.out.println("Good try but sorry :P");
			}
		}else{
			lHandler.initScheme();
			System.out.println("Password successfully setup !!");
		}
	}
	
}
