package com.scs.security;

/* main workflow of handling user login */
public class LoginHandler {
	
	private static boolean INITIALIZED = false;
	
	private String password;
	private long[] features = new long[Constants.M];
	
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
	
	/* returns true if user is successfully authenticated */
	public boolean authenticate(){
		getUserFeatures();
		return Authenticator.authenticate(password, features);
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
		boolean check = (getLoginHandler()).authenticate();
		if(check){
			System.out.println("You have been successfully authenticated");
		}else{
			System.out.println("Good try but sorry :P");
		}
	}
	
}
