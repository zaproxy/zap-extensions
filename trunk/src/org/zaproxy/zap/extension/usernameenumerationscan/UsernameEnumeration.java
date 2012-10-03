/**
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.usernameenumerationscan;

import java.text.MessageFormat;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.auth.ExtensionAuth;

/**
 * The UsernameEnumeration plugin identifies vulnerabilities with the login page or "forgot password" page.  
 * It identifies urls where the page results depend on whether the username supplied is valid or invalid
 * using a differentiation based approach
 * 
 *  @author Colm O'Flaherty
 */
public class UsernameEnumeration extends AbstractAppPlugin {
	/**
	 * plugin dependencies
	 */
    private static final String[] dependency = {};    	
	    
    /**
     * for logging.
     */
    private static Logger log = Logger.getLogger(UsernameEnumeration.class);
    
    /**
     * determines if we should output Debug level logging
     */
    private boolean debugEnabled = log.isDebugEnabled(); 

    /**
     * contains the internationalisation (i18n) messages. Must be statically initialised, since messages is accessed before the plugin is initialised (using init)
     */
    private ResourceBundle messages = ResourceBundle.getBundle(
            this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
    
	/** 
	 * These are LCS "constants" which indicate a direction in the backtracking array.
	 */
	private static final int NEITHER     = 0;
	private static final int UP          = 1;
	private static final int LEFT        = 2;
	private static final int UP_AND_LEFT = 3;
	
    
    /**
     * gets the internationalised message corresponding to the key
     * @param key the key to look up the internationalised message
     * @return the internationalised message corresponding to the key
     */
    public String getString(String key) {
    	try {
            return messages.getString(key);
        } catch (MissingResourceException e) {
            return '!' + key + '!';
        }
    }
    
    /**
     * gets the internationalised message corresponding to the key, using the parameters supplied
     * @param key the key to look up the internationalised message
     * @param params the parameters used to internationalise the message
     * @return the internationalised message corresponding to the key, using the parameters supplied
     */
    public String getString(String key, Object... params  ) {
    	try {
            return MessageFormat.format(messages.getString(key), params);
        } catch (MissingResourceException e) {
            return '!' + key + '!';
        }
    }
        
    @Override
    public int getId() {
        return 40023;
    }

    @Override
    public String getName() {
    	return getString("usernameenumeration.name");
    }

    @Override
    public String[] getDependency() {        
        return dependency;
    }

    @Override
    public String getDescription() {
        return getString("usernameenumeration.desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;  //allows information (usernames) to be gathered
    }

    @Override
    public String getSolution() {
        return getString("usernameenumeration.soln");
    }

    @Override
    public String getReference() {
        return getString("usernameenumeration.refs");  
    }

    @Override
    public void init() {
    	//DEBUG: turn on for debugging
    	//TODO: turn this off
    	log.setLevel(org.apache.log4j.Level.DEBUG);
    	this.debugEnabled = true;

    	if ( this.debugEnabled ) log.debug("Initialising");
    }


    /**
     * looks for username enumeration in the login page, by changing the username field to be a valid / invalid user, and looking for differences in the response
     */
	@Override
	public void scan() {

		//the technique to determine if usernames can be enumerated is as follows, using a variant of the Freiling+Schinzel method, 
		//adapted to the case where we do not know which is the username field
		// 
		//1) Request the original URL n times. (The original URL is assumed to have a valid username, if not a valid password). Store the results in A[].
		//2) Compute the longest common subsequence (LCS) of A[] into LCS_A
		//3) for each parameter in the original URL (ie, for URL params, form params, and cookie params)
		//	4) Change the current parameter (which we assume is the username parameter) to an invalid username (randomly), and request the URL n times. Store the results in B[].
		//	5) Compute the longest common subsequence (LCS) of B[] into LCS_B
		//	6) If LCS_A <> LCS_B, then there is a Username Enumeration issue on the current parameter

		try {
        	boolean loginUrl = false;
        	
        	//are we dealing with the login url? 
        	try {
        		ExtensionAuth extAuth = (ExtensionAuth) Control.getSingleton().getExtensionLoader().getExtension(ExtensionAuth.NAME);
        		URI loginUri = extAuth.getApi().getLoginRequest().getRequestHeader().getURI();
        		URI requestUri = getBaseMsg().getRequestHeader().getURI();
        		if (	requestUri.getScheme().equals(loginUri.getScheme()) && 
        				requestUri.getHost().equals(loginUri.getHost()) &&
        				requestUri.getPort() == loginUri.getPort() &&
        				requestUri.getPath().equals(loginUri.getPath()) ) {
        			//we got this far.. only the method (GET/POST), user details, query params, fragment, and POST params 
        			//are possibly different from the login page.
        			loginUrl = true;
        		}
        	}
        	catch (Exception e) {
        		log.error("For the Username Enumeration scanner to actually do anything, a Login Page *must* be set!");
        	}
        	
        	//the Username Enumeration scanner will only run for logon pages
        	if (loginUrl == false) return;
        	
        	//log.debug("We have the Login URL. Looking for Username Enumeration issues");

        	//find all params set in the request (GET/POST/Cookie)
    		TreeSet<HtmlParameter> htmlParams = new TreeSet<> ();
        	htmlParams.addAll(getBaseMsg().getRequestHeader().getCookieParams());  //request cookies only. no response cookies
    		htmlParams.addAll(getBaseMsg().getFormParams());  //add in the POST params
    		htmlParams.addAll(getBaseMsg().getUrlParams()); //add in the GET params
    		
    		int numberOfRequests = 0; 
    		if ( this.getAttackStrength() == AttackStrength.INSANE ) {
    			numberOfRequests= 50;
    		} else if ( this.getAttackStrength() == AttackStrength.HIGH ) {
    			numberOfRequests= 15;
    		} else if ( this.getAttackStrength() == AttackStrength.MEDIUM) {
    			numberOfRequests= 5;
    		} else if ( this.getAttackStrength() == AttackStrength.LOW) {
    			numberOfRequests= 3;
    		} 
    		
    		//1) Request the original URL n times. (The original URL is assumed to have a valid username, if not a valid password). Store the results in A[].
    		//make sure to manually handle all redirects, and cookies that may be set in response.
    		//allocate enough space for the responses
    		StringBuffer baseResponses[] = new StringBuffer [numberOfRequests];
    		
    		//log.debug("About to loop for "+numberOfRequests + " iterations of the original query");
    		
    		for (int i = 0; i < numberOfRequests; i++) {
    			
    			//initialise the storage for this iteration
    			baseResponses[i]= new StringBuffer();
    			
    			//log.debug("Looping for iteration "+ i + " of "+numberOfRequests + " iterations of the original query");
    			
    			HttpMessage msgCpy = getNewMsg();  //clone the request, but not the response
    			
    			//log.debug("Sending message");
    			sendAndReceive(msgCpy, false, false);  //request the URL, but do not automatically follow redirects.
    			
    			//get all cookies set in the response
    			TreeSet<HtmlParameter> cookies = msgCpy.getResponseHeader().getCookieParams();
    			
    			int redirectCount = 0;
    			while ( HttpStatusCode.isRedirection(msgCpy.getResponseHeader().getStatusCode())) {
    				redirectCount++;
    				
    				//log.debug("Following redirect "+redirectCount + " for message "+ i + " of " +numberOfRequests + " iterations of the original query");
    				
    				//append the response to the responses so far for this particular instance
    				//this will give us a complete picture of the full set of actual traffic associated with following redirects for the request
    				baseResponses[i].append(msgCpy.getResponseHeader().getHeadersAsString());
    				baseResponses[i].append(msgCpy.getResponseBody().toString());
    				
    				//and manually follow the redirect
    				//create a new message from scratch
    				HttpMessage msgRedirect = new HttpMessage (); 
    				
	                //create a new URI from the absolute location returned, and interpret it as escaped
	            	//note that the standard says that the Location returned should be absolute, but it ain't always so...
	                URI newLocation = new URI (msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION), true);
	                try {
	                	msgRedirect.getRequestHeader().setURI(newLocation);
					} catch (Exception e) {
						//the Location field contents may not be standards compliant. Lets generate a uri to use as a workaround where a relative path was 
		                //given instead of an absolute one
		                URI newLocationWorkaround = new URI(msgCpy.getRequestHeader().getURI(), msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION), true);			                
						//try again, except this time, if it fails, don't try to handle it
						//if (this.debugEnabled) log.debug("The Location ["+ newLocation + "] specified in a redirect was not valid (not absolute?). Trying absolute workaround url ["+ newLocationWorkaround + "]");
						msgRedirect.getRequestHeader().setURI(newLocationWorkaround);
					}
	                msgRedirect.getRequestHeader().setMethod(HttpRequestHeader.GET); //it's always a GET for a redirect
	                msgRedirect.getRequestHeader().setContentLength(0);  //since we send a GET, the body will be 0 long
	                if ( cookies != null) {
	                	//if a previous request sent back a cookie that has not since been invalidated, we need to set that cookie when following redirects, as a browser would
	                	//if ( this.debugEnabled ) log.debug("Adding in cookies ["+ cookies+ "] for a redirect");
	                	msgRedirect.getRequestHeader().setCookieParams(cookies);
	                	
	                }
	                
	                //if ( this.debugEnabled ) log.debug("DEBUG: Following redirect to ["+ newLocation +"]");	                
	                sendAndReceive(msgRedirect, false, false);  //do NOT redirect.. handle it here
	                
	                //handle scenario where a cookie is unset in a subsequent iteration, or where the same cookie name is later re-assigned a different value
	                //ie, in these cases, do not simply (and dumbly) accumulate cookie detritus.
	    			//first get all cookies set in the response
	    			TreeSet<HtmlParameter> cookiesTemp = msgRedirect.getResponseHeader().getCookieParams();
	    			for (Iterator <HtmlParameter> redirectSetsCookieIterator = cookiesTemp.iterator(); redirectSetsCookieIterator.hasNext();) {
	    				HtmlParameter cookieJustSet = redirectSetsCookieIterator.next();
	    				//loop through each of the cookies we know about in cookies, to see if it matches by name.
	    				//if so, delete that cookie, and add the one that was just set to cookies.
	    				//if not, add the one that was just set to cookies.
	    				for (Iterator <HtmlParameter> knownCookiesIterator = cookies.iterator(); knownCookiesIterator.hasNext();) {
	    					HtmlParameter knownCookie = knownCookiesIterator.next();
	    					if (cookieJustSet.getName().equals(knownCookie.getName())) {
	    						cookies.remove(knownCookie);
	    						break; //out of the loop for known cookies, back to the next cookie set in the response 
	    					}
	    				//we can now safely add the cookie that was just set into cookies, knowing it does not clash with anything else in there.
	    				cookies.add(cookieJustSet);
	    				} //end of loop for cookies we already know about
	    			} //end of for loop for cookies just set in the redirect
	    			
	    		msgCpy=msgRedirect;  //store the last redirect message into the MsgCpy, as we will be using it's output in a moment..
    			} //end of loop to follow redirects
    			
    			//log.debug("Done following redirects!");
    			
    			//append the response to the responses so far for this particular instance
				//this will give us a complete picture of the full set of actual traffic associated with following redirects for the request
				baseResponses[i].append(msgCpy.getResponseHeader().getHeadersAsString());
				baseResponses[i].append(msgCpy.getResponseBody().toString());
			    			
    			//log.debug("Instance ["+i+"] of the base message followed ["+redirectCount+"] redirects to produce ["+baseResponses[i]+"]");
    		}
    		
    		
    		//2) Compute the longest common subsequence (LCS) of A[] into LCS_A
    		//Note: in the Freiling and Schinzel method, this is calculated recursively. We calculate it iteratively, but using an equivalent method
    		String longestCommonSubstringA = baseResponses[0].toString();
    		//Note: we start at 1, not 0, so the first calculation will be LCS([0],[1]), then LCS(LCS([0], [1]),[2]), and so forth
    		for (int i = 1; i < numberOfRequests; i++) {  
    			longestCommonSubstringA = this.longestCommonSubsequence(longestCommonSubstringA, baseResponses[i].toString());
    		}
    		//log.debug("The LCS of A is ["+longestCommonSubstringA+"]");
    		

    		//3) for each parameter in the original URL (ie, for URL params, form params, and cookie params)
    		
    		int counter = 0;
    		for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext(); ) {
    			
            	HttpMessage msgModifiedParam = getNewMsg();            	            	
    			HtmlParameter currentHtmlParameter = iter.next();
    			
    			log.debug("Handling ["+currentHtmlParameter.getType()+"] parameter ["+currentHtmlParameter.getName()+"], with value ["+currentHtmlParameter.getValue()+"]");
    			
    			//4) Change the current parameter (which we assume is the username parameter) to an invalid username (randomly), and request the URL n times. Store the results in B[].
    			
    			//get a random user name the same length as the original!
    			StringBuffer invalidUsername=new StringBuffer("");
    			for (int i=0; i< currentHtmlParameter.getValue().length(); i++) {
	    			Random r = new Random();
	    			invalidUsername.append((char)(r.nextInt(26) + 'a'));
	    			}
    			log.debug("The invalid username chosen was ["+invalidUsername+"]");
    			
    			//if ( this.debugEnabled ) log.debug("Scanning URL ["+ msg1.getRequestHeader().getMethod()+ "] ["+ msg1.getRequestHeader().getURI() + "], ["+ currentHtmlParameter.getType()+"] field ["+ currentHtmlParameter.getName() + "] with value ["+currentHtmlParameter.getValue()+"] for Username Enumeration");
    			TreeSet <HtmlParameter> requestParams = null;
    			if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.cookie)) {
    				requestParams = msgModifiedParam.getRequestHeader().getCookieParams();
    				requestParams.remove(currentHtmlParameter);
    				requestParams.add(new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(), invalidUsername.toString())); //add in the invalid username
    				msgModifiedParam.setCookieParams(requestParams);
    			}
    			else if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.url)) {
    				requestParams = msgModifiedParam.getUrlParams();
    				requestParams.remove(currentHtmlParameter);
    				requestParams.add(new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(), invalidUsername.toString())); //add in the invalid username
    				msgModifiedParam.setGetParams(requestParams);
    			}
    			else if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.form)) {
    				requestParams = msgModifiedParam.getFormParams();
    				requestParams.remove(currentHtmlParameter);
    				requestParams.add(new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(), invalidUsername.toString())); //add in the invalid username
    				msgModifiedParam.setFormParams(requestParams);
    			}
    			    			
    			StringBuffer incorrectUserResponses[] = new StringBuffer [numberOfRequests];

    			//log.debug("About to loop for "+numberOfRequests + " iterations with an incorrect user of the same length");

    			for (int i = 0; i < numberOfRequests; i++) {

    				//initialise the storage for this iteration
    				incorrectUserResponses[i]= new StringBuffer();

    				//log.debug("Looping for iteration "+ i + " of "+numberOfRequests + " iterations of the original query");

    				HttpMessage msgCpy = msgModifiedParam;  //use the message we already set up, with the modified parameter value

    				//log.debug("Sending message");
    				sendAndReceive(msgCpy, false, false);  //request the URL, but do not automatically follow redirects.

    				//get all cookies set in the response
    				TreeSet<HtmlParameter> cookies = msgCpy.getResponseHeader().getCookieParams();

    				int redirectCount = 0;
    				while ( HttpStatusCode.isRedirection(msgCpy.getResponseHeader().getStatusCode())) {
    					redirectCount++;

    					//log.debug("Following redirect "+redirectCount + " for message "+ i + " of " +numberOfRequests + " iterations of the original query");

    					//append the response to the responses so far for this particular instance
    					//this will give us a complete picture of the full set of actual traffic associated with following redirects for the request
    					incorrectUserResponses[i].append(msgCpy.getResponseHeader().getHeadersAsString());
    					incorrectUserResponses[i].append(msgCpy.getResponseBody().toString());

    					//and manually follow the redirect
    					//create a new message from scratch
    					HttpMessage msgRedirect = new HttpMessage (); 

    					//create a new URI from the absolute location returned, and interpret it as escaped
    					//note that the standard says that the Location returned should be absolute, but it ain't always so...
    					URI newLocation = new URI (msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION), true);
    					try {
    						msgRedirect.getRequestHeader().setURI(newLocation);
    					} catch (Exception e) {
    						//the Location field contents may not be standards compliant. Lets generate a uri to use as a workaround where a relative path was 
    						//given instead of an absolute one
    						URI newLocationWorkaround = new URI(msgCpy.getRequestHeader().getURI(), msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION), true);			                
    						//try again, except this time, if it fails, don't try to handle it
    						//if (this.debugEnabled) log.debug("The Location ["+ newLocation + "] specified in a redirect was not valid (not absolute?). Trying absolute workaround url ["+ newLocationWorkaround + "]");
    						msgRedirect.getRequestHeader().setURI(newLocationWorkaround);
    					}
    					msgRedirect.getRequestHeader().setMethod(HttpRequestHeader.GET); //it's always a GET for a redirect
    					msgRedirect.getRequestHeader().setContentLength(0);  //since we send a GET, the body will be 0 long
    					if ( cookies != null) {
    						//if a previous request sent back a cookie that has not since been invalidated, we need to set that cookie when following redirects, as a browser would
    						//if ( this.debugEnabled ) log.debug("Adding in cookies ["+ cookies+ "] for a redirect");
    						msgRedirect.getRequestHeader().setCookieParams(cookies);

    					}

    					//if ( this.debugEnabled ) log.debug("DEBUG: Following redirect to ["+ newLocation +"]");	                
    					sendAndReceive(msgRedirect, false, false);  //do NOT redirect.. handle it here

    					//handle scenario where a cookie is unset in a subsequent iteration, or where the same cookie name is later re-assigned a different value
    					//ie, in these cases, do not simply (and dumbly) accumulate cookie detritus.
    					//first get all cookies set in the response
    					TreeSet<HtmlParameter> cookiesTemp = msgRedirect.getResponseHeader().getCookieParams();
    					for (Iterator <HtmlParameter> redirectSetsCookieIterator = cookiesTemp.iterator(); redirectSetsCookieIterator.hasNext();) {
    						HtmlParameter cookieJustSet = redirectSetsCookieIterator.next();
    						//loop through each of the cookies we know about in cookies, to see if it matches by name.
    						//if so, delete that cookie, and add the one that was just set to cookies.
    						//if not, add the one that was just set to cookies.
    						for (Iterator <HtmlParameter> knownCookiesIterator = cookies.iterator(); knownCookiesIterator.hasNext();) {
    							HtmlParameter knownCookie = knownCookiesIterator.next();
    							if (cookieJustSet.getName().equals(knownCookie.getName())) {
    								cookies.remove(knownCookie);
    								break; //out of the loop for known cookies, back to the next cookie set in the response 
    							}
    							//we can now safely add the cookie that was just set into cookies, knowing it does not clash with anything else in there.
    							cookies.add(cookieJustSet);
    						} //end of loop for cookies we already know about
    					} //end of for loop for cookies just set in the redirect

    					msgCpy=msgRedirect;  //store the last redirect message into the MsgCpy, as we will be using it's output in a moment..
    				} //end of loop to follow redirects

    				//log.debug("Done following redirects!");

    				//append the response to the responses so far for this particular instance
    				//this will give us a complete picture of the full set of actual traffic associated with following redirects for the request
    				incorrectUserResponses[i].append(msgCpy.getResponseHeader().getHeadersAsString());
    				incorrectUserResponses[i].append(msgCpy.getResponseBody().toString());

    				//log.debug("Instance ["+i+"] of the message for an incorrect user followed ["+redirectCount+"] redirects to produce ["+incorrectUserResponses[i]+"]");
    			}

    			
    			//5) Compute the longest common subsequence (LCS) of B[] into LCS_B
        		//Note: in the Freiling and Schinzel method, this is calculated recursively. We calculate it iteratively, but using an equivalent method
        		String longestCommonSubstringB = incorrectUserResponses[0].toString();
        		//Note: we start at 1, not 0, so the first calculation will be LCS([0],[1]), then LCS(LCS([0], [1]),[2]), and so forth
        		for (int i = 1; i < numberOfRequests; i++) {  
        			longestCommonSubstringB = this.longestCommonSubsequence(longestCommonSubstringB, incorrectUserResponses[i].toString());
        		}
        		//log.debug("The LCS of B is ["+longestCommonSubstringB+"]");
        		
//        		6) If LCS_A <> LCS_B, then there is a Username Enumeration issue on the current parameter
        		if (! longestCommonSubstringA.equals(longestCommonSubstringB)) {
        			log.debug("["+currentHtmlParameter.getType()+ "] parameter ["+currentHtmlParameter.getName()+"] leaks information based on LCS A ["+longestCommonSubstringA+"] and LCS B ["+longestCommonSubstringB+"]");
    				
        			String extraInfo = getString("usernameenumeration.alert.extrainfo", currentHtmlParameter.getType(), currentHtmlParameter.getName(), longestCommonSubstringA, currentHtmlParameter.getValue(), longestCommonSubstringB, invalidUsername.toString());
        			String attack = getString("usernameenumeration.alert.attack", currentHtmlParameter.getType(), currentHtmlParameter.getName());
        			String vulnname=getString("usernameenumeration.name");
        			String vulndesc=getString("usernameenumeration.desc");
        			String vulnsoln=getString("usernameenumeration.soln");
        			
        			//call bingo with some extra info, indicating that the alert is 
        			bingo(Alert.RISK_MEDIUM, Alert.WARNING, vulnname, vulndesc, 
        					getBaseMsg().getRequestHeader().getURI().getURI(),
        					currentHtmlParameter.getName(),  attack, 
        					extraInfo, vulnsoln, getBaseMsg());
        					        			
        			log.info(extraInfo);
        		} else {
        			log.debug("["+currentHtmlParameter.getType()+ "] parameter ["+currentHtmlParameter.getName()+"] looks ok");
        		}
    			
    		} //end of the for loop around the parameter list

        } catch (Exception e) {
        	//Do not try to internationalise this.. we need an error message in any event.. 
        	//if it's in English, it's still better than not having it at all. 
            log.error("An error occurred checking a url for Username Enumeration issues", e);
        }
	}	
	
	
	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM;
	}


	/**
	 * gets the Longest Common Subsequence of two strings, using Dynamic programming techniques
	 * @param a the first String
	 * @param b the second String
	 * @return the Longest Common Subsequence of a and b
	 * 
	 * @see http://bix.ucsd.edu/bioalgorithms/downloads/code/LCS.java
	 * Note: 
	 * This code is provided AS-IS.
	 * You may use this code in any way you see fit, EXCEPT as the answer to a homework
	 * problem or as part of a term project in which you were expected to arrive at this
	 * code yourself.  
	 * 
	 * Copyright (C) 2005 Neil Jones.
	 */
	public String longestCommonSubsequence (String a, String b) {
		int n = a.length();
		int m = b.length();
		int S[][] = new int[n+1][m+1];
		int R[][] = new int[n+1][m+1];
		int ii, jj;

		// It is important to use <=, not <.  The next two for-loops are initialization
		for(ii = 0; ii <= n; ++ii) {
			S[ii][0] = 0;
			R[ii][0] = UP;
		}
		for(jj = 0; jj <= m; ++jj) {
			S[0][jj] = 0;
			R[0][jj] = LEFT;
		}

		// This is the main dynamic programming loop that computes the score and
		// backtracking arrays.
		for(ii = 1; ii <= n; ++ii) {
			for(jj = 1; jj <= m; ++jj) { 

				if( a.charAt(ii-1) == b.charAt(jj-1) ) {
					S[ii][jj] = S[ii-1][jj-1] + 1;
					R[ii][jj] = UP_AND_LEFT;
				}

				else {
					S[ii][jj] = S[ii-1][jj-1] + 0;
					R[ii][jj] = NEITHER;
				}

				if( S[ii-1][jj] >= S[ii][jj] ) {	
					S[ii][jj] = S[ii-1][jj];
					R[ii][jj] = UP;
				}

				if( S[ii][jj-1] >= S[ii][jj] ) {
					S[ii][jj] = S[ii][jj-1];
					R[ii][jj] = LEFT;
				}
			}
		}

		// The length of the longest substring is S[n][m]
		ii = n; 
		jj = m;
		int pos = S[ii][jj] - 1;
		char lcs[] = new char[ pos+1 ];

		// Trace the backtracking matrix.
		while( ii > 0 || jj > 0 ) {
			if( R[ii][jj] == UP_AND_LEFT ) {
				ii--;
				jj--;
				lcs[pos--] = a.charAt(ii);
			}

			else if( R[ii][jj] == UP ) {
				ii--;
			}

			else if( R[ii][jj] == LEFT ) {
				jj--;
			}
		}

		return new String(lcs);
	}


}
