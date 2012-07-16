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
package org.zaproxy.zap.extension.ldapinjectionscan;

import java.text.MessageFormat;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HtmlParameter.Type;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * The LDAPInjection plugin identifies LDAP injection vulnerabilities with
 * GET, POST, and cookie parameters, as well as Headers (TODO!).
 *
 *  @author Colm O'Flaherty, Encription Ireland Ltd
 */
public class LDAPInjection extends AbstractAppPlugin {
	/**
	 * plugin dependencies
	 */
    private static final String[] dependency = {};    	
	    
    /**
     * for logging.
     */
    private static Logger log = Logger.getLogger(LDAPInjection.class);
    
    /**
     * determines if we should output Debug level logging
     */
    private boolean debugEnabled = log.isDebugEnabled(); 

    /**
     * contains the internationalisation (i18n) messages. Must be statically initialised, since messages is accessed before the plugin is initialised (using init)
     */
    private ResourceBundle messages = ResourceBundle.getBundle(
            this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
    
    private static final String errorAttack = "|!<>=~=>=<=*(),+-\"'\\/&;";
    //Note the ampersand at the end.. causes problems if earlier in the string..
    //and the semicolon after that..
    
    
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
        
    /* 
     * returns the plugin id
     * @see org.parosproxy.paros.core.scanner.Test#getId()
     */
    @Override
    public int getId() {
        return 40015;
    }

    /* returns the plugin name
     * @see org.parosproxy.paros.core.scanner.Test#getName()
     */
    @Override
    public String getName() {
    	return getString("ldapinjection.name");
    }

    /* returns the plugin dependencies
     * @see org.parosproxy.paros.core.scanner.Test#getDependency()
     */
    @Override
    public String[] getDependency() {        
        return dependency;
    }

    /* returns the plugin description
     * @see org.parosproxy.paros.core.scanner.Test#getDescription()
     */
    @Override
    public String getDescription() {
        return getString("ldapinjection.desc");
    }

    /* returns the type of plugin
     * @see org.parosproxy.paros.core.scanner.Test#getCategory()
     */
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.core.scanner.Test#getSolution()
     */
    @Override
    public String getSolution() {
        return getString("ldapinjection.soln");
    }

    /* returns references for the plugin
     * @see org.parosproxy.paros.core.scanner.Test#getReference()
     */
    @Override
    public String getReference() {
        return getString("ldapinjection.refs");  
    }

    /* initialise
     * @see org.parosproxy.paros.core.scanner.AbstractTest#init()
     */
    @Override
    public void init() {
    	//DEBUG: turn on for debugging
    	//TODO: turn this off
    	//log.setLevel(org.apache.log4j.Level.DEBUG);
    	//this.debugEnabled = true;

    	if ( this.debugEnabled ) log.debug("Initialising");
    }


    /**
     * scans all POST, GET, Cookie params, and header fields for LDAP injection vulnerabilities. 
     * Requires min one extra request for each parameter (cookie, URL, POST param)
     */
	@Override
	public void scan() {
		
		try {
			//TODO: get the header fields and directives as well
			
        	//find all params set in the request (GET(URL)/POST(FORM)/Cookie)    		
        	TreeSet<HtmlParameter> htmlParams = new TreeSet<HtmlParameter> (); 
    		htmlParams.addAll(getBaseMsg().getRequestHeader().getCookieParams());  //request cookies only. no response cookies
    		htmlParams.addAll(getBaseMsg().getFormParams());  //add in the POST params
    		htmlParams.addAll(getBaseMsg().getUrlParams()); //add in the GET params
    		
    		////for each parameter in turn, 
    		for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext(); ) {    			
            	HttpMessage msg1Initial = getNewMsg();            	            	
    			HtmlParameter currentHtmlParameter = iter.next();
    			    			
    			if ( this.debugEnabled ) log.debug("Scanning URL ["+ msg1Initial.getRequestHeader().getMethod()+ "] ["+ msg1Initial.getRequestHeader().getURI() + "], ["+ currentHtmlParameter.getType()+"] field ["+ currentHtmlParameter.getName() + "] with value ["+currentHtmlParameter.getValue()+"] for LDAP Injection");
    				
				TreeSet <HtmlParameter> requestParams = null; 
				if (currentHtmlParameter.getType() == Type.cookie) 
					requestParams = msg1Initial.getCookieParams();
				else if (currentHtmlParameter.getType() == Type.form)
					requestParams = msg1Initial.getFormParams();
				else if (currentHtmlParameter.getType() == Type.url)
					requestParams = msg1Initial.getUrlParams();
				else {
					//just in case... nothing else exists now, but maybe later... 
					throw new Exception ("Unknown parameter type ["+ currentHtmlParameter.getType() + "] for parameter ["+ currentHtmlParameter.getName()+ "]");
				}
    			//delete the original parameter from the set of parameters
    			requestParams.remove(currentHtmlParameter);
    			//create a new cookie parameter with various LDAP metacharacters, to see if this trips the code up
    			//note: use the same name and type as the original
    			HtmlParameter errorParameter = new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(),
    					errorAttack);    			
    			requestParams.add (errorParameter);
    			
				if (currentHtmlParameter.getType() == Type.cookie) 
					msg1Initial.setCookieParams(requestParams);
				else if (currentHtmlParameter.getType() == Type.form)
					msg1Initial.setFormParams(requestParams);
				else if (currentHtmlParameter.getType() == Type.url)
					msg1Initial.setGetParams(requestParams);

				//send it, and see what happens :)
				sendAndReceive(msg1Initial);
				
				//compare the request response with each of the known error messages, for each of the known LDAP implementations.
				//in order to minimise false positives, only consider a match for the error message in the response
				//if the string also did NOT occur in the original (unmodified) response
								
				//TODO: move some of this code to the the static constructor.. once it works :) 
				String ldapImplementationsFlat = getString("ldapinjection.knownimplementations");
				String [] ldapImplementations = ldapImplementationsFlat.split(":");
				for (String ldapImplementation : ldapImplementations) {  //for each LDAP implementation
					//for each known LDAP implementation
					String errorMessageFlat = getString("ldapinjection."+ldapImplementation+".errormessages");
					String [] errorMessages = errorMessageFlat.split(":");
					for (String errorMessage : errorMessages) {  //for each error message for the given LDAP implemention
						//compile it into a pattern
						//log.error("Compiling pattern for ["+errorMessage + "]" );
						Pattern errorPhpSearchPattern = Pattern.compile(errorMessage);
						//if the pattern was found in the new response, but not in the original response (for the unmodified request)
						//and the new response was OK (200), then we have a match.. LDAP injection!
						if ( msg1Initial.getResponseHeader().getStatusCode() == HttpStatusCode.OK && 
		        				responseMatches (msg1Initial, errorPhpSearchPattern) &&
		        				! responseMatches (getBaseMsg(), errorPhpSearchPattern) ) {
		    				//response code is ok, and the HTML matches one of the known PHP LDAP errors.
		    				//so raise the error, and move on to the next parameter
		    				String extraInfo = getString("ldapinjection.alert.extrainfo", 
		        						currentHtmlParameter.getType(), 
		        						currentHtmlParameter.getName(),
		        						getBaseMsg().getRequestHeader().getMethod(),  
		    							getBaseMsg().getRequestHeader().getURI().getURI(),
		    							errorAttack, ldapImplementation, errorPhpSearchPattern);
		
		        			String attack = getString("ldapinjection.alert.attack", currentHtmlParameter.getType(), currentHtmlParameter.getName(), errorAttack);
		        			String vulnname=getString("ldapinjection.name");
		        			String vulndesc=getString("ldapinjection.desc");
		        			String vulnsoln=getString("ldapinjection.soln");
		        			
		        			bingo(Alert.RISK_HIGH, Alert.WARNING, vulnname, vulndesc, 
		        					getBaseMsg().getRequestHeader().getURI().getURI(),
		        					currentHtmlParameter.getName(),  attack, 
		        					extraInfo, vulnsoln, getBaseMsg());
		        					
		        			//and log it
		    				String logMessage = getString ("ldapinjection.alert.logmessage", 
		    							getBaseMsg().getRequestHeader().getMethod(),  
		    							getBaseMsg().getRequestHeader().getURI().getURI(), 
		    							currentHtmlParameter.getType(), 
		    							currentHtmlParameter.getName(), 
		    							errorAttack, ldapImplementation, errorPhpSearchPattern);
		    				log.info(logMessage);
		    				
		    				continue; // to the next parameter (to infinity and beyond!)
		        		}
					} //for each error message for the given LDAP implemention
				} //for each LDAP implementation

        			
    		} //end of the for loop around the parameter list

        } catch (Exception e) {
        	//Do not try to internationalise this.. we need an error message in any event.. 
        	//if it's in English, it's still better than not having it at all. 
            log.error("An error occurred checking a url for LDAP Injection issues", e);
        }
	}	

	/**
	 * returns does the Message Response matche the pattern provided?
	 * @param msg the Message whose response we will examine
	 * @param pattern the pattern which we will look for in the Message Body
	 * @return true/false. D'uh! (It being a boolean, and all that)
	 */
	protected boolean responseMatches (HttpMessage msg, Pattern pattern) {
		Matcher matcher = pattern.matcher(msg.getResponseBody().toString());
		return matcher.find();
	}
	
}
