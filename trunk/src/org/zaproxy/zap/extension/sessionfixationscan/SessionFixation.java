/**
 */
package org.zaproxy.zap.extension.sessionfixationscan;

import java.text.MessageFormat;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.TreeSet;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * @author Colm O'Flaherty
 * The SessionFixation plugin identifies Session Fixation vulnerabilities
 */
public class SessionFixation extends AbstractAppPlugin {
	/**
	 * plugin dependencies
	 */
    private static final String[] dependency = {};    	
	    
    /**
     * for logging.
     */
    private static Logger log = Logger.getLogger(SessionFixation.class);

    /**
     * contains the internationalisation (i18n) messages. Must be statically initialised, since messages is accessed before the plugin is initialised (using init)
     */
    private ResourceBundle messages = ResourceBundle.getBundle(
            this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
    
    
    public String getString(String key) {
        try {
            return messages.getString(key);
        } catch (MissingResourceException e) {
            return '!' + key + '!';
        }
    }
    
    public String getString(String key, Object... params  ) {
        try {
            return MessageFormat.format(messages.getString(key), params);
        } catch (MissingResourceException e) {
            return '!' + key + '!';
        }
    }
    
    

    
    /* returns the plugin id
     * @see org.parosproxy.paros.core.scanner.Test#getId()
     */
    @Override
    public int getId() {
        return 40013;
    }

    /* returns the plugin name
     * @see org.parosproxy.paros.core.scanner.Test#getName()
     */
    @Override
    public String getName() {
    	return getString("sessionfixation.name");
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
        return getString("sessionfixation.desc");
    }

    /* returns the type of plugin
     * @see org.parosproxy.paros.core.scanner.Test#getCategory()
     */
    @Override
    public int getCategory() {
        return Category.MISC;
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.core.scanner.Test#getSolution()
     */
    @Override
    public String getSolution() {
        return getString("sessionfixation.soln");
    }

    /* returns references for the plugin
     * @see org.parosproxy.paros.core.scanner.Test#getReference()
     */
    @Override
    public String getReference() {
        return getString("sessionfixation.refs");  
    }

    /* initialise
     * @see org.parosproxy.paros.core.scanner.AbstractTest#init()
     */
    @Override
    public void init() {
    	//DEBUG: turn on for debugging
    	//log.setLevel(org.apache.log4j.Level.DEBUG);

    	if ( log.isDebugEnabled()) log.debug("Initialising");
    }


    /**
     * scans all POST, GET, Cookie params for Session fields, and looks for SessionFixation vulnerabilities
     */
	@Override
	public void scan() {
		
		//TODO: scan the GET and POST params for session id fields.
        try {
        	//find all params set in the request (GET/POST/Cookie)
    		//Note: this will be the full set, before we delete anything.
    		
    		TreeSet<HtmlParameter> htmlParams = getBaseMsg().getCookieParams();  //gets both request and response cookie parameters..
    		
    		htmlParams.addAll(getBaseMsg().getFormParams());  //add in the POST params
    		htmlParams.addAll(getBaseMsg().getUrlParams()); //add in the GET params
    		
    		////for each field in turn, 
    		//int counter = 0;
    		for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext(); ) {
    			
            	HttpMessage msg1Final;
        		HttpMessage msg1Initial = getNewMsg();
            	//HttpMessage msg1Initial = getBaseMsg();
            	            	
    			////debug logic only.. to do first field only
    			//counter ++;
    			//if ( counter > 1 )
    			//	return;
    			
    			HtmlParameter currentHtmlParameter = iter.next();
    			
    			//Useful for debugging, but I can't find a way to view this data in the GUI, so leave it out for now.
    			//msg1Initial.setNote("Message 1 for parameter "+ currentHtmlParameter);
    			
    			if ( log.isDebugEnabled()) log.debug("Scanning URL ["+ msg1Initial.getRequestHeader().getMethod()+ "] ["+ msg1Initial.getRequestHeader().getURI() + "], ["+ currentHtmlParameter.getType()+"] field ["+ currentHtmlParameter.getName() + "] for Session Fixation");
    			//set the field to be empty, and re-send it
        		//Note that there is no variant for Cookies.. just POSTS (forms) and GETS (urls)
        		if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.cookie)) {
        			/////remove the named cookie parameter from the request..
        			TreeSet <HtmlParameter> cookieRequestParams = msg1Initial.getRequestHeader().getCookieParams();
        			cookieRequestParams.remove(currentHtmlParameter);
        			msg1Initial.setCookieParams(cookieRequestParams);
        		}
        		else {
        			//TODO: other types such as URL parameters and form parameters.. to be implemnted later
        			if ( log.isDebugEnabled()) log.debug("Not scanning URL ["+ msg1Initial.getRequestHeader().getMethod()+ "] ["+ msg1Initial.getRequestHeader().getURI() + "], ["+ currentHtmlParameter.getType()+"] field ["+ currentHtmlParameter.getName() + "] yet: only cookie parameters are yet supported!");
        			continue;  //to next parameter
        		}
        		
        		//send the message, minus the parameters, and see how it comes back.
        		//Note: do NOT automatically follow redirects.. handle those here instead.
        		sendAndReceive(msg1Initial, false, false);
        		
        		/////////////////////////////
        		//create a copy of msg1 to play with to handle redirects (if any).
        		//we use a copy because if we change msg1 itself, it messes the URL and params displayed on the GUI.
        		//Note that we need to clone the Request and the Response..
	       
	            msg1Final=msg1Initial;
	            HtmlParameter cookieBack1 = getParameterCookie (msg1Initial, currentHtmlParameter.getName());
	            
	            HttpMessage temp = msg1Initial.cloneAll();
	            
	            int redirectsFollowed1 = 0;
	            while ( HttpStatusCode.isRedirection(temp.getResponseHeader().getStatusCode())) {
	            	
	            	//HttpMessage temp = msg1Initial.cloneRequest();
	            	
	            	redirectsFollowed1++;
	            	if ( redirectsFollowed1 > 10 ) {
	            		throw new Exception ("Too many redirects were specified in the first message");
	            	}
	            	//build up a new location to follow
	                String location = temp.getResponseHeader().getHeader(HttpHeader.LOCATION);
	                URI baseUri = temp.getRequestHeader().getURI();
	                URI newLocation = new URI(baseUri, location, false);
	                
	                //and follow it
	                //need to clear the params (which would come from the initial POST, otherwise)
	                temp.getRequestHeader().setGetParams(new TreeSet<HtmlParameter>());
	                temp.setRequestBody("");
	                temp.setResponseBody(""); //make sure no values accidentally carry from one iteration to the next
	                
	                temp.getRequestHeader().setURI(newLocation);
	                temp.getRequestHeader().setMethod(HttpRequestHeader.GET);
	                temp.getRequestHeader().setContentLength(0);  //since we send a GET, the body will be 0 long
	                if ( cookieBack1 != null) {
	                	//if the previous request sent back a cookie, we need to set that cookie when following redirects, as a browser would
	                	if ( log.isDebugEnabled()) log.debug("Adding in cookie ["+ cookieBack1+ "] for a redirect");
	                	TreeSet <HtmlParameter> forwardCookieParams = temp.getRequestHeader().getCookieParams();
	                	forwardCookieParams.add(cookieBack1);
	                	temp.getRequestHeader().setCookieParams(forwardCookieParams);
	                }
	                
	                if ( log.isDebugEnabled()) log.debug("DEBUG: Message 1 causes us to follow redirect to ["+ newLocation +"]");
	                
	                sendAndReceive(temp, false, false);  //do NOT redirect.. handle it here
	                
	                //handle any cookies set from following redirects that override the cookie set in the redirect itself (if any)
	                //note that this will handle the case where a latter cookie unsets one set earlier.
	                HtmlParameter cookieBack1Temp = getParameterCookie (temp, currentHtmlParameter.getName());
	        		if ( cookieBack1Temp != null  ) {
	        			cookieBack1 = cookieBack1Temp;
	        		}
	        		
	        		//reset the "final" version of message1 to use the final response in the chain
	        		msg1Final=temp;
	        		temp = temp.cloneAll();  //create a new message for each communication
	            }
        		///////////////////////////
	            
	            //if non-200 on the final response for message 1, no point in continuing. Bale out.
        		if (msg1Final.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
        			if ( log.isDebugEnabled()) log.debug("Got a non-200 response code ["+ msg1Final.getResponseHeader().getStatusCode()+"] when sending ["+msg1Initial.getRequestHeader().getURI()+ "] with param ["+ currentHtmlParameter +"] = NULL (possibly somewhere in the redirects)");
        			continue;
        		}
        		
        		//now check that the response set a cookie. if it didn't, then either..
        		//1) we are messing with the wrong field
        		//2) the app doesn't do sessions
        		//either way, there is not much point in continuing to look at this field..
        		
        		if ( cookieBack1 == null || cookieBack1.getValue() == null ) {
        			//no cookie was set, or the cookie param was set to a null value
        			if ( log.isDebugEnabled()) log.debug("The Cookie parameter was NOT set in the response, when cookie param ["+ currentHtmlParameter.getName() + "] was set to NULL: "+cookieBack1);
        			continue;
        		}
        				
        		////////////////////////////////////////////////////////////////////////////////////////////
        		/// Message 2 - processing starts here
        		////////////////////////////////////////////////////////////////////////////////////////////
        		//there is now definitely a cookie param set somewhere in the responses
        		//so we have a parameter candidate for further checking..
        		if ( log.isDebugEnabled()) log.debug("A Cookie was set by the URL for the correct param, when param ["+ currentHtmlParameter.getName() + "] was set to NULL: "+cookieBack1);
        		        		
        		//so now that we know the URL responds with 200 (OK), and that it sets a cookie, lets re-issue the original request, 
        		//but lets add in the new (valid) session cookie that was just issued.
        		//we will re-send it.  the aim is then to see if it accepts the cookie (BAD, in some circumstances), 
        		//or if it issues a new session cookie (GOOD, in most circumstances)
        		
        		
        		//and set the (modified) cookies for the second message
        		//use a copy of msg1, since it has already had the correct cookie removed in the request..
        		//do NOT use msg1 itself, as this will cause both requests in the GUI to show the modified data..
        		//finally send the second message, and see how it comes back.
        		//HttpMessage msg2Initial= msg1Initial.cloneAll();
        		HttpMessage msg2Initial= msg1Initial.cloneRequest();
        		
        		TreeSet<HtmlParameter> cookieParams2Set = msg1Initial.getCookieParams();
        		cookieParams2Set.add(cookieBack1);         		
        		msg2Initial.setCookieParams(cookieParams2Set);
        		
        		//resend a copy of the initial message, but with the valid session cookie added in, to see if it is accepted
        		//do not automatically follow redirects, as we need to check these for cookies being set.
        		sendAndReceive(msg2Initial, false, false);
        		
        		if ( log.isDebugEnabled()) log.debug("Sent message 2");
        		
        		//create a copy of msg2 to play with to handle redirects (if any).
        		//we use a copy because if we change msg2 itself, it messes the URL and params displayed on the GUI.
	            HttpMessage temp2 = msg2Initial.cloneAll();	            
	            
	       
	            HttpMessage msg2Final=msg2Initial;
	            HtmlParameter cookieBack2 = getParameterCookie (msg2Initial, currentHtmlParameter.getName());
	            
	            int redirectsFollowed2 = 0;
	            while ( HttpStatusCode.isRedirection(temp2.getResponseHeader().getStatusCode())) {
	            	//build up a new location to follow
	                String location = temp2.getResponseHeader().getHeader(HttpHeader.LOCATION);
	                URI baseUri = temp2.getRequestHeader().getURI();
	                URI newLocation = new URI(baseUri, location, false);
	                
	                if ( log.isDebugEnabled()) log.debug("DEBUG: Message 2 causes us to follow redirect to ["+newLocation+ "]");
	                
	                redirectsFollowed2++;
	            	if ( redirectsFollowed2 > 10 ) {
	            		throw new Exception ("Too many redirects were specified in the second message");
	            	}	            	
	                
	                //and follow it
	            	 //need to clear the params (which would come from the initial POST, otherwise)
	                temp2.getRequestHeader().setGetParams(new TreeSet<HtmlParameter>());
	                temp2.setRequestBody("");
	                temp2.setResponseBody(""); //make sure no values accidentally carry from one iteration to the next
	                
	                temp2.getRequestHeader().setURI(newLocation);
	                temp2.getRequestHeader().setMethod(HttpRequestHeader.GET);
	                temp2.getRequestHeader().setContentLength(0);  //since we send a GET, the body will be 0 long
	                if ( cookieBack2 != null) {
	                	//if the previous request sent back a cookie, we need to set that cookie when following redirects, as a browser would
	                	if ( log.isDebugEnabled()) log.debug("Adding in cookie ["+ cookieBack2+ "] for a redirect");
	                	TreeSet <HtmlParameter> forwardCookieParams = temp2.getRequestHeader().getCookieParams();
	                	forwardCookieParams.add(cookieBack2);
	                	temp2.getRequestHeader().setCookieParams(forwardCookieParams);
	                }	               
	                
	                sendAndReceive(temp2, false, false);  //do NOT redirect.. handle it here
	                	                
	                //handle any cookies set from following redirects that override the cookie set in the redirect itself (if any)
	                //note that this will handle the case where a latter cookie unsets one set earlier.	                
	                HtmlParameter cookieBack2Temp = getParameterCookie (temp2, currentHtmlParameter.getName());
	        		if ( cookieBack2Temp != null  ) {
	        			cookieBack2 = cookieBack2Temp;
	        		}
	        		
	        		//reset the "final" version of message2 to use the final response in the chain
	        		msg2Final=temp2;
	        		temp2 = temp2.cloneAll();  //create a new message for each communication
	            }
	            if ( log.isDebugEnabled()) log.debug("Done following redirects");
        		
	            //final result was non-200, no point in continuing. Bale out.
        		if (msg2Final.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
        			if ( log.isDebugEnabled()) log.debug("Got a non-200 response code ["+ msg2Final.getResponseHeader().getStatusCode()+"] when sending ["+msg2Initial.getRequestHeader().getURI()+ "] with a borrowed cookie (or by following a redirect)");
        			continue;
        		}
        		
        		if ( log.isDebugEnabled()) log.debug("Message 2 (intiial) gave "+ msg2Initial.getResponseHeader().getStatusCode() + ", with cookies: "+ msg2Initial.getResponseHeader().getCookieParams());
        		if ( log.isDebugEnabled()) log.debug("Message 2 (final) gave "+ msg2Final.getResponseHeader().getStatusCode()+ ", with cookies: "+ msg2Final.getResponseHeader().getCookieParams());
        		        		        		
        		//and what we've been waiting for.. do we get a *different* cookie being set in the response of message 2??
        		//or do we get a new cookie back at all?
        		//No cookie back => the borrowed cookie was accepted. Not ideal
        		//Cookie back, but same as the one we sent in => the borrowed cookie was accepted. Not ideal
        		        		
        		if ( (cookieBack2== null) || cookieBack2.getValue().equals(cookieBack1.getValue())) {
        			//no cookie back, when a borrowed cookie is in use.. suspicious!
        			
        			String extraInfo = getString("sessionfixation.alert.extrainfo", currentHtmlParameter.getName(), cookieBack1.getValue(), (cookieBack2== null?"NULL": cookieBack2.getValue()));
        			String attack = getString("sessionfixation.alert.attack", currentHtmlParameter.getType(), currentHtmlParameter.getName());        			
        			
        			bingo(Alert.RISK_MEDIUM, Alert.WARNING, msg2Initial.getRequestHeader().getURI().getURI(), currentHtmlParameter.getName(), attack, extraInfo, msg2Initial);
        			if ( log.isInfoEnabled())  {
        				String logMessage = getString ("sessionfixation.alert.logmessage", msg2Initial.getRequestHeader().getMethod(),  msg2Initial.getRequestHeader().getURI().getURI(), currentHtmlParameter.getType(), currentHtmlParameter.getName());
        				log.info(logMessage);
        			}
        			
        			continue;  //jump to the next iteration of the loop (ie, the next parameter)
        		}
        			
    		}

        } catch (Exception e) {
        	//Do not try to internationalise this.. we need an error message in any event.. 
        	//if it's in English, it's still better than not having it at all. 
            log.error("An error occurred checking a url for Session Fixation issues", e);
        }
	}	
	
	/**
	 * finds and returns the cookie matching the specified cookie name from the message response.
	 * @param message
	 * @param cookieName
	 * @return the HtmlParameter representing the cookie, or null if no matching cookie was found
	 */
	private HtmlParameter getParameterCookie (HttpMessage message, String cookieName) {
		TreeSet<HtmlParameter> cookieBackParams = message.getResponseHeader().getCookieParams();
		if ( cookieBackParams.size() == 0) {
			//no cookies
			return null;
		}
		for (Iterator <HtmlParameter> i = cookieBackParams.iterator(); i.hasNext(); ) {
			HtmlParameter tempparam = i.next();
			if ( tempparam.getName().equals(cookieName)) {
				//found it. return it.
				return tempparam;
			}	
		}
		//there were cookies, but none matching the name
		return null;
	}
}
