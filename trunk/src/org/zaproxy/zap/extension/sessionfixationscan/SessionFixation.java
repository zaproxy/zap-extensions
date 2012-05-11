/**
 * A plugin to detect session fixation vulnerabilities in web apps.
 */
package org.zaproxy.zap.extension.sessionfixationscan;

import java.text.MessageFormat;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
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
    	log.debug("Initialising");
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
    		HttpMessage msg1 = getNewMsg();
    		TreeSet<HtmlParameter> params = msg1.getCookieParams();
    		params.addAll(msg1.getFormParams());  //add in the POST params
    		params.addAll(msg1.getUrlParams()); //add in the GET params
    		
    		//for each field in turn, 
    		//int counter = 0;
    		for (Iterator<HtmlParameter> iter = params.iterator(); iter.hasNext(); ) {
    			
    			////debug logic only.. to do first field only
    			//counter ++;
    			//if ( counter > 1 )
    			//	return;
    			
    			HtmlParameter param = iter.next();
    			//HttpMessage msg2 = getBaseMsg();
    			msg1 = getNewMsg(); //get a clone of the message to mess with..
    			
        		log.debug("Scanning URL ["+ msg1.getRequestHeader().getURI() + "], ["+ param.getType()+"] field ["+ param.getName() + "] for Session Fixation");
    			//set the field to be empty, and re-send it
        		//Note that there is no variant for Cookies.. just POSTS (forms) and GETS (urls)
        		if ( param.getType().equals (HtmlParameter.Type.cookie)) {
        			TreeSet <HtmlParameter> cookieParams = msg1.getCookieParams();
        			for (Iterator <HtmlParameter> i = cookieParams.iterator(); i.hasNext(); ) {
        				HtmlParameter loopParam =  i.next();
        				if ( loopParam.getName().equals(param.getName())) {
        					//this is the (cookie) param we want. delete it from p, 
        					//and set the (reduced) cookie parameters on the message
        					log.debug("Removing cookie param ["+ param +"]");
        					cookieParams.remove(param);
        					msg1.setCookieParams(cookieParams);
        					break; //out of loop!
        				}
        			}
        		}
        		
        		//send the message, minus the parameters, and see how it comes back.
        		sendAndReceive(msg1);
        		
        		//if non-200, no point in continuing. Bale out.
        		if (msg1.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
        			log.debug("Got a non-200 response code ["+ msg1.getResponseHeader().getStatusCode()+"] when sending ["+msg1.getRequestHeader().getURI()+ "] with param ["+ param +"] = NULL");
        			continue;
        		}
        		
        		//now check that the response set a cookie. if it didn't, then either..
        		//1) we are messing with the wrong field
        		//2) the app doesn't do sessions
        		//either way, there is not much point in continuing to look at this field..

        		//get the cookie header the server sent back, if any
        		TreeSet<HtmlParameter> cookieBackParams = msg1.getResponseHeader().getCookieParams();
        		if ( cookieBackParams.size() == 0) {
        			log.debug("A cookie was not set by the URL when the parameter was set to NULL, so discarding it");
        			continue;  //jump to the next iteration of the loop (ie, the next parameter)
        		}
        		String cookieBack1 = null, cookieBack1ParamValue = null;
        		//build up the string containing the cookie param names, for output to the GUI, etc
        		for (Iterator <HtmlParameter> i = cookieBackParams.iterator(); i.hasNext(); ) {
        			HtmlParameter tempparam = i.next();
        			if (cookieBack1 == null)
        				cookieBack1 = tempparam.getName() + "=" + tempparam.getValue();
        			else
        				cookieBack1 = ";"+tempparam.getName() + "=" + tempparam.getValue();
        		}  
        		
        		//check that a cookie parameter name received matches the name of the cookie parameter that we set to NULL
        		//and pick up the cookie parameter value, for comparison later 
        		boolean cookieBackMatches = false;
        		for (Iterator <HtmlParameter> i = cookieBackParams.iterator(); i.hasNext(); ) {
        			HtmlParameter tempparam = i.next();
        			if ( tempparam.getName().equals(param.getName())) {
        				cookieBackMatches=true;
        				cookieBack1ParamValue=tempparam.getValue();
        				break; //out of this loop
        			}
        		}        		
        		if ( cookieBackMatches == false ) {
        			log.debug("A cookie was set by the URL when the parameter was set to NULL, but for a different parameter(s), so discarding it!");
        			continue;  //jump to the next iteration of the loop (ie, the next parameter)
        		}
        		
        		//have a parameter candidate for further checking..
        		log.debug("A Cookie was Set by the URL for the correct param, when param ["+ param.getName() + "] was set to NULL: "+cookieBack1);
        		        		
        		//so now that we know the URL responds with 200 (OK), and that it sets a cookie, lets re-issue the original request, 
        		//but lets add in the new (valid) session cookie that was just issued.
        		//the aim is to see if it accepts it (BAD, in some circumstances), or if it issues a new session cookie (GOOD, in most circumstances)
        		//parse out the received string into its constituent parts (a cookie can comprise various parameters)
        		TreeSet<HtmlParameter> cookieParams2Set = msg1.getCookieParams();
        		cookieParams2Set.addAll(cookieBackParams);
        		
        		//and set the (modified) cookies for the second message
        		//use a copy of msg1, since it has already had the correct cookie removed in the request..
        		//do NOT use msg1 itself, as this will cause both requests in the GUI to show the modified data..
        		//finally send the second message, and see how it comes back.
        		HttpMessage msg2= msg1.cloneAll();        		
        		msg2.setCookieParams(cookieParams2Set);        		
        		sendAndReceive(msg2);
        		
        		//if non-200, no point in continuing. Bale out.
        		if (msg2.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
        			log.debug("Got a non-200 response code ["+ msg2.getResponseHeader().getStatusCode()+"] when sending ["+msg2.getRequestHeader().getURI()+ "] with a borrowed cookie");
        			continue;
        		}
        		        		
        		//and what we've been waiting for.. do we get a different cookie being set in the response??
        		//or do we get a new cookie back at all?
        		//No cookie back => the borrowed cookie was accepted. Not ideal
        		//Cookie back, but same as the one we sent in => the borrowed cookie was accepted. Not ideal
        		
        		String cookieBack2 = null, cookieBack2ParamValue = null;;
        		TreeSet<HtmlParameter> cookieBack2Params = msg2.getResponseHeader().getCookieParams();        		
        		//build up the string containing the cookie param names, for output to the GUI, comparison etc
        		for (Iterator <HtmlParameter> i = cookieBack2Params.iterator(); i.hasNext(); ) {
        			HtmlParameter tempparam = i.next();
        			if (cookieBack2 == null)
        				cookieBack2 = tempparam.getName() + "=" + tempparam.getValue();
        			else
        				cookieBack2 = ";"+tempparam.getName() + "=" + tempparam.getValue();
        		}  
        		//check that a cookie parameter name received matches the name of the cookie parameter that we are messing with
        		//and pick up the cookie parameter value, for comparison later 
        		boolean cookieBack2Matches = false;
        		for (Iterator <HtmlParameter> i = cookieBack2Params.iterator(); i.hasNext(); ) {
        			HtmlParameter tempparam = i.next();
        			if ( tempparam.getName().equals(param.getName())) {
        				cookieBack2Matches=true;
        				cookieBack2ParamValue=tempparam.getValue();
        				break; //out of this loop
        			}
        		} 
        		
        		//Note: we cannot compare the entire cookie contents, as a cookie may contain multiple parameters, which could cause false negatives
        		//need to compare *just* the relevant parameter field in each..
        		if ( (cookieBack2ParamValue== null) || (cookieBack2ParamValue != null && cookieBack2ParamValue.equals(cookieBack1ParamValue))) {
        			//no cookie back, when a borrowed cookie is in use.. suspicious!
        			
        			String extraInfo = getString("sessionfixation.alert.extrainfo", param.getName(), cookieBack1, cookieBack2);
        			String attack = getString("sessionfixation.alert.attack", param.getType(), param.getName());
        			String logMessage = getString ("sessionfixation.alert.logmessage", msg2.getRequestHeader().getURI().getURI(), param.getType(), param.getName());
        			
        			bingo(Alert.RISK_MEDIUM, Alert.WARNING, msg2.getRequestHeader().getURI().getURI(), param.getName(), attack, extraInfo, msg2);
        			log.info(logMessage);
        			
        			continue;  //jump to the next iteration of the loop (ie, the next parameter)
        		}
        			
    		}

        } catch (Exception e) {
        	//Do not try to internationalise this.. we need an error message in any event.. 
        	//if it's in English, it's still better than not having it at all. 
            log.error("An error occurred checking a url for Session Fixation issues", e);
        }
	}	
}
