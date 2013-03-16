package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import java.util.TreeSet;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvUserControlledOpenRedirect}
 */
public class UserControlledOpenRedirectScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.usercontrolledopenredirect.";

	public UserControlledOpenRedirectScanner() {
		super();
		PscanUtils.registerI18N();
	}
	
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseHeader().getStatusCode() == 301 || 
        		msg.getResponseHeader().getStatusCode() == 302) {
            if (msg.getResponseHeader().getHeader(HttpResponseHeader.LOCATION) != null) {
            	Set<HtmlParameter> params = new TreeSet<HtmlParameter>(msg.getUrlParams());
            	params.addAll(msg.getFormParams());
            	
            	if (!params.isEmpty()) {
                	checkUserControllableLocationHeaderValue(msg, params, 
                			msg.getResponseHeader().getHeader(HttpResponseHeader.LOCATION));
            	}
            }
        }	
	}

    private void checkUserControllableLocationHeaderValue(HttpMessage msg, 
    		Set<HtmlParameter> params, String responseLocation) {
    	if (responseLocation.length() == 0) {
    		return;
    	}
    	
        String protocol = null;
        String domain = null;
        String token = null;

        // if contains protocol/domain name separator
        if (responseLocation.indexOf("://") > 0) {
        	URL responseURL;
			try {
				responseURL = new URL(responseLocation);
			} catch (MalformedURLException e) {
				return;
			}
            // get protocol
            protocol = responseURL.getProtocol();

            // get domain name
            domain = responseURL.getAuthority();
        }
        // is local path
        else {
            // get up to first slash
            if (responseLocation.indexOf("/") > 0) {
            	token = responseLocation.substring(0, responseLocation.indexOf("/"));
            }
            else {
            	token = responseLocation;
            }
        }

        for (HtmlParameter param: params) {
            String paramValue = param.getValue();

            if (paramValue == null || paramValue.length() == 0) {
            	continue;
            }
            
            if (paramValue.equalsIgnoreCase(protocol) || paramValue.equalsIgnoreCase(domain) ||
            		paramValue.equalsIgnoreCase(token) || 
            		(responseLocation.indexOf("://") > 0 && paramValue.indexOf(responseLocation) > 0)) {
            	raiseAlert(msg, getId(), param.getName(), paramValue, responseLocation, 
            			"POST".equalsIgnoreCase(msg.getRequestHeader().getMethod()));
            }
        }
    }
	
	private void raiseAlert(HttpMessage msg, int id, String paramName, String paramValue, 
			String responseLocation, boolean ispost) {
		Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.WARNING,
				getName());		
		
     

		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), "content-type", getExploitMessage(), 
				getExtraInfoMessage(msg, paramName, paramValue, responseLocation),
				getSolutionMessage(), getReferenceMessage(), msg);  

		parent.raiseAlert(id, alert);
	}

	private int getId() {
		return 90011;
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/*
	 * Rule-associated messages
	 */

	private String getDescriptionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolutionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReferenceMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	private String getExploitMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "exploit");
	}

	private String getExtraInfoMessage(HttpMessage msg, String paramName,
			String paramValue, String responseLocation) {
		StringBuilder extraInfoSB = new StringBuilder();
        if ("GET".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {      	        	
        	extraInfoSB.append(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.get"));
        } else if ("POST".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
        	extraInfoSB.append(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.post"));
        }
        
        extraInfoSB.append(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.common", 
        		msg.getRequestHeader().getURI().toString(), paramName, paramValue, responseLocation));    		
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.get", 
				msg.getRequestHeader().getURI(), paramName, paramValue,
				responseLocation);
	}
}
