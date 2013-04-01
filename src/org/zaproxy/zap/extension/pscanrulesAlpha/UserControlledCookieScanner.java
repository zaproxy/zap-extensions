/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Set;
import java.util.TreeSet;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvUserControlledCookie}
 */
public class UserControlledCookieScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.usercontrolledcookie.";

	public UserControlledCookieScanner() {
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
		if (msg.getResponseHeader().getHeader(HttpResponseHeader.SET_COOKIE) != null) {
			
		}
		
    	Set<HtmlParameter> params = new TreeSet<>(msg.getFormParams());
    	params.addAll(msg.getUrlParams());

        if (msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE) == null) {
        	return;
        }
        
    	for (String cookie: msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE)) {
            // Cookies are commonly URL encoded, maybe other encodings.
            // TODO: apply other decodings?  htmlDecode, etc.
    		String charset = msg.getResponseHeader().getCharset();
    		if (charset == null) {
    			charset = Charset.defaultCharset().name();
    		}
    		
    		try {
				cookie = URLDecoder.decode(cookie, charset);
			} catch (UnsupportedEncodingException e) {
				continue;
			}
    		
            // Now we have a cookie.  Parse it out into an array.
            // I'm doing this to avoid false positives.  By parsing
            // the cookie at each delimiter, I'm checking to see that
            // we can match user-input directly.  Otherwise we'd find
            // all the cases where the cookie simply 'contained' user input,
            // which leads to many false positives.
            // For example, if user input was 'number=20' and the cookie was
            // value=82384920 then we don't want to match.  I want precise
            // matches such as value=20.
    		//
    		// Common delimiters in cookies.  E.g. name=value;name2=v1|v2|v3
            String[] cookieSplit = cookie.split("[;=|]");
            for (String cookiePart: cookieSplit) {
                if (params != null && params.size() > 0) {
                    checkUserControllableCookieHeaderValue(msg, id, params, cookiePart, cookie);
                }
            }
    	}
	}
    
    public void checkUserControllableCookieHeaderValue(HttpMessage msg, int id, 
    		Set<HtmlParameter> params, String cookiePart, String cookie) {
        if (cookie.length() == 0) {
        	return;
        }
        	
        for (HtmlParameter param: params) {
            // False Positive Reduction
            // Need to ignore parameters equal to empty value (e.g. name= )
            // otherwise we'll wind up with false positives when cookie
            // values are also set to empty.  
            // 
            // False Positive Reduction
            // Ignore values not greater than 1 character long.  It seems to
            // be common that value=0 and value=/ type stuff raise a false
            // positive.
            if (param.getValue() != null && param.getValue().length() > 1 &&
            		param.getValue().equals(cookiePart)) {
            	raiseAlert(msg, id, param, cookie);
            }
        }
    }    
	
	private void raiseAlert(HttpMessage msg, int id, HtmlParameter param,
			String cookie) {
		Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.WARNING,
				getName());		
		     
		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), param.getName(), getExploitMessage(msg), 
				getExtraInfoMessage(msg, param, cookie),
				getSolutionMessage(), getReferenceMessage(), msg);  

		parent.raiseAlert(id, alert);
	}

	private int getId() {
		return 10029;
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

	private String getExploitMessage(HttpMessage msg) {
        if ("GET".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {      	        	
        	return Constant.messages.getString(MESSAGE_PREFIX + "exploit.get");
        } else if ("POST".equalsIgnoreCase(msg.getRequestHeader().getMethod())) {
        	return Constant.messages.getString(MESSAGE_PREFIX + "exploit.post");
        }
        
        return null;
	}

	private String getExtraInfoMessage(HttpMessage msg, HtmlParameter param, String cookie) {        
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", 
        		msg.getRequestHeader().getURI().toString(), cookie, 
        		param.getName(), param.getValue());        
	}
}