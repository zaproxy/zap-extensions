/*
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
package org.zaproxy.zap.extension.plugnhack.brk;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.zaproxy.zap.extension.brk.AbstractBreakPointMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;

public class ClientBreakpointMessage extends AbstractBreakPointMessage {

    private static final String TYPE = "Client";
    
    private Pattern urlPattern = null;
    
	public ClientBreakpointMessage(String urlPattern) throws PatternSyntaxException {
		setUrlPattern(urlPattern);
	}

	@Override
    public String getType() {
        return TYPE;
    }
	
	public String getUrlPattern() {
		if (urlPattern != null) {
			return urlPattern.pattern();
		}
		return null;
	}

	/**
	 * Catch {@link PatternSyntaxException} in dialog & show warning. You can do
	 * this by <code>View.getSingleton().showWarningDialog(message)</code>.
	 * 
	 * @param urlPattern
	 * @throws PatternSyntaxException
	 */
	public void setUrlPattern(String urlPattern) throws PatternSyntaxException {
		if (urlPattern == null || urlPattern.length() == 0) {
			this.urlPattern = null;
		} else {
			this.urlPattern = Pattern.compile(urlPattern, Pattern.MULTILINE);
		}
	}

	@Override
	public boolean match(Message aMessage, boolean isRequest, boolean onlyIfInScope) {
	    if (aMessage instanceof ClientMessage) {
	    	// TODO
	    	// ClientMessage msg = (ClientMessage)aMessage;
	        
	        return true;
	    }
	    
		return false;
	}

    @Override
    public String getDisplayMessage() {
    	return this.getUrlPattern();
    	// TODO
    	/*
    	String message = "";
    	
    	if (opcode != null) {
    		message += Constant.messages.getString("websocket.brk.add.opcode") + " " + opcode + "; ";
        }
        
        if (channelId != null) {
    		message += Constant.messages.getString("websocket.brk.add.channel") + " #" + channelId + "; ";
        }
        
        if (payloadPattern != null) {
    		message += Constant.messages.getString("websocket.brk.add.pattern") + " " + payloadPattern.pattern() + "; ";
        }
        
        if (direction != null) {
    		message += Constant.messages.getString("websocket.brk.add.direction") + " " + direction + "; ";
        }
        
        if (message.isEmpty()) {
        	return Constant.messages.getString("websocket.brk.add.break_on_all");
        }
        
        return Constant.messages.getString("websocket.brk.add.break_on_custom") + " " + message;
        */
    }

}
