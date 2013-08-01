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
package org.zaproxy.zap.extension.httpsInfo;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.PopupMenuHttpMessage;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages. 
 * 
 * This class is defines the popup menu item.
 */
public class MenuEntry extends PopupMenuHttpMessage {

	private static final long serialVersionUID = 1L;
	private RightClickMenu extension = null;

    public MenuEntry(String label) {
        super(label);
    }
	@Override
	public void performAction(HttpMessage msg) throws Exception {
	    SSLServer mServer = new SSLServer(getHostName(msg.getRequestHeader().getURI().toString()));
	    View.getSingleton().showMessageDialog(mServer.getInfo());
	}
	public String getHostName(String name){
	    String host = name;
	    while(!host.startsWith("www")){
		host = host.substring(1);
	    }
	    while(!Character.isDigit(host.charAt(host.length()-1)) && !Character.isLetter(host.charAt(host.length()-1))){
		host = host.substring(0, host.length()-1);
	    }
	    return host;
	}
	public void setExtension(RightClickMenu extension) {
		this.extension = extension;
	}

	@Override
	public boolean isEnableForInvoker(Invoker invoker) {
		// This is enabled for all tabs which list messages
		// You can examine the invoker is you wish to restrict this to specific tabs
		return true;
	}

	
}
