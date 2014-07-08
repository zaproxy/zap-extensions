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
package org.zaproxy.zap.extension.simpleExample;

import java.text.MessageFormat;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages. 
 * 
 * This class is defines the popup menu item.
 */
public class RightClickMsgMenu extends PopupMenuItemHttpMessageContainer {

	private static final long serialVersionUID = 1L;
	@SuppressWarnings("unused")
	private ExtensionSimpleExample extension = null;

    /**
     * @param ext 
     * @param label
     */
    public RightClickMsgMenu(ExtensionSimpleExample ext, String label) {
        super(label);
        /*
         * This is how you can pass in your extension, which you may well need to use
         * when you actually do anything of use.
         */
        this.extension = ext;
    }
	
	@Override
	public void performAction(HttpMessage msg) {
		// This is where you do what you want to do.
		// In this case we'll just show a popup message.
		View.getSingleton().showMessageDialog(
				MessageFormat.format(
						Constant.messages.getString(ExtensionSimpleExample.PREFIX + ".popup.msg"),
						msg.getRequestHeader().getURI().toString()));
	}

	@Override
	public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
		// This is enabled for all tabs which list messages
		// You can examine the invoker is you wish to restrict this to specific tabs
		return true;
	}

	
}
