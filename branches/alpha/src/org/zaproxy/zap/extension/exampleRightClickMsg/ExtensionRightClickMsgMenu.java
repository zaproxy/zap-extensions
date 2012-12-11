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
package org.zaproxy.zap.extension.exampleRightClickMsg;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ResourceBundle;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages. 
 * 
 * This class is defines the extension.
 */
public class ExtensionRightClickMsgMenu extends ExtensionAdaptor {

	private RightClickMsgMenu popupMsgMenuExample = null;
    private ResourceBundle messages = null;

	/**
     * 
     */
    public ExtensionRightClickMsgMenu() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionRightClickMsgMenu(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setName("ExtensionPopupMsgMenu");
        // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    if (getView() != null) {
	    	// Register our popup menu item, as long as we're not running as a daemon
	    	extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
	    }

	}

	private RightClickMsgMenu getPopupMsgMenuExample() {
		if (popupMsgMenuExample  == null) {
			popupMsgMenuExample = new RightClickMsgMenu(
					this.getMessageString("ext.popupmsg.popup.example"));
			popupMsgMenuExample.setExtension(this);
		}
		return popupMsgMenuExample;
	}

	public String getMessageString (String key) {
		return messages.getString(key);
	}
	
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return messages.getString("ext.popupmsg.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_EXTENSIONS_PAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

}