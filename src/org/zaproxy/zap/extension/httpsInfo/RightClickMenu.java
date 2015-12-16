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

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages. 
 * 
 * This class is defines the extension.
 */
public class RightClickMenu extends ExtensionAdaptor {

    private MenuEntry httpsEntry = null;
    private List<MDialog> dialogues;
    private boolean unloaded;

    public RightClickMenu() {
        super();
 		initialize();
    }

    public RightClickMenu(String name) {
        super(name);
    }

    private void initialize() {
        this.setName("PopupMenu");
	}

	@Override
	public void init() {
		super.init();

		dialogues = new ArrayList<>();
	}

	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void unload() {
		super.unload();
		unloaded = true;

		while (!dialogues.isEmpty()) {
			// When disposed the dialogue is removed from the list 
			dialogues.get(0).dispose();
		}
	}
	
    public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    if (getView() != null) {
	    	// Register our popup menu item, as long as we're not running as a daemon
		MenuEntry entry = getPopupMsgMenuExample();
		
	    	extensionHook.getHookMenu().addPopupMenuItem(entry);
	    }

	}

	private MenuEntry getPopupMsgMenuExample() {
		if (httpsEntry  == null) {
			httpsEntry = new MenuEntry(
					this.getMessageString("httpsInfo.httpsInfo.menuitem"), this);
		}
		return httpsEntry;
	}

	public String getMessageString (String key) {
		return Constant.messages.getString(key);
	}
	
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("httpsInfo.httpsInfo.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_EXTENSIONS_PAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	void showSslTlsInfo(String hostname) {
		new Thread(new BackgroundThread(hostname)).start();
	}

	private class BackgroundThread implements Runnable {

		private String servername;

		public BackgroundThread(String servername) {
			this.servername = servername;
		}

		@Override
		public void run() {
			final SSLServer mServer = new SSLServer(servername);
			if (unloaded) {
				return;
			}
			EventQueue.invokeLater(new Runnable() {

				@Override
				public void run() {
					if (unloaded) {
						return;
					}
					MDialog d = new MDialog(mServer);
					dialogues.add(d);
					d.addWindowListener(new WindowAdapter() {

						@Override
						public void windowClosed(WindowEvent e) {
							dialogues.remove(e.getSource());
						}
					});
				}
			});
		}
	}
}