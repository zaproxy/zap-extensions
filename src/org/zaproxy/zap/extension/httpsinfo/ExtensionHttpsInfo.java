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
package org.zaproxy.zap.extension.httpsinfo;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class ExtensionHttpsInfo extends ExtensionAdaptor {

	public static final String NAME = "ExtensionHttpsInfo";
	public static final String ICON_PATH = "/org/zaproxy/zap/extension/httpsinfo/resources/icon.png";
	private static final Logger LOGGER = Logger.getLogger(ExtensionHttpsInfo.class);
	private static final List<Class<?>> DEPENDENCIES;
	static {
		List<Class<?>> dep = new ArrayList<>(1);
		dep.add(ExtensionAlert.class);

		DEPENDENCIES = Collections.unmodifiableList(dep);
	}

	private MenuEntry httpsEntry;
	private List<MDialog> dialogues;
	private boolean unloaded;

	public ExtensionHttpsInfo() {
		super();
	}

	@Override
	public List<Class<?>> getDependencies() {
		return DEPENDENCIES;
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

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		if (getView() != null) {
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenu());
		}

	}

	private MenuEntry getPopupMsgMenu() {
		if (httpsEntry == null) {
			httpsEntry = new MenuEntry(this.getMessageString("httpsinfo.rightclick.menuitem"), this);
			httpsEntry.setIcon(new ImageIcon(ExtensionHttpsInfo.class.getResource(ICON_PATH)));
		}
		return httpsEntry;
	}

	public String getMessageString(String key) {
		return Constant.messages.getString(key);
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("httpsinfo.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_EXTENSIONS_PAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	void showSslTlsInfo(String hostname, HttpMessage msg) {
		new Thread(new BackgroundThread(hostname, msg)).start();
	}

	private class BackgroundThread implements Runnable {

		private String servername;
		private HttpMessage baseMessage;

		public BackgroundThread(String servername, HttpMessage msg) {
			this.baseMessage = msg;
			this.servername = servername;
		}

		@Override
		public void run() {
			final SSLServer mServer;
			try {
				mServer = new SSLServer(servername);
			} catch (IOException ioe) {
				getView().showWarningDialog(Constant.messages.getString("httpsinfo.failure.dialog.message"));
				LOGGER.info("Could not establish a SSL/TLS connection with the server. " + ioe.getMessage());
				return;
			}
			if (unloaded) {
				return;
			}
			EventQueue.invokeLater(new Runnable() {

				@Override
				public void run() {
					if (unloaded) {
						return;
					}
					MDialog d = new MDialog(mServer, baseMessage);
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