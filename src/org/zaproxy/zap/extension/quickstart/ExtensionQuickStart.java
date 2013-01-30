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
package org.zaproxy.zap.extension.quickstart;

import java.awt.Container;
import java.net.MalformedURLException;
import java.net.URL;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.ext.ExtensionExtension;
import org.zaproxy.zap.extension.help.ExtensionHelp;

public class ExtensionQuickStart extends ExtensionAdaptor implements SessionChangedListener {
	
	public static final String NAME = "ExtensionQuickStart";
	protected static final String SCRIPT_CONSOLE_HOME_PAGE = Constant.ZAP_HOMEPAGE;
	
	private QuickStartPanel quickStartPanel = null;
	private AttackThread attackThread = null;
	
    public ExtensionQuickStart() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionQuickStart(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setName(NAME);
        //this.setOrder(0);
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

	    if (getView() != null) {
	        extensionHook.getHookView().addWorkPanel(getQuickStartPanel());
	        
	        ExtensionHelp.enableHelpKey(getQuickStartPanel(), "quickstart");
	    }
        extensionHook.addSessionListener(this);

	}

	@Override
	public boolean canUnload() {
    	return true;
    }

	private QuickStartPanel getQuickStartPanel() {
		if (quickStartPanel == null) {
			quickStartPanel = new QuickStartPanel(this);
		    quickStartPanel.setName(Constant.messages.getString("quickstart.panel.title"));
		    // Force it to be the first one
			quickStartPanel.setTabIndex(0);
		}
		return quickStartPanel;
	}
	

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("quickstart.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	public void attack (URL url) {
		if (attackThread != null && attackThread.isAlive()) {
			return;
		}
		attackThread = new AttackThread(this);
		attackThread.setURL(url);
		attackThread.start();

	}
	
	public void notifyProgress(AttackThread.Progress progress) {
		this.getQuickStartPanel().notifyProgress(progress);
	}

	public void stopAttack() {
		if (attackThread != null) {
			attackThread.stopAttack();
		}
	}

	public void showOnStart(boolean showOnStart) {
		if (!showOnStart) {
			// Remove the tab right away
			Container parent = this.getQuickStartPanel().getParent();
			parent.remove(this.getQuickStartPanel());
		}
		
		// Save in configs
		ExtensionExtension extExt = 
				(ExtensionExtension) Control.getSingleton().getExtensionLoader().getExtension(ExtensionExtension.NAME);
		if (extExt != null) {
			extExt.enableExtension(NAME, showOnStart);
		}
		
	}

	@Override
	public void sessionAboutToChange(Session arg0) {
		// Ignore
	}

	@Override
	public void sessionChanged(Session arg0) {
		// Ignore
	}

	@Override
	public void sessionModeChanged(Mode mode) {
		this.getQuickStartPanel().setMode(mode);
	}

	@Override
	public void sessionScopeChanged(Session arg0) {
		// Ignore
	}


}
