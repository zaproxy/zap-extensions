/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2016 sanchitlucknow@gmail.com
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
package org.zaproxy.zap.extension.bugTracker;

import java.net.MalformedURLException;
import java.net.URL;
import org.zaproxy.zap.view.ZapMenuItem;
import java.util.HashSet;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * A ZAP Extension to help user raise issues in bug trackers from within ZAP.
 */
public class ExtensionBugTracker extends ExtensionAdaptor {

	public static final String NAME = "ExtensionBugTracker";
	public HashSet<Alert> alerts = null;
	
	protected static final String PREFIX = "bugTracker";

	private static final String RESOURCE = "/org/zaproxy/zap/extension/bugTracker/resources";

	private ZapMenuItem menuManual;
	private ZapMenuItem menuSemi;
	private PopupSemiAutoIssue popupMsgRaiseSemiAuto;

    private static final Logger LOGGER = Logger.getLogger(ExtensionBugTracker.class);

    public ExtensionBugTracker() {
        super(NAME);
    }
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    if (getView() != null) {
	    	extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgRaiseSemiAuto());
	    }

	}

	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void unload() {
		super.unload();
	}

	private PopupSemiAutoIssue getPopupMsgRaiseSemiAuto() {
		if (popupMsgRaiseSemiAuto  == null) {
			popupMsgRaiseSemiAuto = new PopupSemiAutoIssue(this,
					Constant.messages.getString(PREFIX + ".popup.issue.semi"));
		}
		popupMsgRaiseSemiAuto.setExtension(Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class)); 
		return popupMsgRaiseSemiAuto;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(PREFIX + ".desc");
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