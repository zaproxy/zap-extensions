/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2010 The ZAP development team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.search.ExtensionSearch;


public class PopupMenuEvidence extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;

    private ExtensionWappalyzer extension;
    
    private List<PopupMenuEvidenceSearch> subMenus = new ArrayList<PopupMenuEvidenceSearch>();

	/**
     * 
     */
    public PopupMenuEvidence() {
        super();
    }

    /**
     * @param label
     */
    public PopupMenuEvidence(String label) {
        super(label);
    }

	public void setExtension(ExtensionWappalyzer extension) {
		this.extension = extension;
	}
	
	@Override
	public boolean isSuperMenu() {
		return true;
	}

    @Override
    public boolean isEnableForComponent(Component invoker) {
    	// Remove any old submenus
    	for (PopupMenuEvidenceSearch menu : this.subMenus) {
			View.getSingleton().getPopupMenu().removeMenu(menu);
    	}
    	this.subMenus.clear();
    	
        if (invoker.getName() != null && invoker.getName().equals(TechPanel.PANEL_NAME)) {
            Application app = extension.getSelectedApp();
            if (app != null) {
            	for (AppPattern p : app.getUrl()) {
            		this.addSubMenu("URL", p.getPattern(), ExtensionSearch.Type.URL);
            	}
            	for (Map<String,AppPattern> mp : app.getHeaders()) {
					for (Map.Entry<String, AppPattern> entry : mp.entrySet()) {
						Pattern p = Pattern.compile(entry.getKey() + ".*" + entry.getValue().getPattern().pattern());
	            		this.addSubMenu("HEAD", p, ExtensionSearch.Type.Header);
					}
            	}
            	for (AppPattern p : app.getHtml()) {
            		this.addSubMenu("HTML", p.getPattern(), ExtensionSearch.Type.Response);
            	}
            	for (AppPattern p : app.getScript()) {
            		this.addSubMenu("SCRIPT", p.getPattern(), ExtensionSearch.Type.Response);
            	}
            }
        }
        return false;
    }
    
    private void addSubMenu(String label, Pattern p, ExtensionSearch.Type type) {
    	// TODO add prefix for pattern types?
		PopupMenuEvidenceSearch menu = new PopupMenuEvidenceSearch(label, p, type);
		menu.setExtension(extension);
		menu.setMenuIndex(this.getMenuIndex());
		View.getSingleton().getPopupMenu().addMenu(menu);
		this.subMenus.add(menu);
    }

    @Override
    public boolean isSafe() {
    	return true;
    }
}
