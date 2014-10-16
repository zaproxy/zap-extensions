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
package org.zaproxy.zap.extension.tips;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.ResourceBundle;

import javax.swing.SwingUtilities;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * An example ZAP extension which adds a top level menu item. 
 * 
 * This class is defines the extension.
 */
public class ExtensionTipsAndTricks extends ExtensionAdaptor {

	// The name is public so that other extensions can access it
	public static final String NAME = "ExtensionTipsAndTricks";
	
	private static final String PREFIX = "tips";
	private static final String TIPS_PREFIX = PREFIX + ".tip.";

    private ZapMenuItem menuTipsAndTricks = null;
    private TipsAndTricksDialog dialog = null;
	private TipsParam params = null;
    
    private List<String> tipsAndTricks = null;
    private Random random = new Random();

    public ExtensionTipsAndTricks() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionTipsAndTricks(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setName(NAME);
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
        extensionHook.addOptionsParamSet(getTipsParam());

	    if (getView() != null) {
    		extensionHook.getHookMenu().addHelpMenuItem(getMenuTipsAndTricks());
	    }
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}
	
	private TipsParam getTipsParam() {
		if (params == null) {
			params = new TipsParam();
		}
		return params;
	}
	
	public boolean isShowOnStart() {
		return this.getTipsParam().isShowOnStart();
	}
	
	public void setShowOnStart(boolean show) {
		this.getTipsParam().setShowOnStart(show);
	}

	@Override
	public void optionsLoaded() {
		if (this.isShowOnStart()) {
			SwingUtilities.invokeLater(new Runnable(){
				@Override
				public void run() {
					displayRandomTip();
				}});
		}
	}
	
	private ZapMenuItem getMenuTipsAndTricks() {
        if (menuTipsAndTricks == null) {
        	menuTipsAndTricks = new ZapMenuItem(PREFIX + ".topmenu.help.tips");

        	menuTipsAndTricks.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent ae) {
            		displayRandomTip();
                }
            });
        }
        return menuTipsAndTricks;
    }
	
	private List<String> getTipsAndTricks() {
		if (tipsAndTricks == null) {
			// Need to load them in
			tipsAndTricks = new ArrayList<String>();
			
			ResourceBundle rb = Constant.messages.getMessageBundle(PREFIX);
			Enumeration<String> enm = rb.getKeys();
			while (enm.hasMoreElements()) {
				String key = enm.nextElement();
				if (key.startsWith(TIPS_PREFIX)) {
					tipsAndTricks.add(/*Constant.messages.getString(key)*/rb.getString(key));	
				}
			}

			if (tipsAndTricks.size() == 0) {
				this.getMenuTipsAndTricks().setEnabled(false);
			}
		}
		return this.tipsAndTricks;
	}
	
	public String getRandomTip() {
		return this.getTipsAndTricks().get(random.nextInt(this.getTipsAndTricks().size()));
	}
	
	private void displayRandomTip() {
		this.getTipsAndTricksDialog().displayTip();
	}
	
	private TipsAndTricksDialog getTipsAndTricksDialog() {
		if (dialog == null) {
			dialog = new TipsAndTricksDialog(this, View.getSingleton().getMainFrame());
		}
		return dialog;
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