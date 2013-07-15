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
package org.zaproxy.zap.extension.scripts;

import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.ImageIcon;
import javax.swing.JMenuItem;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.DesktopUtils;

public class ExtensionScripts extends ExtensionAdaptor implements ScriptEventListener {
	
	public static final String NAME = "ExtensionScripts";
	public static final ImageIcon ICON = new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png")); // Script icon
	
	protected static final String SCRIPT_CONSOLE_HOME_PAGE = "http://code.google.com/p/zaproxy/wiki/ScriptConsole";

	public static final String TYPE_STANDALONE = "standalone";
	public static final String TYPE_ACTIVE = "active";
	public static final String TYPE_PASSIVE = "passive";
	public static final String TYPE_TARGETED = "targeted";
	
	private ScriptsListPanel scriptsPanel = null;
	private ConsolePanel consolePanel = null;
	private JMenuItem menuConsoleLink = null;
	private OutputPanelWriter outputPanelWriter = null;

	private InvokeScriptWithNodePopupMenu popupInvokeScriptWithNodeMenu = null;
	private PopupEnableDisableScript popupEnableDisableScript = null;
	private PopupRemoveScript popupRemoveScript = null;
	
	private ExtensionScript extScript = null;

	//private static final Logger logger = Logger.getLogger(ExtensionScripts.class);

    public ExtensionScripts() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionScripts(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setName(NAME);
        this.setOrder(61);	// TODO ok?
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    this.getExtScript().addListener(this);

	    if (getView() != null) {
	    	extensionHook.getHookView().addSelectPanel(getScriptsPanel());
	        extensionHook.getHookView().addWorkPanel(getConsolePanel());
	        extensionHook.getHookMenu().addToolsMenuItem(getMenuConsoleLink());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupInvokeScriptWithNodeMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupEnableDisableScript ());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupRemoveScript ());
            
            ExtensionHelp.enableHelpKey(getConsolePanel(), "addon.scripts.console");
            ExtensionHelp.enableHelpKey(getScriptsPanel(), "addon.scripts.tree");

	    }
	}
	
    @Override
	public boolean canUnload() {
    	return true;
    }
	
    @Override
    public void unload() {
        if (getView() != null) {
            if (consolePanel != null) {
                consolePanel.unload();
            }
        }
        
        super.unload();
    }
    
	public ExtensionScript getExtScript() {
		if (extScript == null) {
			extScript = (ExtensionScript) Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.NAME);
			if (View.isInitialised()) {
				extScript.addWriter(getOutputPanelWriter());
			}
		}
		return extScript;
	}

	private ConsolePanel getConsolePanel() {
		if (consolePanel == null) {
			consolePanel = new ConsolePanel(this);
		    consolePanel.setName(Constant.messages.getString("scripts.panel.title"));
		}
		return consolePanel;
	}
	

	private InvokeScriptWithNodePopupMenu getPopupInvokeScriptWithNodeMenu() {
		if (popupInvokeScriptWithNodeMenu == null) {
			popupInvokeScriptWithNodeMenu = new InvokeScriptWithNodePopupMenu(this);
		}
		return popupInvokeScriptWithNodeMenu;
	}
	
	private PopupEnableDisableScript getPopupEnableDisableScript() {
		if (popupEnableDisableScript == null) {
			popupEnableDisableScript = new PopupEnableDisableScript(this);
		}
		return popupEnableDisableScript;
	}

	private PopupRemoveScript getPopupRemoveScript () {
		if (popupRemoveScript == null) {
			popupRemoveScript = new PopupRemoveScript(this); 
		}
		return popupRemoveScript;
	}

	public void displayScript (ScriptWrapper script) {
		if (!View.isInitialised()) {
			return;
		}
		
		if (script.getEngine() == null) {
			// Scripts loaded from the configs my have loaded before all of the engines
			script.setEngine(getExtScript().getEngineWrapper(script.getEngineName()));
		}
		if (script.getEngine() != null) {
			// Save any changes
			refreshScript(this.getConsolePanel().getScript());
			// push to ScriptConsole
			this.getConsolePanel().setScript(script);
			
			// Show in the tree panel
			ScriptNode node = this.getExtScript().getTreeModel().getNodeForScript(script);
			if (node != null) {
				this.getScriptsPanel().showInTree(node);
			}
			
			// Show last result
			this.getConsolePanel().getOutputPanel().clear();
			if (script.getLastOutput() != null) {
				this.getConsolePanel().getOutputPanel().append(script.getLastOutput());
			}
			if (script.getLastException() != null) {
				this.showError(script.getLastException());
			} else if (script.getLastErrorDetails() != null && script.getLastErrorDetails().length() > 0) {
				this.showError(script.getLastErrorDetails());
			}
		}
	}
	
	private boolean isScriptDisplayed(ScriptWrapper script) {
		return View.isInitialised() && script != null && script.equals(this.getConsolePanel().getScript());
	}

	protected ScriptsListPanel getScriptsPanel() {
		if (scriptsPanel == null) {
			scriptsPanel = new ScriptsListPanel(this);
		}
		return scriptsPanel;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("scripts.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	private JMenuItem getMenuConsoleLink() {
        if (menuConsoleLink == null) {
        	menuConsoleLink = new JMenuItem();
        	menuConsoleLink.setText(Constant.messages.getString("scripts.topmenu.tools.consoleLink"));

        	menuConsoleLink.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
            		// Open the Script Console wiki page using the default browser
                	DesktopUtils.openUrlInBrowser(SCRIPT_CONSOLE_HOME_PAGE);
                }
            });
        }
        return menuConsoleLink;
	}
	
	protected OutputPanelWriter getOutputPanelWriter() {
		if (View.isInitialised() && outputPanelWriter == null) {
			outputPanelWriter = new OutputPanelWriter(this.getConsolePanel().getOutputPanel());
		}
		return outputPanelWriter;
	}

    public void invokeTargetedScript(ScriptWrapper script, HttpMessage msg) {
    	if (View.isInitialised()) {
    		this.displayScript(script);
			this.getConsolePanel().getOutputPanel().clear();
    	}
   		this.getExtScript().invokeTargetedScript(script, msg);
    }


	@Override
	public void preInvoke(ScriptWrapper script) {
		if (this.isScriptDisplayed(script)) {
			this.getConsolePanel().getOutputPanel().clear();
		}
	}

	@Override
	public void refreshScript(ScriptWrapper script) {
		if (this.isScriptDisplayed(script)) {
			// Get the latest version from the console
			if (! script.getContents().equals(this.getConsolePanel().getCommandScript())) {
				script.setContents(this.getConsolePanel().getCommandScript());
				getExtScript().getTreeModel().nodeStructureChanged(script);
			}
		}
	}

	@Override
	public void scriptAdded(ScriptWrapper script) {
		if (View.isInitialised()) {
			this.displayScript(script);
		}
	}

	@Override
	public void scriptChanged(ScriptWrapper script) {
		if (View.isInitialised()) {
			this.getScriptsPanel().setButtonStates();
		}
	}

	@Override
	public void scriptError(ScriptWrapper script) {
		if (this.isScriptDisplayed(script)) {
			if (script.getLastException() != null) {
				this.showError(script.getLastException());
			} else {
				this.showError(script.getLastErrorDetails());
			}
		}
	}

	@Override
	public void scriptSaved(ScriptWrapper script) {
	}

	public void showError(Exception e) {
		if (View.isInitialised()) {
			this.getConsolePanel().getOutputPanel().append(e);
		} else {
			System.out.println("ERROR: " + e);
		}
	}
	public void showError(String string) {
		if (View.isInitialised()) {
			this.getConsolePanel().getOutputPanel().appendError(string);
		} else {
			System.out.println("ERROR: " + string);
		}
	}

}
