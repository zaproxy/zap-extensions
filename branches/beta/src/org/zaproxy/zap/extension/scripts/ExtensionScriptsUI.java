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

import java.awt.event.MouseAdapter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.tree.TreeCellRenderer;

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
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptUI;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/**
 * The Extension that adds the UI for managing Scripts: scripts tree, scripts console.
 */
public class ExtensionScriptsUI extends ExtensionAdaptor implements ScriptEventListener, ScriptUI {
	
	public static final String NAME = "ExtensionScripts";
	public static final ImageIcon ICON = new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png")); // Script icon
	
	private static final List<Class<?>> EXTENSION_DEPENDENCIES;

	private ScriptsListPanel scriptsPanel = null;
	private ConsolePanel consolePanel = null;
	private OutputPanelWriter outputPanelWriter = null;

	private InvokeScriptWithNodePopupMenu popupInvokeScriptWithNodeMenu = null;
	private PopupEnableDisableScript popupEnableDisableScript = null;
	private PopupRemoveScript popupRemoveScript = null;
	private PopupInstantiateTemplate popupInstantiateTemplate = null;
	
	private ExtensionScript extScript = null;
	private ScriptsTreeCellRenderer renderer = null;

	//private static final Logger logger = Logger.getLogger(ExtensionScripts.class);

	static {
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionScript.class);
		EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}

    public ExtensionScriptsUI() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionScriptsUI(String name) {
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
			extensionHook.getHookMenu().addPopupMenuItem(getPopupInvokeScriptWithNodeMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupEnableDisableScript());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupRemoveScript());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupInstantiateTemplate());
            
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
				extScript.setScriptUI(this);
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

	private PopupInstantiateTemplate getPopupInstantiateTemplate () {
		if (popupInstantiateTemplate == null) {
			popupInstantiateTemplate = new PopupInstantiateTemplate(this); 
		}
		return popupInstantiateTemplate;
	}

	@Override
	public void displayScript (ScriptWrapper script) {
		if (!View.isInitialised()) {
			return;
		}
		
		if (script.getEngine() == null) {
			// Scripts loaded from the configs my have loaded before all of the engines
			script.setEngine(getExtScript().getEngineWrapper(script.getEngineName()));
		}
		if (script.getEngine() != null) {
			// Save any changes to previous script
			this.saveChanges();
			
			// push to ScriptConsole
			this.getConsolePanel().setScript(script);
			
			// Show in the tree panel
			ScriptNode node = this.getExtScript().getTreeModel().getNodeForScript(script);
			if (node != null) {
				this.getScriptsPanel().showInTree(node);
			}
			
			// Show last result
			boolean noOutput = true;
			this.getConsolePanel().getOutputPanel().clear();
			if (script.getLastOutput() != null && script.getLastOutput().length() > 0) {
				this.getConsolePanel().getOutputPanel().append(script.getLastOutput());
				noOutput = false;
			}
			if (script.getLastException() != null) {
				this.showError(script.getLastException());
				noOutput = false;
			} else if (script.getLastErrorDetails() != null && script.getLastErrorDetails().length() > 0) {
				this.showError(script.getLastErrorDetails());
				noOutput = false;
			}
			if (! script.getEngine().isTextBased() && noOutput) {
				// Output message to explain about non test based scriopts
				this.getConsolePanel().getOutputPanel().append(Constant.messages.getString("scripts.welcome.nontest"));
			}
		}
	}

	public void displayTemplate (ScriptWrapper script) {
		if (!View.isInitialised()) {
			return;
		}
		
		if (script.getEngine() == null) {
			// Scripts loaded from the configs my have loaded before all of the engines
			script.setEngine(getExtScript().getEngineWrapper(script.getEngineName()));
		}
		if (script.getEngine() != null) {
			// Save any changes to previous script
			this.saveChanges();

			// push to ScriptConsole
			this.getConsolePanel().setTemplate(script);
			
			// Show in the tree panel
			ScriptNode node = this.getExtScript().getTreeModel().getNodeForScript(script);
			if (node != null) {
				this.getScriptsPanel().showInTree(node);
			}
			
			this.getConsolePanel().getOutputPanel().clear();
		}
	}
	
	private void saveChanges() {
		if (this.getConsolePanel().getScript() != null && this.getConsolePanel().getScript().getEngine().isTextBased()) {
			// Save any changes made
			// Non text based scripts wont be updated via the console panel
			refreshScript(this.getConsolePanel().getScript());
		}
	}

	public void displayType (ScriptType type) {
		if (!View.isInitialised()) {
			return;
		}
		// Save any changes to previous script
		this.saveChanges();

		this.getConsolePanel().clearScript();
		this.getConsolePanel().getOutputPanel().clear();

		if (Constant.messages.containsKey(type.getI18nKey() + ".desc")) {
			setOutput(Constant.messages.getString(type.getI18nKey() + ".desc"));
			this.getConsolePanel().setTabFocus();
		}
	}
	
	@Override
	public boolean isScriptDisplayed(ScriptWrapper script) {
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
	
	protected OutputPanelWriter getOutputPanelWriter() {
		if (View.isInitialised() && outputPanelWriter == null) {
			outputPanelWriter = new OutputPanelWriter(this.getConsolePanel().getOutputPanel());
		}
		return outputPanelWriter;
	}

    public void invokeTargetedScript(ScriptWrapper script, HttpMessage msg) {
    	if (View.isInitialised()) {
    		this.displayScript(script);
			this.getConsolePanel().getOutputPanel().preScriptInvoke();
    	}
   		this.getExtScript().invokeTargetedScript(script, msg);
    }

	@Override
	public void preInvoke(ScriptWrapper script) {
		if (this.isScriptDisplayed(script)) {
			this.getConsolePanel().getOutputPanel().preScriptInvoke();
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
	public void scriptAdded(ScriptWrapper script, boolean display) {
		if (View.isInitialised() && display) {
			this.displayScript(script);
		}
		
	}

	@Override
	public void scriptRemoved(ScriptWrapper script) {
		if (this.isScriptDisplayed(script)) {
			this.getConsolePanel().clearScript();
		}
	}

	@Override
	public void templateAdded(ScriptWrapper script, boolean display) {
		// Ignore
	}

	@Override
	public void templateRemoved(ScriptWrapper script) {
		// Ignore
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
	
	public void setOutput(String string) {
		if (View.isInitialised()) {
			this.getConsolePanel().getOutputPanel().clear();
			this.getConsolePanel().getOutputPanel().append(string);
		}
	}

	@Override
	public void addMouseListener(MouseAdapter l) {
		if (View.isInitialised()) {
			this.getScriptsPanel().getTree().addMouseListener(l);
		}
	}

	@Override
	public ScriptNode getSelectedNode() {
		if (View.isInitialised()) {
			return this.getScriptsPanel().getSelectedNode();
		}
		return null;
	}

	@Override
	public List<ScriptNode> getSelectedNodes() {
		if (View.isInitialised()) {
			return this.getScriptsPanel().getSelectedNodes();
		}
		return null;
	}

	@SuppressWarnings("rawtypes")
	public void addRenderer(Class c, TreeCellRenderer renderer) {
		this.getScriptsTreeCellRenderer().addRenderer(c, renderer);
	}

	public ScriptsTreeCellRenderer getScriptsTreeCellRenderer() {
		if (renderer == null) {
			renderer = new ScriptsTreeCellRenderer(this);
		}
		return renderer;
	}

	@Override
	public void disableScriptDialog(Class<?> klass) {
		if (View.isInitialised()) {
			this.getScriptsPanel().disableScriptDialog(klass);
		}
		
	}

	@Override
	public void selectNode(ScriptNode node, boolean expand) {
		if (View.isInitialised()) {
			this.getScriptsPanel().showInTree(node, expand);
			this.getScriptsPanel().setTabFocus();
		}
	}

	@Override
	public String getTreeName() {
		return ScriptsListPanel.TREE;
	}

	@Override
	public List<Class<?>> getDependencies() {
		return EXTENSION_DEPENDENCIES;
	}
}
