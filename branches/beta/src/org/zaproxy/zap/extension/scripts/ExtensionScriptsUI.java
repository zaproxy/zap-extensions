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
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.TransferHandler;
import javax.swing.tree.TreeCellRenderer;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptUI;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.stdmenus.PopupContextMenuItemFactory;
import org.zaproxy.zap.model.Context;

/**
 * The Extension that adds the UI for managing Scripts: scripts tree, scripts console.
 */
public class ExtensionScriptsUI extends ExtensionAdaptor implements ScriptEventListener, ScriptUI {
	
	public static final String NAME = "ExtensionScripts";
	public static final ImageIcon ICON = new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png")); // Script icon
	
	private static final List<Class<?>> EXTENSION_DEPENDENCIES;

	private ScriptsListPanel scriptsPanel = null;
	private ConsolePanel consolePanel = null;
	private OutputPanelWriter stdOutputPanelWriter = null;
	private OutputPanelWriter displayedScriptOutputPanelWriter = null;

	private InvokeScriptWithNodePopupMenu popupInvokeScriptWithNodeMenu = null;
	private PopupEnableDisableScript popupEnableDisableScript = null;
	private PopupRemoveScript popupRemoveScript = null;
	private PopupInstantiateTemplate popupInstantiateTemplate = null;
	private PopupDuplicateScript popupDuplicateScript = null;
	private PopupNewScriptFromType popupNewScriptFromType = null;
	private PopupContextMenuItemFactory popupFactoryUseScriptForAuthentication = null;
	
	private ExtensionScript extScript = null;
	private ScriptsTreeCellRenderer renderer = null;
	
	private ScriptWrapper currentLockedScript = null;
	private boolean lockOutputToDisplayedScript = false;
	//private ZapMenuItem menuEnableScripts = null;

	//private static final Logger logger = Logger.getLogger(ExtensionScriptsUI.class);

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
		// Make sure this extension is loaded after the ExtensionScript and after the
		// ExtensionAuthentication, so the Popup for using the scripts as authentication is properly
		// enabled (it needs the authentication method types to already be registered).
        this.setOrder(ExtensionScript.EXTENSION_ORDER + 1);	
		if (this.getOrder() < ExtensionAuthentication.EXTENSION_ORDER)
			Logger.getLogger(getClass()).error(
					"Scripts UI extension's order is not higher than Authentication extension's");
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
            extensionHook.getHookMenu().addPopupMenuItem(getPopupDuplicateScript());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupNewScriptFromType());
            //extensionHook.getHookMenu().addToolsMenuItem(getMenuEnableScripts());
            if(PopupUseScriptAsAuthenticationScript.arePrerequisitesSatisfied())
            	extensionHook.getHookMenu().addPopupMenuItem(getPopupFactoryUseScriptForAuthentication());
            
            ExtensionHelp.enableHelpKey(getConsolePanel(), "addon.scripts.console");
            ExtensionHelp.enableHelpKey(getScriptsPanel(), "addon.scripts.tree");

	    }
	}
	
	/* TODO Work in progress
    private ZapMenuItem getMenuEnableScripts() {
		// TODO Auto-generated method stub
    	if (menuEnableScripts == null) {
    		menuEnableScripts = new ZapMenuItem("scripts.menu.tools.enable");
    		final ExtensionScriptsUI ext = this;
    		menuEnableScripts.addActionListener(new ActionListener(){
				@Override
				public void actionPerformed(ActionEvent arg0) {
					EnableScriptsDialog dialog = new EnableScriptsDialog(ext); 
					dialog.setVisible(true);
				}});
    	}
		return menuEnableScripts ;
	}
	*/

	public void addScriptTreeTransferHander (@SuppressWarnings("rawtypes") Class c, TransferHandler th) {
		if (View.isInitialised()) {
			this.getScriptsPanel().addScriptTreeTransferHander(c, th);
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

        if (extScript != null) {
            extScript.removeScriptUI();
        }
        
        super.unload();
    }
    
	public ExtensionScript getExtScript() {
		if (extScript == null) {
			extScript = (ExtensionScript) Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.NAME);
			if (View.isInitialised()) {
				extScript.addWriter(getStdOutputPanelWriter());
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
	
	private PopupDuplicateScript getPopupDuplicateScript () {
		if (popupDuplicateScript == null) {
			popupDuplicateScript = new PopupDuplicateScript(this); 
		}
		return popupDuplicateScript;
	}
	
	private PopupNewScriptFromType getPopupNewScriptFromType () {
		if (popupNewScriptFromType == null) {
			popupNewScriptFromType = new PopupNewScriptFromType(this); 
		}
		return popupNewScriptFromType;
	}
	
	private PopupContextMenuItemFactory getPopupFactoryUseScriptForAuthentication() {
		if (popupFactoryUseScriptForAuthentication == null) {
			popupFactoryUseScriptForAuthentication = new PopupContextMenuItemFactory(
					Constant.messages.getString("scripts.popup.useForContextAs")) {

				private static final long serialVersionUID = 2158469059590381956L;

				@Override
				public ExtensionPopupMenuItem getContextMenu(Context context, String parentMenu) {
					return new PopupUseScriptAsAuthenticationScript(ExtensionScriptsUI.this, context);
				}

				@Override
				public int getMenuIndex() {
					return 1000;
				}
			};
		}

		return popupFactoryUseScriptForAuthentication;
	}

	@Override
	public void displayScript (ScriptWrapper script) {
		if (!View.isInitialised()) {
			return;
		}
		
		if (this.lockOutputToDisplayedScript) {
			// switch writers..
			if (this.currentLockedScript != null) {
				// Unset the script specific writer
				this.currentLockedScript.setWriter(null);
			}
			this.currentLockedScript = script;
			script.setWriter(this.getDisplayedScriptOutputPanelWriter());
		}
		
		if (script.getEngine() == null) {
			try {
				// Scripts loaded from the configs my have loaded before all of the engines
				script.setEngine(getExtScript().getEngineWrapper(script.getEngineName()));
			} catch (Exception e) {
				showWarningMissingEngine(script);
			}
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
			
			if (this.getConsolePanel().getOutputPanel().isClearOnRun()) {
				this.getConsolePanel().getOutputPanel().clear();
				
				if (script.getLastOutput() != null && script.getLastOutput().length() > 0) {
					this.getConsolePanel().getOutputPanel().append(script.getLastOutput());
				}
				if (script.getLastException() != null) {
					this.showError(script.getLastException());
				} else if (script.getLastErrorDetails() != null && script.getLastErrorDetails().length() > 0) {
					this.showError(script.getLastErrorDetails());
				}
			}

			if (! script.getEngine().isTextBased() && this.getConsolePanel().getOutputPanel().isEmpty()) {
				// Output message to explain about non test based scripts
				this.getConsolePanel().getOutputPanel().append(Constant.messages.getString("scripts.welcome.nontest"));
			}
		}
	}

	private void showWarningMissingEngine(ScriptWrapper script) {
		View.getSingleton().showMessageDialog(
				MessageFormat.format(getMessages().getString("scripts.warn.missing.engine"), script.getEngineName()));
		displayType(script.getType());
	}

	public void displayTemplate (ScriptWrapper script) {
		if (!View.isInitialised()) {
			return;
		}
		
		if (script.getEngine() == null) {
			try {
				// Scripts loaded from the configs my have loaded before all of the engines
				script.setEngine(getExtScript().getEngineWrapper(script.getEngineName()));
			} catch (Exception e) {
				showWarningMissingEngine(script);
			}
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
		if (this.getConsolePanel().getScript() != null && this.getConsolePanel().getScript().getEngine() != null
				&& this.getConsolePanel().getScript().getEngine().isTextBased()) {
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

	/*
	 * The writer that will get output from all scripts run
	 */
	private OutputPanelWriter getStdOutputPanelWriter() {
		if (View.isInitialised() && stdOutputPanelWriter == null) {
			stdOutputPanelWriter = new OutputPanelWriter(this.getConsolePanel().getOutputPanel());
		}
		return stdOutputPanelWriter;
	}

	/*
	 * The writer which will get output only for the script currently being displayed
	 */
	private OutputPanelWriter getDisplayedScriptOutputPanelWriter() {
		if (View.isInitialised() && displayedScriptOutputPanelWriter == null) {
			displayedScriptOutputPanelWriter = new OutputPanelWriter(this.getConsolePanel().getOutputPanel());
		}
		return this.displayedScriptOutputPanelWriter;
	}

    public void invokeTargetedScript(ScriptWrapper script, HttpMessage msg) {
    	if (View.isInitialised()) {
    		this.displayScript(script);
			this.getConsolePanel().getOutputPanel().preScriptInvoke();
			this.getConsolePanel().setTabFocus();
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

	public boolean isLockOutputToDisplayedScript() {
		return lockOutputToDisplayedScript;
	}

	public void setLockOutputToDisplayedScript(boolean lockOutputToDisplayedScript) {
		this.lockOutputToDisplayedScript = lockOutputToDisplayedScript;
		
		this.getStdOutputPanelWriter().setEnabled(!lockOutputToDisplayedScript);
		this.getDisplayedScriptOutputPanelWriter().setEnabled(lockOutputToDisplayedScript);

		if (this.currentLockedScript != null) {
			this.currentLockedScript.setWriter(null);
		}

		ScriptWrapper script = this.getScriptsPanel().getSelectedScript();
		if (script != null) {
			if (this.lockOutputToDisplayedScript) {
				script.setWriter(this.getDisplayedScriptOutputPanelWriter());
				this.currentLockedScript = script;
			} else {
				script.setWriter(null);
				this.currentLockedScript = null;
			}
		}
	}

	@Override
	public Writer getOutputWriter() {
		return this.getStdOutputPanelWriter();
	}
	
}
