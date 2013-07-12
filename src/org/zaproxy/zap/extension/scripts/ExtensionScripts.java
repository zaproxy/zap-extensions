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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.swing.ImageIcon;
import javax.swing.JMenuItem;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.scripts.javascript.JavascriptEngineWrapper;
import org.zaproxy.zap.utils.DesktopUtils;

public class ExtensionScripts extends ExtensionAdaptor {
	
	public static final String NAME = "ExtensionScripts";
	public static final ImageIcon ICON = new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png")); // Script icon
	
	private static final String LANG_ENGINE_SEP = " : ";
	protected static final String SCRIPT_CONSOLE_HOME_PAGE = "http://code.google.com/p/zaproxy/wiki/ScriptConsole";

	public static final String TYPE_STANDALONE = "standalone";
	public static final String TYPE_ACTIVE = "active";
	public static final String TYPE_PASSIVE = "passive";
	public static final String TYPE_TARGETED = "targeted";
	
	private static final String RESOURCE_ROOT = "/org/zaproxy/zap/extension/scripts/resource/icons/";
	private static final ImageIcon ASCAN_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "script-ascan.png"));
	private static final ImageIcon PSCAN_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "script-pscan.png"));
	private static final ImageIcon STANDALONE_ICON =
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "script-standalone.png"));
	/*
	private static final ImageIcon INLINE_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "script-proxy.png"));
	private static final ImageIcon TARGETED_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "script-target.png"));
	private static final ImageIcon LIBRARY_ICON =
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "script-library.png"));
	*/


	private ScriptsListPanel scriptsPanel = null;
	private ConsolePanel consolePanel = null;
	private ScriptEngineManager mgr = new ScriptEngineManager();
	private ScriptParam scriptParam = null;
	private JMenuItem menuConsoleLink = null;

	private InvokeScriptWithNodePopupMenu popupInvokeScriptWithNodeMenu = null;
	private PopupEnableDisableScript popupEnableDisableScript = null;
	private PopupRemoveScript popupRemoveScript = null;

	private ScriptTreeModel treeModel = null;
	private List <ScriptEngineWrapper> engineWrappers = new ArrayList<ScriptEngineWrapper>();
	private Map<String, ScriptType> typeMap = new HashMap<String, ScriptType>();

	private static final Logger logger = Logger.getLogger(ExtensionScripts.class);

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
        this.setOrder(60);
        
        ScriptEngine se = mgr.getEngineByName("ECMAScript");
        if (se != null) {
        	this.registerScriptEngineWrapper(new JavascriptEngineWrapper(se));
        } else {
        	logger.error("No Javascript/ECMAScript engine found");
        }
        
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

		this.registerScriptType(new ScriptType(TYPE_STANDALONE, "scripts.type.standalone", STANDALONE_ICON, false));
		// TODO move into relevant extensions
		this.registerScriptType(new ScriptType(TYPE_ACTIVE, "scripts.type.active", ASCAN_ICON, true));
		this.registerScriptType(new ScriptType(TYPE_PASSIVE, "scripts.type.passive", PSCAN_ICON, true));

	    extensionHook.addOptionsParamSet(getScriptParam());
	    
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
    
	private ConsolePanel getConsolePanel() {
		if (consolePanel == null) {
			consolePanel = new ConsolePanel(this);
		    consolePanel.setName(Constant.messages.getString("scripts.panel.title"));
		}
		return consolePanel;
	}
	
	public List<String> getScriptingEngines() {
		List <String> engineNames = new ArrayList<>();
		List<ScriptEngineFactory> engines = mgr.getEngineFactories();
		for (ScriptEngineFactory engine : engines) {
			engineNames.add(engine.getLanguageName() + LANG_ENGINE_SEP + engine.getEngineName());
		}
		Collections.sort(engineNames);
		return engineNames;
	}
	
	public void registerScriptEngineWrapper(ScriptEngineWrapper wrapper) {
		this.engineWrappers.add(wrapper);
	}
	
	public ScriptEngineWrapper getEngineWrapper(String name) {
		
		for (ScriptEngineWrapper sew : this.engineWrappers) {
			// In the configs we just use the engine name, in the UI we use the language name as well
			if (name.indexOf(LANG_ENGINE_SEP) > 0) {
				if (name.equals(sew.getLanguageName() + LANG_ENGINE_SEP + sew.getEngineName())) {
					return sew;
				}
			} else {
				if (name.equals(sew.getEngineName())) {
					return sew;
				}
			}
		}
		// Not one we know of, create a default wrapper
		List<ScriptEngineFactory> engines = mgr.getEngineFactories();
		ScriptEngine engine = null;
		for (ScriptEngineFactory e : engines) {
			if (name.indexOf(LANG_ENGINE_SEP) > 0) {
				if (name.equals(e.getLanguageName() + LANG_ENGINE_SEP + e.getEngineName())) {
					engine = e.getScriptEngine();
					break;
				}
			} else {
				if (name.equals(e.getEngineName())) {
					engine = e.getScriptEngine();
					break;
				}
			}
		}
		if (engine != null) {
			DefaultEngineWrapper dew = new DefaultEngineWrapper(engine);
			this.registerScriptEngineWrapper(dew);
			return dew;
		}
		throw new InvalidParameterException("No such engine: " + name);
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
			script.setEngine(this.getEngineWrapper(script.getEngineName()));
		}
		if (script.getEngine() != null) {
			// Save any changes
			refreshScript(this.getConsolePanel().getScript());
			// push to ScriptConsole
			this.getConsolePanel().setScript(script);
			
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

	protected ScriptParam getScriptParam() {
		if (this.scriptParam == null) {
			this.scriptParam = new ScriptParam();
			// NASTY! Need to find a cleaner way of getting the configs to load before the UI
			this.scriptParam.load(Model.getSingleton().getOptionsParam().getConfig());
		}
		return this.scriptParam;
	}
	
	protected ScriptTreeModel getTreeModel() {
		if (this.treeModel == null) {
			this.treeModel = new ScriptTreeModel();
		}
		return this.treeModel;
	}
	
	public void registerScriptType(ScriptType type) {
		if (typeMap.containsKey(type.getName())) {
			throw new InvalidParameterException("ScriptType already registered: " + type.getName());
		}
		this.typeMap.put(type.getName(), type);
		this.getTreeModel().addType(type);
	}

	public ScriptType getScriptType (String name) {
		return this.typeMap.get(name);
	}
	
	public Collection<ScriptType> getScriptTypes() {
		return typeMap.values();
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
	
	private void refreshScript(ScriptWrapper script) {
		if (this.isScriptDisplayed(script)) {
			// Get the latest version from the console
			if (! script.getContents().equals(this.getConsolePanel().getCommandScript())) {
				script.setContents(this.getConsolePanel().getCommandScript());
				this.getTreeModel().nodeStructureChanged(script);
			}
		}
	}
	
	public ScriptWrapper getScript(String name) {
		ScriptWrapper script =  this.treeModel.getScript(name);
		refreshScript(script);
		return script;
	}
	
	public void addScript(ScriptWrapper script) {
		this.addScript(script, true);
	}
	
	public void addScript(ScriptWrapper script, boolean display) {
		if (script == null) {
			return;
		}
		ScriptNode node = this.getTreeModel().addScript(script);
		if (display && View.isInitialised() && node != null) {
			this.displayScript(script);
			this.getScriptsPanel().showInTree(node);
		}
	}

	public void saveScript(ScriptWrapper script) throws IOException {
		refreshScript(script);
	    BufferedWriter fw = new BufferedWriter(new FileWriter(script.getFile(), false));
        fw.append(script.getContents());
        fw.close();
        this.setChanged(script, false);
		this.getScriptParam().addScript(script);
		this.getScriptParam().saveScripts();
	}

	public void removeScript(ScriptWrapper script) {
		script.setLoadOnStart(false);
		this.getScriptParam().saveScripts();
		this.getTreeModel().removeScript(script);
	}

	@Override
	public void optionsLoaded() {
		for (ScriptWrapper script : this.getScriptParam().getScripts()) {
			try {
				this.loadScript(script);
				this.addScript(script, false);
				
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}
	
	public ScriptWrapper loadScript(ScriptWrapper script) throws IOException {
	    BufferedReader fr = new BufferedReader(new FileReader(script.getFile()));
	    StringBuilder sb = new StringBuilder();
        String line;
        try {
			while ((line = fr.readLine()) != null) {
			    sb.append(line);
			    sb.append("\n");
			}
		} finally {
	        fr.close();
		}
        script.setContents(sb.toString());
        script.setChanged(false);
        
        if (script.getType() == null) {
        	// This happens when scripts are loaded from the configs as the types 
        	// may well not have been registered at that stage
System.out.println("SBSB ext loadScript, typeName = " + script.getTypeName());
        	script.setType(this.getScriptType(script.getTypeName()));
        }
	    return script;
	}

	public List<ScriptWrapper> getScripts(String type) {
		return this.getScripts(this.getScriptType(type));
	}

	public List<ScriptWrapper> getScripts(ScriptType type) {
		List<ScriptWrapper> scripts = new ArrayList<ScriptWrapper>();
		if (type == null) {
			return scripts;
		}
		for (ScriptNode node : this.getTreeModel().getNodes(type.getName())) {
			ScriptWrapper script = (ScriptWrapper) node.getUserObject();
			refreshScript(script);
			scripts.add((ScriptWrapper) node.getUserObject());
		}
		return scripts;
	}

	public Invocable invokeScript(ScriptWrapper script, Writer writer) throws ScriptException, IOException {
		if (script.getEngine() == null) {
			// Scripts loaded from the configs my have loaded before all of the engines
			script.setEngine(this.getEngineWrapper(script.getEngineName()));
		}
		
		if (script.getEngine() == null) {
			throw new ScriptException("Failed to find script engine: " + script.getEngineName());
		}
		
		refreshScript(script);
		script.setLastErrorDetails("");
		script.setLastException(null);
		script.setLastOutput("");
		
		if (this.isScriptDisplayed(script)) {
			this.getConsolePanel().getOutputPanel().clear();
		}
		ScriptEngine se = script.getEngine().getEngine();
	    se.getContext().setWriter(writer);
	    try {
	    	se.eval(script.getContents());
	    } catch (Exception e) {
	    	writer.append(e.toString());
	    	this.setError(script, e);
	    	this.setEnabled(script, false);
	    }
		return (Invocable) se;
	}

	public void setChanged(ScriptWrapper script, boolean changed) {
		script.setChanged(changed);
		ScriptNode node = this.getTreeModel().getNodeForScript(script);
		if (node.getNodeName().equals(script.getName())) {
			// The name is the same
			this.getTreeModel().nodeStructureChanged(script);
		} else {
			// The name has changed
			node.setNodeName(script.getName());
			this.getTreeModel().nodeStructureChanged(node.getParent());
		}
		
		if (View.isInitialised()) {
			this.getScriptsPanel().setButtonStates();
		}
	}

	public void setEnabled(ScriptWrapper script, boolean enabled) {
		script.setEnabled(enabled);
		this.getTreeModel().nodeStructureChanged(script);
	}

	public void setError(ScriptWrapper script, String details) {
		script.setError(true);
		script.setLastOutput(details);
		
		this.getTreeModel().nodeStructureChanged(script);
		if (this.isScriptDisplayed(script)) {
			this.showError(details);
		}
	}

	public void setError(ScriptWrapper script, Exception e) {
		script.setError(true);
		script.setLastException(e);
		
		this.getTreeModel().nodeStructureChanged(script);
		if (this.isScriptDisplayed(script)) {
			this.showError(e);
		}
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
