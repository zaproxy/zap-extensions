/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.scripts;

import java.awt.EventQueue;
import java.awt.event.MouseAdapter;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.script.ScriptException;
import javax.swing.ImageIcon;
import javax.swing.TransferHandler;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.TreeCellRenderer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.OptionsDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptUI;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.scanrules.ActiveScriptSynchronizer;
import org.zaproxy.zap.extension.scripts.scanrules.PassiveScriptSynchronizer;
import org.zaproxy.zap.extension.stdmenus.PopupContextMenuItemFactory;
import org.zaproxy.zap.model.Context;

/**
 * The Extension that adds the UI for managing Scripts: scripts tree, scripts console and other
 * scripting related functionality.
 */
public class ExtensionScriptsUI extends ExtensionAdaptor implements ScriptEventListener, ScriptUI {

    public static final String NAME = "ExtensionScripts";
    private static ImageIcon icon;
    public static final String SCRIPT_EXT_TYPE = "extender";

    /**
     * Capability used to indicate that while scripts of the associated type can be edited in the
     * script console they are actually external to the ZAP scripting infrastructure, and so wont be
     * using it.
     */
    public static final String CAPABILITY_EXTERNAL = "external";

    /**
     * The templates that should be installed and enabled by default when the add-on is installed
     */
    private static final List<BuiltInScript> BUILT_IN_SCRIPTS =
            List.of(new BuiltInScript("Copy as curl command menu.js", true));

    private static final Logger LOGGER = LogManager.getLogger(ExtensionScriptsUI.class);

    private ScriptType extScriptType;
    private ExtenderScriptHelper helper;
    private Map<String, ExtenderScript> installedExtenderScripts = new HashMap<>();
    private ScriptEngineWrapper nullEngineWrapper = null;

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionScript.class);

    private ScriptsListPanel scriptsPanel = null;
    private ConsolePanel consolePanel = null;

    private InvokeScriptWithHttpMessagePopupMenu popupInvokeScriptWithHttpMessageMenu = null;
    private PopupEnableDisableScript popupEnableDisableScript = null;
    private PopupRemoveScript popupRemoveScript = null;
    private PopupInstantiateTemplate popupInstantiateTemplate = null;
    private PopupDuplicateScript popupDuplicateScript = null;
    private PopupNewScriptFromType popupNewScriptFromType = null;
    private PopupContextMenuItemFactory popupFactoryUseScriptForAuthentication = null;
    private PopupMenuItemSaveScript popupMenuItemSaveScript;

    private ExtensionScript extScript = null;
    private ScriptsTreeCellRenderer renderer = null;

    private ScriptConsoleOptions scriptConsoleOptions;
    private ScriptConsoleOptionsPanel scriptConsoleOptionsPanel;

    private final ActiveScriptSynchronizer activeScriptSynchronizer;
    private final PassiveScriptSynchronizer passiveScriptSynchronizer;

    private final Map<ScriptWrapper, ScriptOutputSource> outputSources = new HashMap<>();

    // private ZapMenuItem menuEnableScripts = null;

    public ExtensionScriptsUI() {
        super(NAME);
        // Make sure this extension is loaded after the ExtensionScript and after the
        // ExtensionAuthentication, so the Popup for using the scripts as authentication is properly
        // enabled (it needs the authentication method types to already be registered).
        this.setOrder(ExtensionScript.EXTENSION_ORDER + 1);
        if (this.getOrder() < ExtensionAuthentication.EXTENSION_ORDER) {
            LOGGER.error(
                    "Scripts UI extension's order is not higher than Authentication extension's");
        }
        activeScriptSynchronizer = new ActiveScriptSynchronizer();
        passiveScriptSynchronizer = new PassiveScriptSynchronizer();
    }

    public static ImageIcon getIcon() {
        if (icon == null) {
            icon = new ImageIcon(ZAP.class.getResource("/resource/icon/16/059.png"));
        }
        return icon;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getScriptConsoleOptions());

        this.getExtScript().addListener(this);
        extScriptType =
                new ScriptType(
                        SCRIPT_EXT_TYPE,
                        "scripts.type.extender",
                        hasView()
                                ? new ImageIcon(
                                        ExtensionScriptsUI.class.getResource(
                                                "/org/zaproxy/zap/extension/scripts/resources/icons/script-extender.png"))
                                : null,
                        true,
                        true);
        this.getExtScript().registerScriptType(extScriptType);

        nullEngineWrapper = new NullScriptEngineWrapper();
        this.getExtScript().registerScriptEngineWrapper(nullEngineWrapper);

        if (hasView()) {
            OptionsDialog optionsDialog = View.getSingleton().getOptionsDialog("");

            String[] scriptNode = {Constant.messages.getString("options.script.title")};
            scriptConsoleOptionsPanel = new ScriptConsoleOptionsPanel();
            optionsDialog.addParamPanel(scriptNode, scriptConsoleOptionsPanel, true);

            extensionHook.getHookView().addSelectPanel(getScriptsPanel());
            extensionHook.getHookView().addWorkPanel(getConsolePanel());
            extensionHook.addOptionsChangedListener(getConsolePanel().getCommandPanel());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupInvokeScriptWithHttpMessageMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupEnableDisableScript());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupRemoveScript());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupInstantiateTemplate());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupDuplicateScript());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupNewScriptFromType());
            // extensionHook.getHookMenu().addToolsMenuItem(getMenuEnableScripts());
            if (PopupUseScriptAsAuthenticationScript.arePrerequisitesSatisfied())
                extensionHook
                        .getHookMenu()
                        .addPopupMenuItem(getPopupFactoryUseScriptForAuthentication());

            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuItemSaveScript());
            ExtensionHelp.enableHelpKey(getConsolePanel(), "addon.scripts.console");
            ExtensionHelp.enableHelpKey(getScriptsPanel(), "addon.scripts.tree");
        }

        extensionHook.addApiImplementor(new ScriptApi(getExtScript()));
    }

    @Override
    public void optionsLoaded() {
        if (hasView()) {
            getConsolePanel().getCommandPanel().optionsChanged(getScriptConsoleOptions());
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

    @Override
    public void addScriptTreeTransferHandler(Class<?> c, TransferHandler th) {
        if (View.isInitialised()) {
            this.getScriptsPanel().addScriptTreeTransferHandler(c, th);
        }
    }

    @Override
    public void removeScriptTreeTransferHandler(Class<?> c) {
        if (View.isInitialised()) {
            this.getScriptsPanel().removeScriptTreeTransferHandler(c);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void postInstall() {
        if (this.hasView()) {
            // Register outputs for all scripts in the tree model
            getExtScript().getScriptTypes().stream()
                    .map(type -> getExtScript().getTreeModel().getNodes(type.getName()))
                    .flatMap(List::stream)
                    .map(ScriptNode::getUserObject)
                    .filter(ScriptWrapper.class::isInstance)
                    .map(ScriptWrapper.class::cast)
                    .forEach(this::registerScriptOutputSource);
        }

        // Install and enable the 'built in' scripts
        for (ScriptWrapper template : this.getExtScript().getTemplates(extScriptType)) {
            for (BuiltInScript builtInScript : BUILT_IN_SCRIPTS) {
                if (template.getName().equals(builtInScript.getName())) {
                    installBuiltInExtenderScript(template, builtInScript);
                }
            }
        }
    }

    private void installBuiltInExtenderScript(ScriptWrapper template, BuiltInScript builtInScript) {
        ScriptWrapper script = this.getExtScript().getScript(template.getName());
        if (script == null) {
            // Only install once
            template.setLoadOnStart(true);
            boolean enable = true;
            if (builtInScript.isViewRequired()) {
                enable = hasView();
            }
            template.setEnabled(enable);
            this.getExtScript().addScript(template, false);
            script = this.getExtScript().getScript(template.getName());
            if (script != null) {
                this.getExtScript().setEnabled(script, enable);
            } else {
                LOGGER.error("Failed to install built in script {}", template.getName());
            }
        }
    }

    @Override
    public void unload() {
        if (hasView()) {
            if (consolePanel != null) {
                consolePanel.unload();
            }
            if (scriptsPanel != null) {
                scriptsPanel.unload();
            }
            OptionsDialog optionsDialog = View.getSingleton().getOptionsDialog("");
            optionsDialog.removeParamPanel(scriptConsoleOptionsPanel);
            outputSources.values().forEach(getView().getOutputPanel()::unregisterOutputSource);
        }

        activeScriptSynchronizer.unload();
        passiveScriptSynchronizer.unload();

        if (extScript != null) {
            if (hasView()) {
                extScript.removeScriptUI();
            }
            extScript.removeListener(this);

            // Uninstall any enabled scripts
            for (ScriptWrapper script : extScript.getScripts(extScriptType)) {
                if (script.isEnabled()) {
                    this.uninstallExtenderScript(script);
                }
            }
            extScript.removeScriptType(extScriptType);
        }

        if (nullEngineWrapper != null) {
            this.getExtScript().removeScriptEngineWrapper(nullEngineWrapper);
        }

        super.unload();
    }

    public ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    (ExtensionScript)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionScript.NAME);
            if (View.isInitialised()) {
                extScript.setScriptUI(this);
            }
        }
        return extScript;
    }

    ScriptConsoleOptions getScriptConsoleOptions() {
        if (scriptConsoleOptions == null) {
            scriptConsoleOptions = new ScriptConsoleOptions();
        }
        return scriptConsoleOptions;
    }

    ConsolePanel getConsolePanel() {
        if (consolePanel == null) {
            consolePanel = new ConsolePanel(this);
            consolePanel.setName(Constant.messages.getString("scripts.panel.title"));
        }
        return consolePanel;
    }

    private ExtenderScriptHelper getExtensionScriptHelper() {
        if (helper == null) {
            if (View.isInitialised()) {
                helper = new ExtenderScriptHelper(View.getSingleton(), API.getInstance());
            } else {
                helper = new ExtenderScriptHelper(null, API.getInstance());
            }
        }
        return helper;
    }

    private InvokeScriptWithHttpMessagePopupMenu getPopupInvokeScriptWithHttpMessageMenu() {
        if (popupInvokeScriptWithHttpMessageMenu == null) {
            popupInvokeScriptWithHttpMessageMenu = new InvokeScriptWithHttpMessagePopupMenu(this);
        }
        return popupInvokeScriptWithHttpMessageMenu;
    }

    private PopupEnableDisableScript getPopupEnableDisableScript() {
        if (popupEnableDisableScript == null) {
            popupEnableDisableScript = new PopupEnableDisableScript(this);
        }
        return popupEnableDisableScript;
    }

    private PopupRemoveScript getPopupRemoveScript() {
        if (popupRemoveScript == null) {
            popupRemoveScript = new PopupRemoveScript(this);
        }
        return popupRemoveScript;
    }

    private PopupInstantiateTemplate getPopupInstantiateTemplate() {
        if (popupInstantiateTemplate == null) {
            popupInstantiateTemplate = new PopupInstantiateTemplate(this);
        }
        return popupInstantiateTemplate;
    }

    private PopupDuplicateScript getPopupDuplicateScript() {
        if (popupDuplicateScript == null) {
            popupDuplicateScript = new PopupDuplicateScript(this);
        }
        return popupDuplicateScript;
    }

    private PopupNewScriptFromType getPopupNewScriptFromType() {
        if (popupNewScriptFromType == null) {
            popupNewScriptFromType = new PopupNewScriptFromType(this);
        }
        return popupNewScriptFromType;
    }

    private PopupContextMenuItemFactory getPopupFactoryUseScriptForAuthentication() {
        if (popupFactoryUseScriptForAuthentication == null) {
            popupFactoryUseScriptForAuthentication =
                    new PopupContextMenuItemFactory(
                            Constant.messages.getString("scripts.popup.useForContextAs")) {

                        private static final long serialVersionUID = 2158469059590381956L;

                        @Override
                        public ExtensionPopupMenuItem getContextMenu(
                                Context context, String parentMenu) {
                            return new PopupUseScriptAsAuthenticationScript(
                                    ExtensionScriptsUI.this, context);
                        }
                    };
        }

        return popupFactoryUseScriptForAuthentication;
    }

    private PopupMenuItemSaveScript getPopupMenuItemSaveScript() {
        if (popupMenuItemSaveScript == null) {
            popupMenuItemSaveScript = new PopupMenuItemSaveScript(getScriptsPanel());
        }
        return popupMenuItemSaveScript;
    }

    @Override
    public void displayScript(ScriptWrapper script) {
        displayScript(script, true);
    }

    @Override
    public void displayScript(ScriptWrapper script, boolean allowFocus) {
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
            this.getConsolePanel().setScript(script, allowFocus);

            // Show in the tree panel
            ScriptNode node = this.getExtScript().getTreeModel().getNodeForScript(script);
            if (node != null) {
                this.getScriptsPanel().showInTree(node);
            }

            this.getConsolePanel()
                    .getCommandPanel()
                    .setScriptTooltip(
                            script.getEngine().isTextBased()
                                    ? null
                                    : Constant.messages.getString("scripts.welcome.nontext"));
        }
    }

    private void showWarningMissingEngine(ScriptWrapper script) {
        View.getSingleton()
                .showMessageDialog(
                        MessageFormat.format(
                                getMessages().getString("scripts.warn.missing.engine"),
                                script.getEngineName()));
        displayType(script.getType());
    }

    public void displayTemplate(ScriptWrapper script) {
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
        }
    }

    private void saveChanges() {
        if (this.getConsolePanel().getScript() != null
                && this.getConsolePanel().getScript().getEngine() != null
                && this.getConsolePanel().getScript().getEngine().isTextBased()) {
            // Save any changes made
            // Non text based scripts wont be updated via the console panel
            refreshScript(this.getConsolePanel().getScript());
        }
    }

    public void displayType(ScriptType type) {
        displayTypeImpl(type, false);
    }

    private void displayTypeImpl(ScriptType type, boolean template) {
        if (!View.isInitialised()) {
            return;
        }
        // Save any changes to previous script
        this.saveChanges();

        String displayText = "";
        this.getConsolePanel().clearScript();

        if (template) {
            displayText += Constant.messages.getString("scripts.template.desc");
        } else {
            displayText += Constant.messages.getString("scripts.welcome.cmd");
        }

        if (Constant.messages.containsKey(type.getI18nKey() + ".desc")) {
            displayText += Constant.messages.getString(type.getI18nKey() + ".desc");
        }
        getConsolePanel().getCommandPanel().setCommandScript(displayText);
    }

    void displayTemplateType(ScriptType type) {
        displayTypeImpl(type, true);
    }

    @Override
    public boolean isScriptDisplayed(ScriptWrapper script) {
        return View.isInitialised()
                && script != null
                && script.equals(this.getConsolePanel().getScript());
    }

    protected ScriptsListPanel getScriptsPanel() {
        if (scriptsPanel == null) {
            scriptsPanel = new ScriptsListPanel(this);
        }
        return scriptsPanel;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("scripts.desc");
    }

    public void invokeTargetedScript(ScriptWrapper script, HttpMessage msg) {
        if (View.isInitialised()) {
            executeInEdt(
                    () -> {
                        this.displayScript(script);
                        this.preInvoke(script);
                        this.getConsolePanel().setTabFocus();
                    });
        }
        this.getExtScript().invokeTargetedScript(script, msg);
    }

    @Override
    public void preInvoke(ScriptWrapper script) {
        if (script != null
                && hasView()
                && outputSources.get(script) != null
                && outputSources.get(script).isClearOnRun()) {
            getView().getOutputPanel().clear(script.getName());
        }
    }

    @Override
    public void refreshScript(ScriptWrapper script) {
        if (this.isScriptDisplayed(script)) {
            // Get the latest version from the console
            if (!script.getContents().equals(this.getConsolePanel().getCommandScript())) {
                script.setContents(this.getConsolePanel().getCommandScript());
                getExtScript().getTreeModel().nodeStructureChanged(script);
            }
        }
    }

    @Override
    public void scriptAdded(ScriptWrapper script, boolean display) {
        if (hasView()) {
            if (display) {
                executeInEdt(() -> this.displayScript(script));
            }
            registerScriptOutputSource(script);
        }
        switch (script.getType().getName()) {
            case SCRIPT_EXT_TYPE:
                if (script.isEnabled()
                        && !this.installedExtenderScripts.containsKey(script.getName())) {
                    // It has been flagged as to be enabled
                    installExtenderScript(script);
                }
                break;
            case ExtensionActiveScan.SCRIPT_TYPE_ACTIVE:
                activeScriptSynchronizer.scriptAdded(script);
                break;
            case ExtensionPassiveScan2.SCRIPT_TYPE_PASSIVE:
                passiveScriptSynchronizer.scriptAdded(script);
                break;
        }
    }

    private static void executeInEdt(Runnable r) {
        if (EventQueue.isDispatchThread()) {
            r.run();
        } else {
            try {
                EventQueue.invokeAndWait(r);
            } catch (InvocationTargetException | InterruptedException e) {
                LOGGER.warn("Failed to properly update the UI:", e);
            }
        }
    }

    @Override
    public void scriptRemoved(ScriptWrapper script) {
        if (this.isScriptDisplayed(script)) {
            executeInEdt(() -> this.getConsolePanel().clearScript());
        }
        switch (script.getType().getName()) {
            case SCRIPT_EXT_TYPE:
                if (this.installedExtenderScripts.containsKey(script.getName())) {
                    // It has been installed so uninstall it
                    uninstallExtenderScript(script);
                }
                break;
            case ExtensionActiveScan.SCRIPT_TYPE_ACTIVE:
                activeScriptSynchronizer.scriptRemoved(script);
                break;
            case ExtensionPassiveScan2.SCRIPT_TYPE_PASSIVE:
                passiveScriptSynchronizer.scriptRemoved(script);
                break;
        }
        if (hasView()) {
            this.getConsolePanel().removeScript(script);
            unregisterScriptOutputSource(script);
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
        if (hasView()) {
            getConsolePanel().updateButtonStates();
            if (outputSources.get(script) == null) {
                // We don't know about this script, register it
                registerScriptOutputSource(script);
            } else if (!script.getName().equals(outputSources.get(script).getName())) {
                // The script was renamed, re-register it with the new name
                unregisterScriptOutputSource(script);
                registerScriptOutputSource(script);
            }
        }
        if (script.getType().getName().equals(SCRIPT_EXT_TYPE)) {
            // Extender scripts are installed and uninstalled when they are enabled/disabled
            if (script.isEnabled()
                    && !this.installedExtenderScripts.containsKey(script.getName())) {
                // Its not been installed but is now enabled, so install it
                installExtenderScript(script);
            } else if (!script.isEnabled()
                    && this.installedExtenderScripts.containsKey(script.getName())) {
                // It has been installed but is now disabled, so uninstall it
                uninstallExtenderScript(script);
            }
        }
    }

    @Override
    public void scriptError(ScriptWrapper script) {
        if (hasView()) {
            if (script.getLastException() != null) {
                getView()
                        .getOutputPanel()
                        .append(
                                extractScriptExceptionMessage(script.getLastException()),
                                script.getName());
            } else {
                getView().getOutputPanel().append(script.getLastErrorDetails(), script.getName());
            }
        }
    }

    @Override
    public void scriptSaved(ScriptWrapper script) {
        switch (script.getType().getName()) {
            case ExtensionActiveScan.SCRIPT_TYPE_ACTIVE:
                activeScriptSynchronizer.scriptAdded(script);
                break;
            case ExtensionPassiveScan2.SCRIPT_TYPE_PASSIVE:
                passiveScriptSynchronizer.scriptAdded(script);
                break;
        }
    }

    @Deprecated(since = "45.9.0", forRemoval = true)
    public void showError(Exception e) {
        showError(extractScriptExceptionMessage(e));
    }

    @Deprecated(since = "45.9.0", forRemoval = true)
    public void showError(String string) {
        if (hasView()) {
            getView().getOutputPanel().append(string, NAME);
        } else {
            System.out.println("ERROR: " + string);
        }
    }

    @Deprecated(since = "45.9.0", forRemoval = true)
    public void setOutput(String string) {
        if (View.isInitialised()) {
            getView().getOutputPanel().append(string, NAME);
        }
    }

    @Override
    public void addMouseListener(MouseAdapter l) {
        if (View.isInitialised()) {
            this.getScriptsPanel().getTree().addMouseListener(l);
        }
    }

    @Override
    public void removeMouseListener(MouseAdapter l) {
        if (View.isInitialised()) {
            this.getScriptsPanel().getTree().removeMouseListener(l);
        }
    }

    @Override
    public void addSelectionListener(TreeSelectionListener tsl) {
        if (!hasView()) {
            return;
        }
        this.getScriptsPanel().getTree().addTreeSelectionListener(tsl);
    }

    @Override
    public void removeSelectionListener(TreeSelectionListener tsl) {
        if (!hasView()) {
            return;
        }
        this.getScriptsPanel().getTree().removeTreeSelectionListener(tsl);
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

    @Override
    public void addRenderer(Class<?> c, TreeCellRenderer renderer) {
        this.getScriptsTreeCellRenderer().addRenderer(c, renderer);
    }

    @Override
    public void removeRenderer(Class<?> c) {
        this.getScriptsTreeCellRenderer().removeRenderer(c);
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
    public void removeDisableScriptDialog(Class<?> klass) {
        if (View.isInitialised()) {
            this.getScriptsPanel().removeDisableScriptDialog(klass);
        }
    }

    @Override
    public void selectNode(ScriptNode node, boolean expand) {
        selectNode(node, expand, true);
    }

    @Override
    public void selectNode(ScriptNode node, boolean expand, boolean allowFocus) {
        if (View.isInitialised()) {
            this.getScriptsPanel().showInTree(node, expand, allowFocus);
            this.getScriptsPanel().setTabFocus();
        }
    }

    @Override
    public String getTreeName() {
        return ScriptsListPanel.TREE;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Deprecated(since = "45.9.0", forRemoval = true)
    public boolean isLockOutputToDisplayedScript() {
        return true;
    }

    @Deprecated(since = "45.9.0", forRemoval = true)
    public void setLockOutputToDisplayedScript(boolean lockOutputToDisplayedScript) {}

    @Override
    @Deprecated(since = "45.9.0", forRemoval = true)
    public Writer getOutputWriter() {
        if (hasView()) {
            return new OutputPanelWriter(getView().getOutputPanel(), NAME);
        }
        return null;
    }

    @Override
    public void engineAdded(final ScriptEngineWrapper scriptEngineWrapper) {
        if (!hasView()) {
            return;
        }

        if (!EventQueue.isDispatchThread()) {
            try {
                EventQueue.invokeAndWait(() -> engineAdded(scriptEngineWrapper));
            } catch (InvocationTargetException | InterruptedException e) {
                LOGGER.error("Failed to update the UI:", e);
            }
            return;
        }

        ScriptNode node = getSelectedNode();
        if (node != null && node.getUserObject() instanceof ScriptWrapper) {
            ScriptWrapper scriptWrapper = (ScriptWrapper) node.getUserObject();
            if (ExtensionScript.hasSameScriptEngine(scriptWrapper, scriptEngineWrapper)) {
                displayScript(scriptWrapper);
            }
        }
    }

    @Override
    public void engineRemoved(final ScriptEngineWrapper scriptEngineWrapper) {
        if (!hasView()) {
            return;
        }

        if (!EventQueue.isDispatchThread()) {
            try {
                EventQueue.invokeAndWait(() -> engineRemoved(scriptEngineWrapper));
            } catch (InvocationTargetException | InterruptedException e) {
                LOGGER.error("Failed to update the UI:", e);
            }
            return;
        }

        ScriptNode node = getSelectedNode();
        if (node != null && node.getUserObject() instanceof ScriptWrapper) {
            ScriptWrapper scriptWrapper = (ScriptWrapper) node.getUserObject();
            if (ExtensionScript.hasSameScriptEngine(scriptWrapper, scriptEngineWrapper)) {
                displayType(scriptWrapper.getType());
            }
        }
    }

    private void installExtenderScript(ScriptWrapper script) {
        ExtenderScript ec;
        try {
            ec = extScript.getInterface(script, ExtenderScript.class);
            if (ec == null) {
                return;
            }
            ec.install(getExtensionScriptHelper());
            this.installedExtenderScripts.put(script.getName(), ec);
            script.setError(false);
        } catch (Exception e) {
            LOGGER.warn("Failed to install extender script {}", script.getName(), e);
            extScript.setError(script, e);
            if (script.isEnabled()) {
                extScript.setEnabled(script, false);
            }
        }
    }

    private void uninstallExtenderScript(ScriptWrapper script) {
        ExtenderScript ec;
        try {
            ec = this.installedExtenderScripts.remove(script.getName());
            ec.uninstall(getExtensionScriptHelper());
        } catch (Exception e) {
            LOGGER.warn("Failed to uninstall extender script {}", script.getName(), e);
            extScript.setError(script, e);
        }
    }

    private void registerScriptOutputSource(ScriptWrapper script) {
        var outputSource = new ScriptOutputSource(script);
        outputSources.put(script, outputSource);
        getView().getOutputPanel().registerOutputSource(outputSource);
        script.setWriter(new OutputPanelWriter(getView().getOutputPanel(), script.getName()));
    }

    private void unregisterScriptOutputSource(ScriptWrapper script) {
        ScriptOutputSource outputSource = outputSources.remove(script);
        if (outputSource != null) {
            getView().getOutputPanel().unregisterOutputSource(outputSource);
        }
    }

    static String extractScriptExceptionMessage(Exception e) {
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof ScriptException) {
                return cause.getMessage();
            }
            cause = cause.getCause();
        }
        return e.toString();
    }

    static class BuiltInScript {

        private final String name;
        private final boolean viewRequired;

        BuiltInScript(String name) {
            this(name, false);
        }

        BuiltInScript(String name, boolean viewRequired) {
            this.name = name;
            this.viewRequired = viewRequired;
        }

        String getName() {
            return name;
        }

        boolean isViewRequired() {
            return viewRequired;
        }
    }
}
