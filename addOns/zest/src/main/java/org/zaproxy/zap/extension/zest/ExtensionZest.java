/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.awt.Component;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import net.htmlparser.jericho.Source;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestResultsTableModel.ZestResultsTableEntry;
import org.zaproxy.zap.extension.zest.dialogs.ZestDialogManager;
import org.zaproxy.zap.extension.zest.menu.ZestMenuManager;
import org.zaproxy.zap.view.ZapToggleButton;
import org.zaproxy.zest.core.v1.ZestActionFail;
import org.zaproxy.zest.core.v1.ZestAssertion;
import org.zaproxy.zest.core.v1.ZestAssignFieldValue;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestExpressionLength;
import org.zaproxy.zest.core.v1.ZestExpressionStatusCode;
import org.zaproxy.zest.core.v1.ZestFieldDefinition;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.core.v1.ZestStructuredExpression;
import org.zaproxy.zest.core.v1.ZestVariables;
import org.zaproxy.zest.impl.ZestScriptEngineFactory;

public class ExtensionZest extends ExtensionAdaptor implements ProxyListener, ScriptEventListener {

    public static final String NAME = "ExtensionZest";
    public static final ImageIcon ZEST_ICON =
            new ImageIcon(
                    ExtensionZest.class.getResource(
                            "/org/zaproxy/zap/extension/zest/resources/icons/fruit-orange.png"));

    private static final ImageIcon RECORD_OFF_ICON =
            new ImageIcon(
                    ExtensionZest.class.getResource(
                            "/org/zaproxy/zap/extension/zest/resources/icons/cassette.png"));
    private static final ImageIcon RECORD_ON_ICON =
            new ImageIcon(
                    ExtensionZest.class.getResource(
                            "/org/zaproxy/zap/extension/zest/resources/icons/cassette-red.png"));

    public static final String HTTP_HEADER_X_SECURITY_PROXY = "X-Security-Proxy";
    public static final String VALUE_RECORD = "record";

    private static final Logger logger = Logger.getLogger(ExtensionZest.class);

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    private ZestParam param = null;
    private OptionsZestPanel optionsZestPanel = null;

    private ZestResultsPanel zestResultsPanel = null;
    private ZapToggleButton recordButton = null;
    private JToolBar.Separator toolbarSeparator;

    private ZestTreeModel zestTreeModel = null;
    private ZestDialogManager dialogManager = null;
    private ZestEngineWrapper zestEngineWrapper = null;
    private ZestScriptEngineFactory zestEngineFactory = null;

    private ExtensionScript extScript = null;
    private ExtensionAntiCSRF extAcsrf = null;
    private ZestScript lastRunScript = null;
    private HttpMessage lastSelectedMessage = null;
    private Map<String, String> acsrfTokenToVar = new HashMap<String, String>();

    private ZestFuzzerDelegate fuzzerMessenger = null;
    private ScriptNode scriptNodeRecording = null;

    // Cut-n-paste stuff
    private List<ScriptNode> cnpNodes = null;
    private boolean cutNodes = false;

    // Client side recording
    private Map<String, String> clientUrlToWindowHandle = new HashMap<String, String>();
    private String startRecordingUrl = null;
    private int recordingWinId = 0;
    private ScriptNode recordingNode = null;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionZest() {
        super(NAME);
        this.setOrder(73); // Almost looks like ZE ;)
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getParam());

        if (getView() != null) {
            extensionHook.addProxyListener(this);
            extensionHook.addSessionListener(new ViewSessionChangedListener());

            extensionHook.getHookView().addStatusPanel(this.getZestResultsPanel());
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());

            this.dialogManager = new ZestDialogManager(this, this.getExtScript().getScriptUI());
            new ZestMenuManager(this, extensionHook);

            View.getSingleton().addMainToolbarButton(getRecordButton());
            View.getSingleton().addMainToolbarSeparator(getToolbarSeparator());

            if (getExtScript().getScriptUI() != null) {
                ZestTreeTransferHandler th = new ZestTreeTransferHandler(this);
                getExtScript()
                        .getScriptUI()
                        .addScriptTreeTransferHandler(ZestElementWrapper.class, th);
            }
        }

        List<Path> defaultTemplates = getDefaultTemplates();

        ScriptEngineManager mgr = new ScriptEngineManager();
        ScriptEngine se = mgr.getEngineByName(ZestScriptEngineFactory.NAME);
        if (se != null) {
            // Looks like this only works if the Zest lib is in the top level
            // lib directory
            this.zestEngineFactory = (ZestScriptEngineFactory) se.getFactory();
        } else {
            // Needed for when the Zest lib is in an add-on (usual case)
            this.zestEngineFactory = new ZestScriptEngineFactory();
            se = zestEngineFactory.getScriptEngine();
        }
        zestEngineWrapper = new ZestEngineWrapper(zestEngineFactory, defaultTemplates);
        this.getExtScript().registerScriptEngineWrapper(zestEngineWrapper);

        this.getExtScript().addListener(this);

        if (this.getExtScript().getScriptUI() != null) {
            ZestTreeCellRenderer renderer = new ZestTreeCellRenderer();
            this.getExtScript().getScriptUI().addRenderer(ZestElementWrapper.class, renderer);
            this.getExtScript().getScriptUI().addRenderer(ZestScriptWrapper.class, renderer);
            this.getExtScript().getScriptUI().disableScriptDialog(ZestScriptWrapper.class);
        }
    }

    private List<Path> getDefaultTemplates() {
        AddOn addOn = getAddOn();
        if (addOn == null) {
            // Probably running from source...
            return Collections.emptyList();
        }

        List<String> files = addOn.getFiles();
        if (files == null || files.isEmpty()) {
            return Collections.emptyList();
        }

        ArrayList<Path> defaultTemplates = new ArrayList<>(files.size());
        Path zapHome = Paths.get(Constant.getZapHome());
        for (String file : files) {
            if (file.startsWith(ExtensionScript.TEMPLATES_DIR)) {
                defaultTemplates.add(zapHome.resolve(file));
            }
        }
        defaultTemplates.trimToSize();
        return defaultTemplates;
    }

    public boolean isPlugNHackInstalled() {
        return Control.getSingleton().getExtensionLoader().getExtension("ExtensionPlugNHack")
                != null;
    }

    public void recordClientScript(String url) {
        Extension extPnh =
                Control.getSingleton().getExtensionLoader().getExtension("ExtensionPlugNHack");
        if (extPnh != null) {
            Method method = null;
            try {
                URI uri = new URI(url, true);

                startClientRecording(url);

                method = extPnh.getClass().getMethod("launchAndRecordClient", URI.class);

                method.invoke(extPnh, uri);

            } catch (Exception e) {
                // Its an older version, so just dont try to use it
                e.printStackTrace();
            }
        }
    }

    protected ZestScriptEngineFactory getZestScriptEngineFactory() {
        return this.zestEngineFactory;
    }

    public ZestFuzzerDelegate getFuzzerDelegate() {
        if (fuzzerMessenger == null) {
            fuzzerMessenger = new ZestFuzzerDelegate();
        }
        return fuzzerMessenger;
    }

    @Override
    public void optionsLoaded() {
        if (getView() == null || EventQueue.isDispatchThread()) {
            // Convert scripts loaded on start into real Zest scripts
            for (ScriptType type : this.getExtScript().getScriptTypes()) {
                for (ScriptWrapper script : this.getExtScript().getScripts(type)) {
                    if (ZestScriptEngineFactory.NAME.equals(script.getEngineName())) {
                        this.scriptAdded(script, false);
                    }
                }
            }
        } else {
            EventQueue.invokeLater(
                    new Runnable() {

                        @Override
                        public void run() {
                            optionsLoaded();
                        }
                    });
        }
    }

    public ZestEngineWrapper getZestEngineWrapper() {
        return zestEngineWrapper;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            View view = View.getSingleton();
            view.removeMainToolbarButton(getRecordButton());
            view.removeMainToolbarSeparator(getToolbarSeparator());
            dialogManager.unload();
        }

        // Convert zest scripts into "plain" scripts
        for (ScriptType type : this.getExtScript().getScriptTypes()) {
            for (ScriptWrapper script : this.getExtScript().getScripts(type)) {
                if (script.getEngineName().equals(ZestScriptEngineFactory.NAME)) {
                    ScriptNode node = this.getExtScript().getTreeModel().getNodeForScript(script);
                    if (script instanceof ZestScriptWrapper) {
                        ZestScriptWrapper zsw = (ZestScriptWrapper) script;
                        ScriptWrapper original = zsw.getOriginal();
                        original.setEngine(zsw.getEngine());
                        original.setEnabled(zsw.isEnabled());
                        original.setFile(zsw.getFile());
                        original.setLoadOnStart(zsw.isLoadOnStart());
                        original.setContents(zsw.getContents());
                        original.setChanged(zsw.isChanged());

                        node.setUserObject(original);
                        node.removeAllChildren();
                        this.getExtScript().getTreeModel().nodeStructureChanged(node);
                    }
                }
            }
        }

        if (this.getExtScript().getScriptUI() != null) {
            this.getExtScript()
                    .getScriptUI()
                    .removeScriptTreeTransferHandler(ZestScriptWrapper.class);
            this.getExtScript()
                    .getScriptUI()
                    .removeScriptTreeTransferHandler(ZestElementWrapper.class);

            this.getExtScript().getScriptUI().removeRenderer(ZestElementWrapper.class);
            this.getExtScript().getScriptUI().removeRenderer(ZestScriptWrapper.class);
            this.getExtScript().getScriptUI().removeDisableScriptDialog(ZestScriptWrapper.class);
        }

        getExtScript().removeListener(this);
        getExtScript().removeScriptEngineWrapper(zestEngineWrapper);

        super.unload();
    }

    public ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    (ExtensionScript)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionScript.NAME);
        }
        return extScript;
    }

    public ExtensionAntiCSRF getExtACSRF() {
        if (extAcsrf == null) {
            extAcsrf =
                    (ExtensionAntiCSRF)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionAntiCSRF.NAME);
        }
        return extAcsrf;
    }

    public ZestDialogManager getDialogManager() {
        return dialogManager;
    }

    private ZestResultsPanel getZestResultsPanel() {
        if (zestResultsPanel == null) {
            zestResultsPanel = new ZestResultsPanel(this);
        }
        return zestResultsPanel;
    }

    public ZestTreeModel getZestTreeModel() {
        if (zestTreeModel == null && getExtScript() != null) {
            zestTreeModel = new ZestTreeModel(this.getExtScript().getTreeModel());
        }
        return zestTreeModel;
    }

    private JToggleButton getRecordButton() {
        if (recordButton == null) {
            recordButton = new ZapToggleButton();
            recordButton.setIcon(RECORD_OFF_ICON);
            recordButton.setSelectedIcon(RECORD_ON_ICON);
            recordButton.setToolTipText(
                    Constant.messages.getString("zest.toolbar.button.record.off"));
            recordButton.setSelectedToolTipText(
                    Constant.messages.getString("zest.toolbar.button.record.on"));

            recordButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            if (recordButton.isSelected()) {
                                getDialogManager().showZestRecordScriptDialog(null);
                            } else {
                                cancelScriptRecording();
                            }
                        }
                    });
        }
        return recordButton;
    }

    private JToolBar.Separator getToolbarSeparator() {
        if (toolbarSeparator == null) {
            toolbarSeparator = new JToolBar.Separator();
        }
        return toolbarSeparator;
    }

    public void cancelScriptRecording() {
        if (scriptNodeRecording != null) {
            // Turn recording off for the 'current' script being recording
            getZestTreeModel().getScriptWrapper(scriptNodeRecording).setRecording(false);
            getZestTreeModel().nodeChanged(scriptNodeRecording);
            scriptNodeRecording = null;
        }
        recordingNode = null;
        getRecordButton().setSelected(false);
    }

    public void setRecording(ScriptNode node, boolean record) {
        if (node != null && node.getUserObject() instanceof ZestScriptWrapper) {
            ZestScriptWrapper script = (ZestScriptWrapper) node.getUserObject();
            script.setRecording(record);
            getZestTreeModel().nodeChanged(node);
            if (node.equals(scriptNodeRecording)) {
                // User has cancelled the recording via the right click option,
                // keep the button in step
                cancelScriptRecording();
            }
        }
    }

    public void redact(ScriptNode node, String replace, String replaceWith, boolean recurse) {
        if (ZestZapUtils.getElement(node) instanceof ZestRequest) {
            ZestRequest request = (ZestRequest) ZestZapUtils.getElement(node);
            this.replaceInResponse(request, replace, replaceWith);
            this.updated(node);
        }
        if (recurse) {
            for (int i = 0; i < node.getChildCount(); i++) {
                this.redact((ScriptNode) node.getChildAt(i), replace, replaceWith, true);
            }
        }
        // Good chance the current response has been changed
        this.refreshMessage();
    }

    public void perameterize(
            ZestScriptWrapper script,
            ScriptNode node,
            ZestRequest request,
            String replace,
            String token,
            boolean replaceInCurrent,
            boolean replaceInAdded) {
        script.getZestScript().getParameters().addVariable(token, replace);
        token =
                script.getZestScript().getParameters().getTokenStart()
                        + token
                        + script.getZestScript().getParameters().getTokenEnd();
        if (replaceInCurrent) {
            ZestStatement stmt = script.getZestScript().getNext();
            while (stmt != null) {
                if (stmt instanceof ZestRequest) {
                    this.replaceInRequest((ZestRequest) stmt, replace, token);
                }
                stmt = stmt.getNext();
            }
            // All nodes could have changed
            this.refreshNode(this.getZestTreeModel().getScriptWrapperNode(node));

        } else {
            this.replaceInRequest(request, replace, token);
            this.updated(node);
        }
        if (replaceInAdded) {
            // TODO support tokens in added reqs
        }
        // Good chance the current response has been changed
        if (View.isInitialised()) {
            this.refreshMessage();
            // Show scripts dialog, selecting the Parameters tab
            this.dialogManager.showZestEditScriptDialog(node, script, false, 1);
        }
    }

    private void replaceInResponse(ZestRequest request, String replace, String replaceWith) {
        ZestResponse resp = request.getResponse();
        if (resp != null) {
            request.setResponse(
                    new ZestResponse(
                            request.getUrl(),
                            resp.getHeaders().replace(replace, replaceWith),
                            resp.getBody().replace(replace, replaceWith),
                            +resp.getStatusCode(),
                            resp.getResponseTimeInMs()));
        }
    }

    private void replaceInRequest(ZestRequest request, String replace, String replaceWith) {
        ZestResponse resp = request.getResponse();
        if (resp != null) {
            request.setUrlToken(request.getUrl().toString().replace(replace, replaceWith));
            request.setHeaders(request.getHeaders().replace(replace, replaceWith));
            request.setData(request.getData().replace(replace, replaceWith));
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("zest.desc");
    }

    public ScriptNode add(ZestScriptWrapper script, boolean display) {
        logger.debug("add script " + script.getName());
        ScriptNode node = this.getExtScript().addScript(script, display);
        this.display(script, node, true);
        if (script.isRecording()) {
            scriptNodeRecording = node;
            // OK, I admit I dont know why this line is required .. but it is ;)
            ((ZestScriptWrapper) node.getUserObject()).setRecording(true);
            getZestTreeModel().nodeChanged(scriptNodeRecording);
        }
        return node;
    }

    public void display(ZestScriptWrapper script, ScriptNode node, boolean expand) {
        if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
            this.getExtScript().getScriptUI().selectNode(node, expand);
            this.getExtScript().getScriptUI().displayScript(script);
        }
    }

    public void display(ScriptNode node, boolean expand) {
        if (node == null) {
            return;
        }
        logger.debug("Display node=" + node.getNodeName() + " expand=" + expand);
        if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
            this.getExtScript()
                    .getScriptUI()
                    .displayScript(this.getZestTreeModel().getScriptWrapper(node));
            this.getExtScript().getScriptUI().selectNode(node, expand);
        }
    }

    public void updated(ScriptNode node) {
        if (node == null) {
            return;
        }
        logger.debug("Updated node=" + node.getNodeName());
        this.getZestTreeModel().update(node);
        ZestScriptWrapper sw = this.getZestTreeModel().getScriptWrapper(node);
        sw.setChanged(true);

        if (this.getExtScript().getScriptUI() != null
                && this.getExtScript().getScriptUI().isScriptDisplayed(sw)) {
            // We need to do this to prevent the UI slating any changes
            this.getExtScript().getScriptUI().displayScript(sw);
        }
    }

    public List<ScriptNode> getAllZestScriptNodes() {
        List<ScriptNode> list = new ArrayList<ScriptNode>();

        for (ScriptType type : this.getExtScript().getScriptTypes()) {
            for (ScriptNode node : this.getExtScript().getTreeModel().getNodes(type.getName())) {
                if (ZestZapUtils.isZestNode(node)) {
                    list.add(node);
                }
            }
        }
        return Collections.unmodifiableList(list);
    }

    public List<ScriptNode> getZestScriptNodes(String type) {
        List<ScriptNode> list = new ArrayList<ScriptNode>();

        for (ScriptNode node : this.getExtScript().getTreeModel().getNodes(type)) {
            if (ZestZapUtils.isZestNode(node)) {
                list.add(node);
            }
        }
        return Collections.unmodifiableList(list);
    }

    public List<ScriptNode> getZestScriptNodesWithCapability(String capability) {
        List<ScriptNode> scriptNodes = new ArrayList<>();
        for (ScriptType scriptType : getExtScript().getScriptTypes()) {
            if (scriptType.hasCapability(capability)) {
                for (ScriptNode node : getZestScriptNodes(scriptType.getName())) {
                    scriptNodes.add(node);
                }
            }
        }
        return Collections.unmodifiableList(scriptNodes);
    }

    public List<ScriptWrapper> getZestScripts(String type) {
        List<ScriptWrapper> list = new ArrayList<ScriptWrapper>();
        for (ScriptWrapper sw : this.getExtScript().getScripts(type)) {
            if (sw.getEngineName().equals(ZestScriptEngineFactory.NAME)) {
                list.add(sw);
            }
        }
        return Collections.unmodifiableList(list);
    }

    public void addToParent(ScriptNode parent, SiteNode sn, String prefix) {
        try {
            this.addToParent(parent, sn.getHistoryReference().getHttpMessage(), prefix);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    public void addToParent(ScriptNode parent, HttpMessage msg, String prefix) {
        if (parent == null) {
            // They're gone for the 'new script' option...
            logger.debug("addToParent parent=null msg=" + msg.getRequestHeader().getURI());
            this.dialogManager.showZestEditScriptDialog(null, null, prefix, true);
            if (msg != null) {
                this.dialogManager.addDeferedMessage(msg);
            }
        } else {
            logger.debug(
                    "addToParent parent="
                            + parent.getNodeName()
                            + " msg="
                            + msg.getRequestHeader().getURI());

            try {
                ZestRequest req = ZestZapUtils.toZestRequest(msg, false, this.getParam());
                ZestScriptWrapper zsw = this.getZestTreeModel().getScriptWrapper(parent);

                ZestScript script = zsw.getZestScript();
                ZestElement parentZe = ZestZapUtils.getElement(parent);

                if (parentZe instanceof ZestScript) {
                    script.add(req);
                } else if (parentZe instanceof ZestConditional) {
                    if (ZestZapUtils.getShadowLevel(parent) == 2) {
                        ((ZestConditional) ZestZapUtils.getElement(parent)).addElse(req);
                    } else {
                        ((ZestConditional) ZestZapUtils.getElement(parent)).addIf(req);
                    }
                } else if (parentZe instanceof ZestLoop<?>) {
                    ((ZestLoop<?>) ZestZapUtils.getElement(parent)).addStatement(req);
                } else {
                    throw new IllegalArgumentException(
                            "Unexpected parent node: "
                                    + parentZe.getElementType()
                                    + " "
                                    + parent.getNodeName());
                }

                if (zsw.isIncStatusCodeAssertion()) {
                    req.addAssertion(
                            new ZestAssertion(
                                    new ZestExpressionStatusCode(
                                            msg.getResponseHeader().getStatusCode())));
                }
                if (zsw.isIncLengthAssertion()) {
                    req.addAssertion(
                            new ZestAssertion(
                                    new ZestExpressionLength(
                                            ZestVariables.RESPONSE_BODY,
                                            getResponseBodyLength(msg),
                                            zsw.getLengthApprox())));
                }

                if (getExtACSRF() != null) {
                    // Identify and CSRF tokens being used
                    List<AntiCsrfToken> acsrfTokens = getExtACSRF().getTokens(msg);
                    for (AntiCsrfToken acsrf : acsrfTokens) {
                        String var = acsrfTokenToVar.get(acsrf.getValue());
                        if (var != null) {
                            logger.debug(
                                    "Replacing ACSRF value "
                                            + acsrf.getValue()
                                            + " with variable "
                                            + var);
                            this.replaceInRequest(
                                    req,
                                    acsrf.getValue(),
                                    script.getParameters().getTokenStart()
                                            + var
                                            + script.getParameters().getTokenEnd());
                        }
                    }
                }

                // Update tree
                ScriptNode reqNode = this.getZestTreeModel().addToNode(parent, req);

                if (getExtACSRF() != null) {
                    // Create assignments for any ACSRF tokens
                    Source src = new Source(msg.getResponseBody().toString());
                    List<AntiCsrfToken> acsrfTokens = getExtACSRF().getTokensFromResponse(msg, src);
                    for (AntiCsrfToken acsrf : acsrfTokens) {
                        ZestAssignFieldValue zafv = new ZestAssignFieldValue();
                        int id = 1;
                        Set<String> names = script.getVariableNames();
                        while (names.contains("csrf" + id)) {
                            id++;
                        }
                        zafv.setVariableName("csrf" + id);
                        ZestFieldDefinition fd = new ZestFieldDefinition();
                        fd.setFormIndex(acsrf.getFormIndex());
                        fd.setFieldName(acsrf.getName());
                        // Record mapping of value to variable name for later
                        // replacement
                        logger.debug(
                                "Recording ACSRF value "
                                        + acsrf.getValue()
                                        + " against variable "
                                        + zafv.getVariableName());
                        acsrfTokenToVar.put(acsrf.getValue(), zafv.getVariableName());
                        zafv.setFieldDefinition(fd);
                        this.addToParent(parent, zafv);
                    }
                }

                this.updated(reqNode);
                this.display(reqNode, false);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    private static int getResponseBodyLength(HttpMessage message) {
        // The following code mimics the behaviour of HttpMethodBase.getResponseBodyAsString() which
        // is the method used by the
        // Zest engine to obtain the response body after sending a request.
        byte[] body = message.getResponseBody().getBytes();
        String charset = message.getResponseHeader().getCharset();
        if (charset == null) {
            charset = StandardCharsets.ISO_8859_1.name();
        }

        try {
            return new String(body, charset).length();
        } catch (UnsupportedEncodingException e) {
            return new String(body).length();
        }
    }

    public void addToRequest(ScriptNode node, ZestRequest req, ZestAssertion assertion) {
        req.addAssertion(assertion);
        if (node != null) {
            ScriptNode child = this.getZestTreeModel().addToNode(node, assertion);
            this.updated(child);
            this.display(child, false);
        } else {
            throw new IllegalArgumentException(
                    "Failed to find ZestRequest in tree " + ZestZapUtils.toUiString(req));
        }
    }

    private ScriptNode addAfterRequest(
            ZestScript script,
            ScriptNode parentNode,
            ScriptNode childNode,
            ZestStatement existingChild,
            ZestStatement newChild) {
        script.add(script.getIndex(existingChild) + 1, newChild);
        ScriptNode child = this.getZestTreeModel().addAfterNode(parentNode, childNode, newChild);
        this.updated(child);
        this.display(child, false);
        return child;
    }

    private ScriptNode addBeforeRequest(
            ZestScript script,
            ScriptNode parentNode,
            ScriptNode childNode,
            ZestStatement existingChild,
            ZestStatement newChild) {
        script.add(script.getIndex(existingChild), newChild);
        ScriptNode child = this.getZestTreeModel().addBeforeNode(parentNode, childNode, newChild);
        this.updated(child);
        this.display(child, false);
        return child;
    }

    public final ScriptNode addToParent(ScriptNode parent, ZestExpression newExp) {
        logger.debug("addToParent parent=" + parent.getNodeName() + " new=" + newExp.toString());
        ScriptNode node;
        ZestElement parentZe = ZestZapUtils.getElement(parent);
        if (parentZe instanceof ZestConditional) {
            ZestConditional pzc = (ZestConditional) parentZe;
            if (pzc.getRootExpression() != null) {
                this.delete((ScriptNode) parent.getChildAt(0));
            }
            pzc.setRootExpression(newExp); // removes the previous root
            // expression!
            node = this.getZestTreeModel().addToNode(parent, newExp);
            this.updated(parent);
            this.display(parent, true);
        } else if (parentZe instanceof ZestStructuredExpression) {
            ZestStructuredExpression pzse = (ZestStructuredExpression) parentZe;
            pzse.addChildCondition(newExp);
            node = this.getZestTreeModel().addToNode(parent, newExp);
        } else {
            throw new IllegalArgumentException(
                    "Unexpected parent node: "
                            + ZestZapUtils.getElement(parent).getElementType()
                            + " ==> "
                            + parent.getNodeName());
        }
        this.updated(node);
        this.display(node, true);
        return node;
    }

    public final ScriptNode addToParent(ScriptNode parent, ZestStatement newChild) {
        return this.addToParent(parent, newChild, true);
    }

    public final ScriptNode addToParent(
            ScriptNode parent, ZestStatement newChild, boolean display) {
        logger.debug(
                "addToParent parent=" + parent.getNodeName() + " new=" + newChild.getElementType());
        ScriptNode node;
        ZestElement parentElement = ZestZapUtils.getElement(parent);
        if (parentElement instanceof ZestScript) {
            ZestScript zc = (ZestScript) parentElement;
            zc.add(newChild);
            node = this.getZestTreeModel().addToNode(parent, newChild);
        } else if (parentElement instanceof ZestConditional) {
            if (ZestZapUtils.getShadowLevel(parent) == 0) {
                parent = (ScriptNode) parent.getParent().getChildAfter(parent);
            }
            ZestConditional zc = (ZestConditional) parentElement;
            if (ZestZapUtils.getShadowLevel(parent) == 2) {
                zc.addElse(newChild);
            } else {
                zc.addIf(newChild);
            }
            node = this.getZestTreeModel().addToNode(parent, newChild);

        } else if (parentElement instanceof ZestLoop<?>) {
            ZestLoop<?> zl = (ZestLoop<?>) parentElement;
            zl.addStatement(newChild);
            node = this.getZestTreeModel().addToNode(parent, newChild);
        } else if (parentElement instanceof ZestStatement) {
            node = this.getZestTreeModel().addAfterNode(parent.getParent(), parent, newChild);
        } else {
            throw new IllegalArgumentException(
                    "Unexpected parent node: " + parentElement + " " + parent.getNodeName());
        }
        this.updated(node);
        if (display) {
            this.display(node, false);
        }
        return node;
    }

    public ScriptNode addAfterRequest(
            ScriptNode parent,
            ScriptNode childNode,
            ZestStatement existingChild,
            ZestStatement newChild) {
        logger.debug(
                "addAfterRequest parent="
                        + parent.getNodeName()
                        + " existing="
                        + existingChild.getElementType()
                        + " new="
                        + newChild.getElementType());

        if (ZestZapUtils.getElement(parent) instanceof ZestScript) {
            return this.addAfterRequest(
                    (ZestScript) ZestZapUtils.getElement(parent),
                    parent,
                    childNode,
                    existingChild,
                    newChild);

        } else if (ZestZapUtils.getElement(parent) instanceof ZestConditional) {
            ZestConditional zc = (ZestConditional) ZestZapUtils.getElement(parent);

            if (ZestZapUtils.getShadowLevel(parent) == 2) {
                zc.addElse(zc.getIndex(existingChild) + 1, newChild);
            } else { // cannot be non shadow
                zc.addIf(zc.getIndex(existingChild) + 1, newChild);
            }
            ScriptNode child =
                    this.getZestTreeModel()
                            .addToNodeAt(parent, newChild, zc.getIndex(existingChild) + 1);
            this.updated(child);
            this.display(child, false);
            return child;
        } else if (ZestZapUtils.getElement(parent) instanceof ZestLoop<?>) {
            ZestLoop<?> zl = (ZestLoop<?>) ZestZapUtils.getElement(parent);
            zl.add(zl.getIndex(existingChild) + 1, newChild);
            ScriptNode child =
                    this.getZestTreeModel()
                            .addToNodeAt(parent, newChild, zl.getIndex(existingChild) + 1);
            this.updated(child);
            this.display(child, false);
            return child;
        } else {
            throw new IllegalArgumentException(
                    "Unexpected parent node: "
                            + ZestZapUtils.getElement(parent)
                            + " "
                            + parent.getNodeName());
        }
    }

    public ScriptNode addBeforeRequest(
            ScriptNode parent,
            ScriptNode childNode,
            ZestStatement existingChild,
            ZestStatement newChild) {
        logger.debug(
                "addAfterRequest parent="
                        + parent.getNodeName()
                        + " existing="
                        + existingChild.getElementType()
                        + " new="
                        + newChild.getElementType());

        if (ZestZapUtils.getElement(parent) instanceof ZestScript) {
            return this.addBeforeRequest(
                    (ZestScript) ZestZapUtils.getElement(parent),
                    parent,
                    childNode,
                    existingChild,
                    newChild);

        } else if (ZestZapUtils.getElement(parent) instanceof ZestConditional) {
            ZestConditional zc = (ZestConditional) ZestZapUtils.getElement(parent);

            if (ZestZapUtils.getShadowLevel(parent) == 2) {
                zc.addElse(zc.getIndex(existingChild), newChild);
            } else { // cannot be non shadow
                zc.addIf(zc.getIndex(existingChild), newChild);
            }
            ScriptNode child = this.getZestTreeModel().addBeforeNode(parent, childNode, newChild);
            this.updated(child);
            this.display(child, false);
            return child;
        } else if (ZestZapUtils.getElement(parent) instanceof ZestLoop<?>) {
            ZestLoop<?> zl = (ZestLoop<?>) ZestZapUtils.getElement(parent);
            zl.add(zl.getIndex(existingChild), newChild);
            ScriptNode child = this.getZestTreeModel().addBeforeNode(parent, childNode, newChild);
            this.updated(child);
            this.display(child, false);
            return child;
        } else {
            throw new IllegalArgumentException(
                    "Unexpected parent node: "
                            + ZestZapUtils.getElement(parent)
                            + " "
                            + parent.getNodeName());
        }
    }

    public void notifyAlert(Alert alert) {
        if (View.isInitialised()) {
            int row = this.getZestResultsPanel().getModel().getIndex(alert.getMessage());
            if (row >= 0) {
                ZestResultsTableEntry entry = this.getZestResultsPanel().getModel().getEntry(row);
                if (entry != null) {
                    entry.setMessage(alert.getName());
                    entry.setPassed(false);
                    this.getZestResultsPanel().getModel().fireTableRowsUpdated(row, row);
                }
            }
        }
    }

    public void notifyChanged(ZestResultWrapper lastResult) {
        if (View.isInitialised()) {
            try {
                int row =
                        this.getZestResultsPanel().getModel().getIndex(lastResult.getHttpMessage());
                if (row >= 0) {
                    this.getZestResultsPanel().getModel().fireTableRowsUpdated(row, row);
                }
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    public void delete(ScriptNode node) {
        ScriptNode parent = node.getParent();
        this.getZestTreeModel().delete(node);
        this.updated(parent);
        this.display(parent, true);
    }

    public void moveNodeUp(ScriptNode node) {
        ScriptNode prev = (ScriptNode) node.getPreviousSibling();
        while (prev != null && ZestZapUtils.getShadowLevel(prev) > 0) {
            prev = (ScriptNode) prev.getPreviousSibling();
        }
        if (prev == null) {
            return;
        }
        if (ZestZapUtils.getElement(node) instanceof ZestScript) {
            // Ignore
        } else if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
            ZestStatement req = (ZestStatement) ZestZapUtils.getElement(node);
            ZestContainer parent = (ZestContainer) ZestZapUtils.getElement(node.getParent());
            int index = parent.getIndex(req);
            parent.move(index - 1, req);
            this.getZestTreeModel().switchNodes(prev, node);
            if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
                this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
            }
            this.updated(node);
            this.display(node, false);
        } else if (ZestZapUtils.getElement(node.getParent()) instanceof ZestRequest) {
            ZestRequest parent = (ZestRequest) ZestZapUtils.getElement(node.getParent());
            parent.moveUp(ZestZapUtils.getElement(node));
            this.getZestTreeModel().switchNodes(prev, node);
            if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
                this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
            }
            this.updated(node);
            this.display(node, false);
        }
    }

    public void moveNodeDown(ScriptNode node) {
        ScriptNode next = (ScriptNode) node.getNextSibling();
        while (next != null && ZestZapUtils.getShadowLevel(next) > 0) {
            next = (ScriptNode) next.getNextSibling();
        }
        if (next == null) {
            logger.error("Cant move node down " + node.getNodeName());
            return;
        }
        if (ZestZapUtils.getElement(node) instanceof ZestScript) {
            // Ignore
        } else if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
            ZestStatement req = (ZestStatement) ZestZapUtils.getElement(node);
            ZestContainer parent = (ZestContainer) ZestZapUtils.getElement(node.getParent());
            int index = parent.getIndex(req);
            parent.move(index + 1, req);
            this.getZestTreeModel().switchNodes(node, next);
            if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
                this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
            }
            this.updated(node);
            this.display(node, false);

        } else if (ZestZapUtils.getElement(node.getParent()) instanceof ZestRequest) {
            ZestRequest parent = (ZestRequest) ZestZapUtils.getElement(node.getParent());
            parent.moveUp(ZestZapUtils.getElement(node));
            this.getZestTreeModel().switchNodes(node, next);
            if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
                this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
            }
            this.updated(node);
            this.display(node, false);
        }
    }

    public boolean isSelectedZestOriginalRequestMessage(Message message) {
        if (message == null) {
            return false;
        }
        return View.getSingleton().getRequestPanel().getMessage() != null
                && View.getSingleton().getRequestPanel().getMessage().hashCode()
                        == message.hashCode()
                && this.isSelectedMessage(message);
    }

    public boolean isSelectedZestOriginalResponseMessage(Message message) {
        if (message == null) {
            return false;
        }
        return View.getSingleton().getResponsePanel().getMessage() != null
                && View.getSingleton().getResponsePanel().getMessage().hashCode()
                        == message.hashCode()
                && this.isSelectedMessage(message);
    }

    public ScriptNode getSelectedZestNode() {
        if (this.getExtScript().getScriptUI() == null) {
            return null;
        }
        if (ZestZapUtils.isZestNode(this.getExtScript().getScriptUI().getSelectedNode())) {
            return this.getExtScript().getScriptUI().getSelectedNode();
        }
        return null;
    }

    public ZestElement getSelectedZestElement() {
        if (this.getExtScript().getScriptUI() == null) {
            return null;
        }
        return ZestZapUtils.getElement(this.getExtScript().getScriptUI().getSelectedNode());
    }

    public List<ZestElement> getSelectedZestElements() {
        if (this.getExtScript().getScriptUI() == null) {
            return null;
        }
        List<ScriptNode> nodes = this.getExtScript().getScriptUI().getSelectedNodes();
        LinkedList<ZestElement> elems = new LinkedList<>();
        for (ScriptNode node : nodes) {
            elems.add(ZestZapUtils.getElement(node));
        }
        return Collections.unmodifiableList(elems);
    }

    public boolean isSelectedZestRequestMessage(Message message) {
        if (message == null) {
            return false;
        }
        return View.getSingleton().getRequestPanel().getMessage() != null
                && View.getSingleton().getRequestPanel().getMessage().hashCode()
                        == message.hashCode()
                && this.getZestResultsPanel().isSelectedMessage(message);
    }

    public boolean isSelectedZestResponseMessage(Message message) {
        if (message == null) {
            return false;
        }
        return View.getSingleton().getResponsePanel().getMessage() != null
                && View.getSingleton().getResponsePanel().getMessage().hashCode()
                        == message.hashCode()
                && this.getZestResultsPanel().isSelectedMessage(message);
    }

    public boolean isScriptTree(Component component) {
        return this.getExtScript().getScriptUI() != null
                && component != null
                && this.getExtScript().getScriptUI().getTreeName().equals(component.getName());
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        return true;
    }

    private ScriptNode getDefaultStandAloneScript() {
        ScriptNode node = this.getSelectedZestNode();
        if (node != null) {
            // Theres a selected Zest node, is it a standalone one?
            ZestScriptWrapper script = this.getZestTreeModel().getScriptWrapper(node);
            if (script != null && ExtensionScript.TYPE_STANDALONE.equals(script.getTypeName())) {
                // right type, use if or the script if its not a container
                if (ZestZapUtils.getElement(node) instanceof ZestContainer) {
                    return node;
                } else {
                    return this.getZestTreeModel().getScriptWrapperNode(node);
                }
            }
        }
        // Is there already a default standalone Zest script
        for (ScriptNode zn : this.getZestScriptNodes(ExtensionScript.TYPE_STANDALONE)) {
            if (this.zestTreeModel
                    .getScriptWrapper(zn)
                    .getName()
                    .equals(Constant.messages.getString("zest.targeted.script.default"))) {
                return zn;
            }
        }
        // No, create one
        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(Constant.messages.getString("zest.targeted.script.default"));
        sw.setEngine(this.getZestEngineWrapper());
        sw.setEngineName(ZestScriptEngineFactory.NAME);
        sw.setType(this.getExtScript().getScriptType(ExtensionScript.TYPE_STANDALONE));
        ZestScriptWrapper script = new ZestScriptWrapper(sw);
        return this.add(script, false);
    }

    @Override
    public boolean onHttpResponseReceive(final HttpMessage msg) {
        String secProxyHeader = msg.getRequestHeader().getHeader(HTTP_HEADER_X_SECURITY_PROXY);
        if (secProxyHeader != null) {
            String[] vals = secProxyHeader.split(",");
            for (String val : vals) {
                if (VALUE_RECORD.equalsIgnoreCase(val.trim())) {
                    // TODO check script prefix??

                    EventQueue.invokeLater(
                            new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        addToParent(getRecordingNode(), msg, null);
                                    } catch (Exception e) {
                                        logger.error(e.getMessage(), e);
                                    }
                                }
                            });

                    break;
                }
            }
        }
        for (final ScriptNode node :
                getZestScriptNodesWithCapability(ScriptType.CAPABILITY_APPEND)) {
            ZestScriptWrapper zsw = (ZestScriptWrapper) node.getUserObject();
            if (zsw.isRecording()) {
                if (msg.getRequestHeader()
                        .getURI()
                        .toString()
                        .startsWith(zsw.getZestScript().getPrefix())) {
                    EventQueue.invokeLater(
                            new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        addToParent(node, msg, null);
                                    } catch (Exception e) {
                                        logger.error(e.getMessage(), e);
                                    }
                                }
                            });
                }
            }
        }

        return true;
    }

    public void setCnpNodes(List<ScriptNode> cnpNodes) {
        this.cnpNodes = cnpNodes;
    }

    public void setCut(boolean cut) {
        this.cutNodes = cut;
    }

    private void pasteExpressionsToNode(ScriptNode parent) {
        for (int i = 0; i < cnpNodes.size(); i++) {
            this.addToParent(parent, (ZestExpression) ZestZapUtils.getElement(cnpNodes.get(i)));
            if (cutNodes) {
                this.delete(cnpNodes.get(i));
            }
        }
    }

    public void pasteToNode(ScriptNode parent) {
        this.pasteToNode(parent, null);
    }

    public void pasteToNode(ScriptNode parent, ScriptNode afterChild) {
        this.pasteToNode(parent, this.cnpNodes, this.cutNodes, null, afterChild);
    }

    public void pasteToNode(
            ScriptNode parent,
            List<ScriptNode> cnpNodes,
            boolean cutNodes,
            ScriptNode beforeChild,
            ScriptNode afterChild) {
        if (cnpNodes != null && cnpNodes.size() > 0) {
            logger.debug(
                    "pasteToNode parent="
                            + parent.getNodeName()
                            + " num children="
                            + cnpNodes.size()
                            + " cut="
                            + cutNodes
                            + " before="
                            + beforeChild
                            + " after = "
                            + afterChild);
            if (ZestZapUtils.getElement(cnpNodes.get(0)) instanceof ZestExpression) {
                pasteExpressionsToNode(parent);
            } else {
                ZestScriptWrapper script = this.getZestTreeModel().getScriptWrapper(parent);
                ScriptNode lastNode = null;
                for (int i = 0; i < cnpNodes.size(); i++) {
                    ZestStatement stmt =
                            ((ZestStatement) ZestZapUtils.getElement(cnpNodes.get(i))).deepCopy();
                    if (cutNodes) {
                        this.delete(cnpNodes.get(i));
                    }
                    if (ZestZapUtils.getShadowLevel(cnpNodes.get(i)) == 0
                            && (stmt.isPassive()
                                    || !ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE.equals(
                                            script.getTypeName()))) {
                        // Dont paste non passive statements into a passive script
                        if (afterChild != null) {
                            lastNode =
                                    this.addAfterRequest(
                                            parent,
                                            afterChild,
                                            (ZestStatement) ZestZapUtils.getElement(afterChild),
                                            stmt);
                            // Dont want to reverse the order
                            afterChild = lastNode;
                        } else if (beforeChild != null) {
                            lastNode =
                                    this.addBeforeRequest(
                                            parent,
                                            beforeChild,
                                            (ZestStatement) ZestZapUtils.getElement(beforeChild),
                                            stmt);
                            // Deliberately using afterChild here so that subsequent nodes are added
                            // after this one
                            afterChild = lastNode;
                        } else {
                            lastNode = this.addToParent(parent, stmt);
                        }
                    }
                }
                refreshNode(parent); // refreshes the subtree starting from the parent
                // Display the last node, otherwise the parent will be displayed
                // if we've done a delete
                this.display(lastNode, false);
            }
        }
    }

    public void refreshNode(ScriptNode node) {
        if (node.isLeaf()) {
            return;
        } else {
            for (int i = 0; i < node.getChildCount(); i++) {
                this.getZestTreeModel().update((ScriptNode) node.getChildAt(i));
                refreshNode((ScriptNode) node.getChildAt(i));
            }
        }
    }

    private boolean canPasteIntoPassiveElement(ScriptNode node) {
        if (!(ZestZapUtils.getElement(node) instanceof ZestConditional)
                && !(ZestZapUtils.getElement(node) instanceof ZestActionFail)) {
            return false;
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            if (!canPasteIntoPassiveElement((ScriptNode) node.getChildAt(i))) {
                return false;
            }
        }
        if (node.getNextSibling() != null
                && ZestZapUtils.getShadowLevel((ScriptNode) node.getNextSibling()) > 0) {
            // The next nodes are shadow ones, e.g. a then or an else node - need
            // to check
            // these too
            while (ZestZapUtils.getShadowLevel((ScriptNode) node.getNextSibling()) > 0) {
                if (!canPasteIntoPassiveElement(((ScriptNode) node.getNextSibling()))) {
                    return false;
                }
                node = (ScriptNode) node.getNextSibling();
            }
        }
        return true;
    }

    public boolean canPasteNodesTo(ScriptNode node) {
        if (this.cnpNodes == null) {
            return false;
        }
        boolean isPassive = false;

        ZestScriptWrapper script = this.getZestTreeModel().getScriptWrapper(node);

        if (ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE.equals(script.getType().getName())) {
            isPassive = true;
        }

        for (ScriptNode cnpNode : this.cnpNodes) {
            if (cnpNode.isNodeDescendant(node)) {
                // Cant paste into a descendant of one of the cut/copied nodes
                return false;
            }
            if (isPassive && !this.canPasteIntoPassiveElement(cnpNode)) {
                return false;
            }
        }
        return true;
    }

    protected void refreshMessage() {
        ZestElement ze = this.getSelectedZestElement();
        if (ze != null && ze instanceof ZestRequest) {
            displayMessage((ZestRequest) ze);
        } else {
            clearMessage();
        }
    }

    public void displayMessage(ZestRequest ze) {
        if (!View.isInitialised()) {
            return;
        }
        try {
            lastSelectedMessage = ZestZapUtils.toHttpMessage(ze, ze.getResponse());
            if (lastSelectedMessage == null) {
                return;
            }

            View.getSingleton().displayMessage(lastSelectedMessage);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private void clearMessage() {
        if (!View.isInitialised()) {
            return;
        }
        lastSelectedMessage = null;
        View.getSingleton().displayMessage(lastSelectedMessage);
    }

    public List<ScriptNode> getSelectedZestNodes() {
        List<ScriptNode> list = new ArrayList<ScriptNode>();
        if (this.getExtScript().getScriptUI() == null) {
            return list;
        }
        for (ScriptNode node : this.getExtScript().getScriptUI().getSelectedNodes()) {
            if (ZestZapUtils.isZestNode(node)) {
                list.add(node);
            }
        }
        return Collections.unmodifiableList(list);
    }

    public void addResultToList(ZestResultWrapper href) {
        this.getZestResultsPanel().getModel().add(href);
        this.getZestResultsPanel().setTabFocus();
    }

    public void failLastResult(Exception e) {
        int lastRow = this.getZestResultsPanel().getModel().getRowCount() - 1;
        ZestResultWrapper zrw = this.getZestResultsPanel().getModel().getHistoryReference(lastRow);
        zrw.setPassed(false);
        // TODO use toUiFailureString varient?
        // zrw.setMessage(ZestZapUtils.toUiFailureString(za, response));
        zrw.setMessage(e.getMessage());
        this.getZestResultsPanel().getModel().fireTableRowsUpdated(lastRow, lastRow);
    }

    public boolean isSelectedMessage(Message msg) {
        return lastSelectedMessage != null && lastSelectedMessage.equals(msg);
    }

    public void addMouseListener(MouseAdapter adapter) {}

    private void addWindowLaunch(ScriptNode node, String handle, String url) {
        ZestScriptWrapper sw = this.getZestTreeModel().getScriptWrapper(node);
        if (!sw.getZestScript().getClientWindowHandles().contains(handle)) {
            final ZestClientLaunch launch = new ZestClientLaunch(handle, "firefox", url);

            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                addToParent(getRecordingNode(), launch);
                            } catch (Exception e) {
                                logger.error(e.getMessage(), e);
                            }
                        }
                    });
        }
    }

    private void addWindowHandle(ScriptNode node, String handle, String url) {
        ZestScriptWrapper sw = this.getZestTreeModel().getScriptWrapper(node);
        if (!sw.getZestScript().getClientWindowHandles().contains(handle)) {
            final ZestClientWindowHandle winHandle = new ZestClientWindowHandle(handle, url, false);

            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                addToParent(getRecordingNode(), winHandle);
                            } catch (Exception e) {
                                logger.error(e.getMessage(), e);
                            }
                        }
                    });
        }
    }

    private String getWindowHandle(
            JSONObject clientMessage, ScriptNode node, String windowId, String url) {
        String windowHandle = this.clientUrlToWindowHandle.get(url);
        if (windowHandle != null) {
            return windowHandle;
        }
        windowHandle = "WIN-" + recordingWinId++;
        if (startRecordingUrl != null && startRecordingUrl.equals(url)) {
            this.addWindowLaunch(node, windowHandle, url);
            startRecordingUrl = null;
        } else {
            this.addWindowHandle(node, windowHandle, url);
        }
        this.clientUrlToWindowHandle.put(url, windowHandle);
        return windowHandle;
    }

    public void startClientRecording(String uri) {
        clientUrlToWindowHandle.clear();
        startRecordingUrl = uri;
        recordingWinId = 0;
        // And turn off the recording button, at least for now
        this.getRecordButton().setSelected(false);
    }

    public void setRecordingNode(ScriptNode node) {
        recordingNode = node;
    }

    private ScriptNode getRecordingNode() {
        if (recordingNode != null) {
            return recordingNode;
        }
        return this.getDefaultStandAloneScript();
    }

    public void clientMessageReceived(JSONObject clientMessage, String windowId, String url) {
        ZestStatement stmt = null;
        String windowHandle;
        final ScriptNode clientRecordingNode = getRecordingNode();

        if (clientMessage.getString("type").equals("heartbeat")) {
            // If this is a new window, get a handle to it
            this.getWindowHandle(clientMessage, getRecordingNode(), windowId, url);
            return;
        }

        if (!clientMessage.containsKey("data")) {
            return;
        }

        try {
            String data = clientMessage.getString("data");
            windowHandle = this.getWindowHandle(clientMessage, clientRecordingNode, windowId, url);

            if ("a click event happened!".equals(data)) {
                ZestClientElementClick clientStmt = new ZestClientElementClick();
                clientStmt.setWindowHandle(windowHandle);
                clientStmt.setType("xpath");
                clientStmt.setElement(clientMessage.getString("originalTargetPath"));
                stmt = clientStmt;
            } else if ("a keypress event happened!".equals(data)) {
                String element = clientMessage.getString("originalTargetPath");
                String eventDataStr = clientMessage.getString("eventData");
                JSONObject eventDataObj = JSONObject.fromObject(eventDataStr);
                String key = eventDataObj.getString("key");
                boolean appended = false;

                if (key.length() > 1) {
                    // Ignore all 'control' keys, at least initially
                    logger.debug("Client recording, ignoring " + key);
                } else {
                    if (getRecordingNode().getChildCount() > 0) {
                        // We get key presses one at a time - try to combine them up where possible
                        ScriptNode lastChild = (ScriptNode) clientRecordingNode.getLastChild();
                        ZestElement lastElement = ZestZapUtils.getElement(lastChild);
                        if (lastElement != null
                                && lastElement instanceof ZestClientElementSendKeys) {
                            ZestClientElementSendKeys sk = (ZestClientElementSendKeys) lastElement;
                            if (sk.getWindowHandle().equals(windowHandle)
                                    && sk.getType().equals("xpath")
                                    && sk.getElement().equals(element)) {
                                sk.setValue(sk.getValue() + key);
                                getZestTreeModel().nodeChanged(lastChild);
                                this.refreshNode(clientRecordingNode);
                                appended = true;
                            }
                        }
                    }

                    if (!appended) {
                        ZestClientElementSendKeys sk = new ZestClientElementSendKeys();
                        sk.setWindowHandle(windowHandle);
                        sk.setType("xpath");
                        sk.setElement(clientMessage.getString("originalTargetPath"));
                        sk.setValue(key);
                        stmt = sk;
                    }
                }
            }
        } catch (Exception e1) {
            logger.error(e1.getMessage(), e1);
        }

        if (stmt != null) {
            final ZestStatement stmtFinal = stmt;

            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                addToParent(clientRecordingNode, stmtFinal, false);
                            } catch (Exception e) {
                                logger.error(e.getMessage(), e);
                            }
                        }
                    });
        }
    }
    /**/
    @Override
    public void preInvoke(ScriptWrapper script) {
        ScriptEngineWrapper ewrap =
                this.getExtScript().getEngineWrapper(ZestScriptEngineFactory.NAME);
        if (ewrap == null) {
            logger.error("Failed to find engine Mozilla Zest");
        } else if (script instanceof ZestScriptWrapper) {
            this.getZestScriptEngineFactory()
                    .setRunner(new ZestZapRunner(this, (ZestScriptWrapper) script));
            clearResults();
            this.lastRunScript = ((ZestScriptWrapper) script).getZestScript();
        }
    }

    public void clearResults() {
        if (View.isInitialised()) {
            // Clear the previous results
            this.getZestResultsPanel().getModel().clear();
        }
    }

    @Override
    public void refreshScript(ScriptWrapper script) {
        // Ignore
    }

    @Override
    public void scriptAdded(ScriptWrapper script, boolean display) {
        if (script.getEngineName().equals(ZestScriptEngineFactory.NAME)) {

            ScriptNode typeNode =
                    this.getExtScript().getTreeModel().getTypeNode(script.getTypeName());
            if (typeNode == null) {
                logger.error("Failed to find type node: " + script.getTypeName());

                typeNode =
                        this.getExtScript()
                                .getTreeModel()
                                .getTypeNode(ExtensionScript.TYPE_STANDALONE);
            }

            logger.debug("Adding Zest script to tree");

            ZestScriptWrapper zsw;
            if (script instanceof ZestScriptWrapper) {
                zsw = (ZestScriptWrapper) script;
            } else {
                zsw = new ZestScriptWrapper(script);
                if (zsw.getName() == null) {
                    zsw.setName(script.getName());
                }
            }

            ScriptNode parentNode = this.getExtScript().getTreeModel().getNodeForScript(script);
            parentNode.setUserObject(zsw);

            this.getZestTreeModel().addScript(parentNode, zsw);

            if (display && View.isInitialised()) {
                this.updated(parentNode);
                this.display(zsw, parentNode, true);
                this.dialogManager.showZestEditScriptDialog(parentNode, zsw, false);
            }
        }
    }

    @Override
    public void scriptRemoved(ScriptWrapper script) {
        // Ignore

    }

    @Override
    public void scriptChanged(ScriptWrapper script) {
        // Ignore
    }

    @Override
    public void scriptError(ScriptWrapper script) {
        // Ignore
    }

    @Override
    public void scriptSaved(ScriptWrapper script) {
        // Ignore
    }

    @Override
    public void templateAdded(ScriptWrapper script, boolean display) {
        /*
         * TODO ?? if (View.isInitialised() && this.getExtScript().getScriptUI()
         * != null &&
         * script.getEngineName().equals(ZestScriptEngineFactory.NAME)) {
         *
         * ScriptNode typeNode = this.getExtScript().getTreeModel()
         * .getTypeNode(script.getTypeName()); if (typeNode == null) {
         * logger.error("Failed to find type node: " + script.getTypeName());
         *
         * typeNode = this.getExtScript().getTreeModel()
         * .getTypeNode(ExtensionScript.TYPE_STANDALONE); }
         *
         * logger.debug("Adding Zest script to tree");
         *
         * ZestScriptWrapper zsw = new ZestScriptWrapper(script); if
         * (zsw.getName() == null) { zsw.setName(script.getName()); }
         *
         * ScriptNode parentNode = this.getExtScript().getTreeModel()
         * .getNodeForScript(script); parentNode.setUserObject(zsw);
         *
         * this.getZestTreeModel().addScript(parentNode, zsw); }
         */
    }

    @Override
    public void templateRemoved(ScriptWrapper script) {
        // Ignore
    }

    public ZestScript getLastRunScript() {
        return lastRunScript;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    /**
     * Set enabled for the specified node and all of its children
     *
     * @param node
     * @param enabled
     */
    public void setEnabled(ScriptNode node, boolean enabled) {
        if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
            ZestStatement stmt = (ZestStatement) ZestZapUtils.getElement(node);
            stmt.setEnabled(enabled);
            for (int i = 0; i < node.getChildCount(); i++) {
                this.setEnabled((ScriptNode) node.getChildAt(i), enabled);
            }
            this.updated(node);
        }
    }

    public ZestParam getParam() {
        if (param == null) {
            param = new ZestParam();
        }
        return param;
    }

    private OptionsZestPanel getOptionsPanel() {
        if (optionsZestPanel == null) {
            optionsZestPanel = new OptionsZestPanel(this);
        }
        return optionsZestPanel;
    }

    /**
     * Return all of the requests in the script ScriptWrapper is deliberately used to make it easier
     * to call this method by reflection
     *
     * @param script
     * @return
     */
    public List<HttpMessage> getAllRequestsInScript(ScriptWrapper script) {
        ArrayList<HttpMessage> requests = new ArrayList<HttpMessage>();

        if (!(script instanceof ZestScriptWrapper)) {
            throw new InvalidParameterException(script.getClass().getCanonicalName());
        }

        ZestScriptWrapper sw = (ZestScriptWrapper) script;
        for (ZestStatement stmt : sw.getZestScript().getStatements()) {
            try {
                if (stmt.getElementType().equals("ZestRequest")) {
                    ZestRequest req = (ZestRequest) stmt;
                    HttpMessage scrMessage = ZestZapUtils.toHttpMessage(req, req.getResponse());
                    requests.add(scrMessage);
                }
            } catch (Exception e) {
                logger.debug(
                        "Exception occurred while fetching HttpMessages from sequence script: "
                                + e.getMessage());
            }
        }
        return requests;
    }

    /** A {@code SessionChangedListener} for view/UI related functionalities. */
    private class ViewSessionChangedListener implements SessionChangedListener {

        @Override
        public void sessionAboutToChange(Session session) {
            clearResults();
        }

        @Override
        public void sessionChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do.
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do.
        }
    }
}
