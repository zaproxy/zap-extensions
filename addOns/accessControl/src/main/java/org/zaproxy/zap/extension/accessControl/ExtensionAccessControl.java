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
package org.zaproxy.zap.extension.accessControl;

import java.awt.Dimension;
import java.io.File;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.report.ReportGenerator;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlResultEntry;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.accessControl.view.AccessControlScanOptionsDialog;
import org.zaproxy.zap.extension.accessControl.view.AccessControlStatusPanel;
import org.zaproxy.zap.extension.accessControl.view.ContextAccessControlPanel;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.authorization.ExtensionAuthorization;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ContextDataFactory;
import org.zaproxy.zap.scan.BaseScannerThreadManager;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.ContextPanelFactory;

/**
 * An extension that adds a set of tools that allows users to test Access Control issues in web
 * applications.
 */
public class ExtensionAccessControl extends ExtensionAdaptor
        implements SessionChangedListener, ContextPanelFactory, ContextDataFactory {

    private static Logger log = Logger.getLogger(ExtensionAccessControl.class);

    public static final String CONTEXT_CONFIG_ACCESS_RULES =
            Context.CONTEXT_CONFIG + ".accessControl.rules";
    public static final String CONTEXT_CONFIG_ACCESS_RULES_RULE =
            CONTEXT_CONFIG_ACCESS_RULES + ".rule";

    /** The NAME of the access control testing extension. */
    public static final String NAME = "ExtensionAccessControl";

    /** The list of extensions this depends on. */
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        // Prepare a list of Extensions on which this extension depends
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionUserManagement.class);
        dependencies.add(ExtensionAuthentication.class);
        dependencies.add(ExtensionAuthorization.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    /** The status panel used by the extension. */
    private AccessControlStatusPanel statusPanel;

    /** The map of context panels shown in the Session Properties Dialog. */
    private Map<Integer, ContextAccessControlPanel> contextPanelsMap;

    /** The scan dialog used to specify the scan options. */
    private AccessControlScanOptionsDialog customScanDialog;

    /** The mapping of Access Rules Managers to Contexts. */
    private Map<Integer, ContextAccessRulesManager> contextManagers;

    /** The scanner threads manager. */
    private AccessControlScannerThreadManager threadManager;

    private AccessControlAPI api;

    public ExtensionAccessControl() {
        super(NAME);
        this.setOrder(601);
        this.threadManager = new AccessControlScannerThreadManager();
        this.contextPanelsMap = new HashMap<>();
        this.contextManagers = new HashMap<>();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        // Register this where needed
        extensionHook.addContextDataFactory(this);
        extensionHook.addSessionListener(this);

        this.api = new AccessControlAPI(this);
        extensionHook.addApiImplementor(this.api);

        if (getView() != null) {
            ExtensionHookView viewHook = extensionHook.getHookView();
            viewHook.addStatusPanel(getStatusPanel());
            viewHook.addContextPanelFactory(this);
        }
    }

    @Override
    public void unload() {
        super.unload();

        if (statusPanel != null) {
            statusPanel.unload();
        }

        discardContexts();

        if (customScanDialog != null) {
            customScanDialog.dispose();
            customScanDialog = null;
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public List<String> getActiveActions() {
        Collection<AccessControlScannerThread> scans = threadManager.getAllThreads();
        if (scans.isEmpty()) {
            return null;
        }

        String activeActionPrefix = Constant.messages.getString("accessControl.activeActionPrefix");
        List<String> activeActions = new ArrayList<>(scans.size());
        for (AccessControlScannerThread scan : scans) {
            if (scan.isRunning()) {
                activeActions.add(
                        MessageFormat.format(
                                activeActionPrefix,
                                scan.getStartOptions().targetContext.getName()));
            }
        }
        return activeActions;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("accessControl.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    private AccessControlStatusPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AccessControlStatusPanel(this, threadManager);
        }
        return statusPanel;
    }

    @Override
    public AbstractContextPropertiesPanel getContextPanel(Context context) {
        ContextAccessControlPanel panel = this.contextPanelsMap.get(context.getId());
        if (panel == null) {
            panel = new ContextAccessControlPanel(this, context.getId());
            this.contextPanelsMap.put(context.getId(), panel);
        }
        return panel;
    }

    /**
     * Shows the options dialog containing configuration needed for starting a scan.
     *
     * @param context the context
     */
    public void showScanOptionsDialog(Context context) {
        if (customScanDialog == null) {
            customScanDialog =
                    new AccessControlScanOptionsDialog(
                            this, View.getSingleton().getMainFrame(), new Dimension(700, 500));
        }
        if (customScanDialog.isVisible()) {
            return;
        }
        customScanDialog.init(context);
        customScanDialog.setVisible(true);
    }

    /**
     * Starts an access control testing scan.
     *
     * @param startOptions the start options
     */
    @SuppressWarnings("fallthrough")
    public void startScan(AccessControlScanStartOptions startOptions) {
        int contextId = startOptions.targetContext.getId();
        AccessControlScannerThread scannerThread = threadManager.getScannerThread(contextId);
        if (scannerThread.isRunning()) {
            log.warn("Access control scan already running for context: " + contextId);
            throw new IllegalStateException("A scan is already running for context: " + contextId);
        }

        switch (Control.getSingleton().getMode()) {
            case safe:
                throw new IllegalStateException("Access control scan is not allowed in Safe mode.");
            case protect:
                if (!startOptions.targetContext.isInScope()) {
                    throw new IllegalStateException(
                            "Access control scan is not allowed with a context out of scope when in Protected mode: "
                                    + startOptions.targetContext.getName());
                }
            case standard:
            case attack:
                // No problem
                break;
        }

        scannerThread = threadManager.recreateScannerThreadIfHasRun(contextId);
        if (getView() != null) {
            scannerThread.addScanListener(getStatusPanel());
        }
        scannerThread.setStartOptions(startOptions);
        scannerThread.start();
    }

    /**
     * The implementation for a {@link BaseScannerThreadManager} that initializes an {@link
     * AccessControlScannerThread}.
     */
    private class AccessControlScannerThreadManager
            extends BaseScannerThreadManager<AccessControlScannerThread> {

        @Override
        public AccessControlScannerThread createNewScannerThread(int contextId) {
            return new AccessControlScannerThread(contextId, ExtensionAccessControl.this);
        }
    }

    @Override
    public void sessionChanged(Session session) {
        if (getView() != null) {
            getStatusPanel().contextsChanged();
            getStatusPanel().reset();
        }
        // If the session has changed, make sure we reload any ContextTrees for the existing context
        // managers
        // NOTE: if https://github.com/zaproxy/zaproxy/issues/1316 is fixed, this could
        // move to the "loadContextData()" method
        if (session != null) {
            for (Context c : session.getContexts()) {
                ContextAccessRulesManager m = contextManagers.get(c.getId());
                if (m != null) {
                    m.reloadContextSiteTree(session);
                }
            }
        }
    }

    @Override
    public void sessionAboutToChange(Session session) {}

    @Override
    public void sessionScopeChanged(Session session) {}

    @Override
    public void sessionModeChanged(Mode mode) {
        if (Mode.safe.equals(mode)) {
            this.threadManager.stopAllScannerThreads();
        } else if (Mode.protect.equals(mode)) {
            for (AccessControlScannerThread scan : threadManager.getAllThreads()) {
                if (scan.isRunning() && !scan.getStartOptions().targetContext.isInScope()) {
                    scan.stopScan();
                }
            }
        }

        if (statusPanel != null) {
            statusPanel.sessionModeChanged(mode);
        }
    }

    private Document generateLastScanXMLReport(int contextId) throws ParserConfigurationException {
        // Prepare the document and the root element
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        Element rootElement = doc.createElement("report");
        doc.appendChild(rootElement);

        // Localization
        Element localizationElement = doc.createElement("localization");
        rootElement.appendChild(localizationElement);
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "title",
                Constant.messages.getString("accessControl.report.title"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "url",
                Constant.messages.getString("accessControl.report.table.header.url"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "method",
                Constant.messages.getString("accessControl.report.table.header.method"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "authorization",
                Constant.messages.getString("accessControl.report.table.header.authorization"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "access-control",
                Constant.messages.getString("accessControl.report.table.header.accessControl"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "show-all",
                Constant.messages.getString("accessControl.report.button.all"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "show-valid",
                Constant.messages.getString("accessControl.report.button.valid"));
        ReportGenerator.addChildTextNode(
                doc,
                localizationElement,
                "show-illegal",
                Constant.messages.getString("accessControl.report.button.illegal"));
        final String UNAUTHENICATED_USER_NAME =
                Constant.messages.getString("accessControl.scanOptions.unauthenticatedUser");
        final String AUTHORIZED_STRING =
                Constant.messages.getString("accessControl.report.table.field.authorized");
        final String UNAUTHORIZED_STRING =
                Constant.messages.getString("accessControl.report.table.field.unauthorized");

        AccessControlScannerThread scanThread = threadManager.getScannerThread(contextId);
        List<AccessControlResultEntry> scanResults = scanThread.getLastScanResults();

        // If there are no scan results (i.e. hasn't run yet, return the document as is at this
        // point
        if (scanResults == null) {
            return doc;
        }

        // Create a sorted list of users based on id (null/unauthenticated user first)
        List<User> users = new ArrayList<>(scanThread.getStartOptions().targetUsers);
        Collections.sort(
                users,
                new Comparator<User>() {
                    @Override
                    public int compare(User o1, User o2) {
                        if (o1 == o2) {
                            return 0;
                        }
                        if (o1 == null) {
                            return -1;
                        }
                        if (o2 == null) {
                            return 1;
                        }
                        return o1.getId() - o2.getId();
                    }
                });
        // ... and add the list of users in the report
        Element usersElement = doc.createElement("users");
        rootElement.appendChild(usersElement);
        for (User user : users) {
            Element userElement = doc.createElement("user");
            usersElement.appendChild(userElement);
            userElement.setAttribute(
                    "name", user == null ? UNAUTHENICATED_USER_NAME : user.getName());
            userElement.setAttribute("id", Integer.toString(user == null ? -1 : user.getId()));
        }

        // Prepare a comparator that keeps scan results in order based on the user id
        Comparator<AccessControlResultEntry> resultsComparator =
                new Comparator<AccessControlScannerThread.AccessControlResultEntry>() {
                    @Override
                    public int compare(AccessControlResultEntry o1, AccessControlResultEntry o2) {
                        if (o1.getUser() == o2.getUser()) {
                            return 0;
                        }
                        if (o1.getUser() == null) {
                            return -1;
                        }
                        if (o2.getUser() == null) {
                            return 1;
                        }
                        return o1.getUser().getId() - o2.getUser().getId();
                    }
                };
        Map<String, TreeSet<AccessControlResultEntry>> uriResults =
                new HashMap<>(scanResults.size());
        TreeSet<AccessControlResultEntry> uriResultsSet;
        for (AccessControlResultEntry result : scanResults) {
            uriResultsSet = uriResults.get(result.getUri());
            if (uriResultsSet == null) {
                uriResultsSet = new TreeSet<>(resultsComparator);
                uriResults.put(result.getUri(), uriResultsSet);
            }
            uriResultsSet.add(result);
        }

        // Actually add the results nodes
        Element resultsElement = doc.createElement("results");
        rootElement.appendChild(resultsElement);
        for (TreeSet<AccessControlResultEntry> uriResultSet : uriResults.values()) {
            // For each result node...
            Element uriElement = doc.createElement("result");
            resultsElement.appendChild(uriElement);
            // ... add the URI and the HTTP method ...
            AccessControlResultEntry firstEntry = uriResultSet.first();
            uriElement.setAttribute("uri", firstEntry.getUri());
            uriElement.setAttribute("method", firstEntry.getMethod());
            // ... and for every result entry, add the necessary data
            for (AccessControlResultEntry result : uriResultSet) {
                Element userResultElement = doc.createElement("userResult");
                uriElement.appendChild(userResultElement);
                if (result.getUser() == null) {
                    userResultElement.setAttribute("name", UNAUTHENICATED_USER_NAME);
                } else {
                    userResultElement.setAttribute("name", result.getUser().getName());
                }
                userResultElement.setAttribute(
                        "authorization",
                        result.isRequestAuthorized() ? AUTHORIZED_STRING : UNAUTHORIZED_STRING);
                userResultElement.setAttribute("access-control", result.getResult().name());
                userResultElement.setAttribute(
                        "access-control-localized", result.getResult().toString());
            }
        }

        return doc;
    }

    /**
     * Generate an access control report for the provided context id and save it in the output file.
     *
     * @param contextId the context id
     * @param outputFile the output file
     * @return the file
     */
    public File generateAccessControlReport(int contextId, File outputFile)
            throws ParserConfigurationException {
        log.debug("Generating report for context " + contextId + " to: " + outputFile);

        // The path for the XSL file
        File xslFile =
                new File(
                        Constant.getZapHome(),
                        "xml" + File.separator + "reportAccessControl.html.xsl");

        // Generate the report
        return ReportGenerator.XMLToHtml(
                generateLastScanXMLReport(contextId), xslFile.getAbsolutePath(), outputFile);
    }

    /**
     * Gets the access rules manager for a Context.
     *
     * @param contextId the context id
     * @return the user access rules manager
     */
    public ContextAccessRulesManager getContextAccessRulesManager(int contextId) {
        ContextAccessRulesManager manager = contextManagers.get(contextId);
        if (manager == null) {
            manager =
                    new ContextAccessRulesManager(
                            Model.getSingleton().getSession().getContext(contextId));
            contextManagers.put(contextId, manager);
        }
        return manager;
    }

    /**
     * Gets the access rules manager for a Context.
     *
     * @param context the context
     * @return the user access rules manager
     */
    public ContextAccessRulesManager getContextAccessRulesManager(Context context) {
        ContextAccessRulesManager manager = contextManagers.get(context.getId());
        if (manager == null) {
            manager = new ContextAccessRulesManager(context);
            contextManagers.put(context.getId(), manager);
        }
        return manager;
    }

    @Override
    public void discardContexts() {
        for (ContextAccessControlPanel panel : contextPanelsMap.values()) {
            panel.unload();
        }
        this.contextPanelsMap.clear();
        this.contextManagers.clear();
        this.threadManager.stopAllScannerThreads();
        this.threadManager.clearThreads();
    }

    @Override
    public void discardContext(Context ctx) {
        ContextAccessControlPanel panel = this.contextPanelsMap.remove(ctx.getId());
        if (panel != null) {
            panel.unload();
        }
        this.contextManagers.remove(ctx.getId());
    }

    @Override
    public void loadContextData(Session session, Context context) {
        // Read the serialized rules for this context
        List<String> serializedRules = null;
        try {
            serializedRules =
                    session.getContextDataStrings(
                            context.getId(), RecordContext.TYPE_ACCESS_CONTROL_RULE);
        } catch (Exception e) {
            log.error("Unable to load access control rules for context: " + context.getId(), e);
            return;
        }

        // Load the rules for this context
        if (serializedRules != null) {
            ContextAccessRulesManager contextManager = getContextAccessRulesManager(context);
            for (String serializedRule : serializedRules) {
                contextManager.importSerializedRule(serializedRule);
            }
        }
    }

    @Override
    public void persistContextData(Session session, Context context) {
        try {
            ContextAccessRulesManager contextManager = contextManagers.get(context.getId());
            if (contextManager != null) {
                List<String> serializedRules = contextManager.exportSerializedRules();
                // Save only if we have anything to save
                if (!serializedRules.isEmpty()) {
                    session.setContextData(
                            context.getId(),
                            RecordContext.TYPE_ACCESS_CONTROL_RULE,
                            serializedRules);
                    return;
                }
            }

            // If we don't have any rules, force delete any previous values
            session.clearContextDataForType(
                    context.getId(), RecordContext.TYPE_ACCESS_CONTROL_RULE);
        } catch (Exception e) {
            log.error("Unable to persist access rules for context: " + context.getId(), e);
        }
    }

    @Override
    public void exportContextData(Context ctx, Configuration config) {
        ContextAccessRulesManager contextManager = contextManagers.get(ctx.getId());
        if (contextManager != null) {
            List<String> serializedRules = contextManager.exportSerializedRules();
            config.setProperty(CONTEXT_CONFIG_ACCESS_RULES_RULE, serializedRules);
        }
    }

    @Override
    public void importContextData(Context ctx, Configuration config) throws ConfigurationException {
        List<Object> serializedRules = config.getList(CONTEXT_CONFIG_ACCESS_RULES_RULE);
        if (serializedRules != null) {
            ContextAccessRulesManager contextManager = getContextAccessRulesManager(ctx);
            // Make sure we reload the context tree
            contextManager.reloadContextSiteTree(Model.getSingleton().getSession());
            for (Object serializedRule : serializedRules) {
                contextManager.importSerializedRule(serializedRule.toString());
            }
        }
    }

    protected int getScanProgress(int contextId) {

        AccessControlScannerThread scannerThread = threadManager.getScannerThread(contextId);

        if (scannerThread.isRunning() || scannerThread.hasRun()) {
            double progress =
                    scannerThread.getScanProgress()
                            * 1.0
                            / scannerThread.getScanMaximumProgress()
                            * 100;
            return (int) Math.round(progress);
        } else {
            throw new IllegalStateException("A scan is not running for context: " + contextId);
        }
    }

    protected String getScanStatus(int contextId) {

        AccessControlScannerThread scannerThread = threadManager.getScannerThread(contextId);
        String result = null;

        if (scannerThread.isRunning()) {
            result = "RUNNING";
        } else if (scannerThread.isPaused()) {
            result = "PAUSED";
        } else if (scannerThread.isInterrupted()) {
            result = "INTERRUPTED";
        } else {
            result = "NOT RUNNING";
        }

        return result;
    }
}
