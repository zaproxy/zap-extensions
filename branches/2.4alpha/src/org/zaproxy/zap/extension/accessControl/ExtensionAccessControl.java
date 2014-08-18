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
package org.zaproxy.zap.extension.accessControl;

import java.awt.Dimension;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.db.RecordContext;
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
 * application.
 */
public class ExtensionAccessControl extends ExtensionAdaptor implements SessionChangedListener,
		ContextPanelFactory, ContextDataFactory {

	public static final String CONTEXT_CONFIG_ACCESS_RULES = Context.CONTEXT_CONFIG + ".accessControl.rules";
	public static final String CONTEXT_CONFIG_ACCESS_RULES_RULE = CONTEXT_CONFIG_ACCESS_RULES + ".rule";

	private static Logger log = Logger.getLogger(ExtensionAccessControl.class);

	/** The NAME of the extension. */
	public static final String NAME = "ExtensionAccessControl";

	/** The Constant EXTENSION DEPENDENCIES. */
	private static final List<Class<?>> EXTENSION_DEPENDENCIES;
	static {
		// Prepare a list of Extensions on which this extension depends
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionUserManagement.class);
		dependencies.add(ExtensionAuthentication.class);
		dependencies.add(ExtensionAuthorization.class);
		EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}

	private AccessControlStatusPanel statusPanel;
	private AccessControlScannerThreadManager threadManager;

	/** The map of context panels. */
	private Map<Integer, ContextAccessControlPanel> contextPanelsMap;

	/** The mapping of Access Rules Managers to Contexts. */
	private Map<Integer, ContextAccessRulesManager> contextManagers;

	private AccessControlScanOptionsDialog customScanDialog;

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
		Model.getSingleton().addContextDataFactory(this);
		extensionHook.addSessionListener(this);

		if (getView() != null) {
			ExtensionHookView viewHook = extensionHook.getHookView();
			viewHook.addStatusPanel(getStatusPanel());

			getView().addContextPanelFactory(this);
		}
	}

	private AccessControlStatusPanel getStatusPanel() {
		if (statusPanel == null)
			statusPanel = new AccessControlStatusPanel(this, threadManager);
		return statusPanel;
	}

	public void showScanOptionsDialog(Context context) {
		if (customScanDialog == null) {
			customScanDialog = new AccessControlScanOptionsDialog(this, View.getSingleton().getMainFrame(),
					new Dimension(700, 500));
		}
		if (customScanDialog.isVisible()) {
			return;
		}
		customScanDialog.init(context);
		customScanDialog.setVisible(true);
	}

	public void startScan(AccessControlScanStartOptions startOptions) {
		int contextId = startOptions.targetContext.getIndex();
		AccessControlScannerThread scannerThread = threadManager.getScannerThread(contextId);
		if (scannerThread.isRunning()) {
			log.warn("Access control scan already running for context: " + contextId);
			throw new IllegalStateException("A scan is already running for context: " + contextId);
		}

		scannerThread = threadManager.recreateScannerThreadIfHasRun(contextId);
		if (getView() != null)
			scannerThread.addScanListener(getStatusPanel());
		scannerThread.setStartOptions(startOptions);
		scannerThread.start();
	}

	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("accessControl.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_EXTENSIONS_PAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	@Override
	public List<Class<?>> getDependencies() {
		return EXTENSION_DEPENDENCIES;
	}

	private class AccessControlScannerThreadManager extends
			BaseScannerThreadManager<AccessControlScannerThread> {

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
		// NOTE: if https://code.google.com/p/zaproxy/issues/detail?id=1316 is fixed, this could
		// move to the "loadContextData()" method
		if (session != null) {
			for (Context c : session.getContexts()) {
				ContextAccessRulesManager m = contextManagers.get(c.getIndex());
				if (m != null)
					m.reloadContextSiteTree(session);
			}
		}
	}

	@Override
	public void sessionAboutToChange(Session session) {
		// TODO Auto-generated method stub
		log.info("About to Change session");
	}

	@Override
	public void sessionScopeChanged(Session session) {
		// TODO Auto-generated method stub

	}

	@Override
	public void sessionModeChanged(Mode mode) {
		// TODO Auto-generated method stub

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
		ReportGenerator.addChildTextNode(doc, localizationElement, "title",
				Constant.messages.getString("accessControl.report.title"));
		ReportGenerator.addChildTextNode(doc, localizationElement, "url",
				Constant.messages.getString("accessControl.report.table.header.url"));
		ReportGenerator.addChildTextNode(doc, localizationElement, "method",
				Constant.messages.getString("accessControl.report.table.header.method"));
		ReportGenerator.addChildTextNode(doc, localizationElement, "authorization",
				Constant.messages.getString("accessControl.report.table.header.authorization"));
		ReportGenerator.addChildTextNode(doc, localizationElement, "access-control",
				Constant.messages.getString("accessControl.report.table.header.accessControl"));
		final String UNAUTHENICATED_USER_NAME = Constant.messages
				.getString("accessControl.scanOptions.unauthenticatedUser");
		final String AUTHORIZED_STRING = Constant.messages
				.getString("accessControl.report.table.field.authorized");
		final String UNAUTHORIZED_STRING = Constant.messages
				.getString("accessControl.report.table.field.unauthorized");

		AccessControlScannerThread scanThread = threadManager.getScannerThread(contextId);
		List<AccessControlResultEntry> scanResults = scanThread.getLastScanResults();

		// If there are no scan results (i.e. hasn't run yet, return the document as is
		if (scanResults == null) {
			return doc;
		}

		// Create a sorted list of users based on id (null/unauthenticated user first)
		ArrayList<User> users = new ArrayList<>(scanThread.getStartOptions().targetUsers);
		Collections.sort(users, new Comparator<User>() {
			@Override
			public int compare(User o1, User o2) {
				if (o1 == o2)
					return 0;
				if (o1 == null)
					return -1;
				if (o2 == null)
					return 1;
				return o1.getId() - o2.getId();
			}
		});
		Element usersElement = doc.createElement("users");
		rootElement.appendChild(usersElement);
		for (User user : users) {
			Element userElement = doc.createElement("user");
			usersElement.appendChild(userElement);
			userElement.setAttribute("name", user == null ? UNAUTHENICATED_USER_NAME : user.getName());
		}

		// Prepare a comparator that keeps scan results in order based on the user id
		Comparator<AccessControlResultEntry> comparator = new Comparator<AccessControlScannerThread.AccessControlResultEntry>() {
			@Override
			public int compare(AccessControlResultEntry o1, AccessControlResultEntry o2) {
				if (o1.getUser() == o2.getUser())
					return 0;
				if (o1.getUser() == null)
					return -1;
				if (o2.getUser() == null)
					return 1;
				return o1.getUser().getId() - o2.getUser().getId();
			}
		};
		Map<String, TreeSet<AccessControlResultEntry>> uriResults = new HashMap<>(scanResults.size());
		TreeSet<AccessControlResultEntry> uriResultsSet;
		for (AccessControlResultEntry result : scanResults) {
			uriResultsSet = uriResults.get(result.getUri());
			if (uriResultsSet == null) {
				uriResultsSet = new TreeSet<>(comparator);
				uriResults.put(result.getUri(), uriResultsSet);
			}
			uriResultsSet.add(result);
		}

		Element resultsElement = doc.createElement("results");
		rootElement.appendChild(resultsElement);
		for (TreeSet<AccessControlResultEntry> uriResultSet : uriResults.values()) {
			Element uriElement = doc.createElement("result");
			resultsElement.appendChild(uriElement);
			AccessControlResultEntry firstEntry = uriResultSet.first();
			uriElement.setAttribute("uri", firstEntry.getUri());
			uriElement.setAttribute("method", firstEntry.getMethod());
			for (AccessControlResultEntry result : uriResultSet) {
				Element userElement = doc.createElement("userResult");
				uriElement.appendChild(userElement);
				if (result.getUser() == null)
					userElement.setAttribute("name", UNAUTHENICATED_USER_NAME);
				else
					userElement.setAttribute("name", result.getUser().getName());
				userElement.setAttribute("authorization", result.isRequestAuthorized() ? AUTHORIZED_STRING
						: UNAUTHORIZED_STRING);
				userElement.setAttribute("access-control", result.getResult().toString());
			}
		}
		try {
			log.debug("Result: " + ReportGenerator.getDebugXMLString(doc));
		} catch (TransformerException e) {
			e.printStackTrace();
		}

		return doc;
	}

	public File generateAccessControlReport(int contextId, File outputFile)
			throws ParserConfigurationException {
		log.debug("Generating report for context " + contextId + " to: " + outputFile);

		// The path for the XSL file
		String xslFile = Constant.getZapInstall() + File.separator + "xml" + File.separator
				+ "reportAccessControl.xsl";

		// Generate the report
		return ReportGenerator.XMLToHtml(generateLastScanXMLReport(contextId), xslFile, outputFile);

	}

	@Override
	public AbstractContextPropertiesPanel getContextPanel(Context context) {
		ContextAccessControlPanel panel = this.contextPanelsMap.get(context.getIndex());
		if (panel == null) {
			panel = new ContextAccessControlPanel(this, context.getIndex());
			this.contextPanelsMap.put(context.getIndex(), panel);
		}
		return panel;
	}

	@Override
	public void discardContexts() {
		this.contextPanelsMap.clear();
		this.contextManagers.clear();
		this.threadManager.stopAllScannerThreads();
		this.threadManager.clearThreads();
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
			manager = new ContextAccessRulesManager(Model.getSingleton().getSession().getContext(contextId));
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
		ContextAccessRulesManager manager = contextManagers.get(context.getIndex());
		if (manager == null) {
			manager = new ContextAccessRulesManager(context);
			contextManagers.put(context.getIndex(), manager);
		}
		return manager;
	}

	@Override
	public void loadContextData(Session session, Context context) {
		// Read the serialized rules for this context
		List<String> serializedRules = null;
		try {
			serializedRules = session.getContextDataStrings(context.getIndex(),
					RecordContext.TYPE_ACCESS_CONTROL_RULE);
		} catch (Exception e) {
			log.error("Unable to load access control rules for context: " + context.getIndex(), e);
			return;
		}

		// Load the rules for this context
		if (serializedRules != null) {
			ContextAccessRulesManager contextManager = getContextAccessRulesManager(context);
			for (String serializedRule : serializedRules)
				contextManager.importSerializedRule(serializedRule);
		}
	}

	@Override
	public void persistContextData(Session session, Context context) {
		try {
			ContextAccessRulesManager contextManager = contextManagers.get(context.getIndex());
			if (contextManager != null) {
				List<String> serializedRules = contextManager.exportSerializedRules();
				// Save only if we have anything to save
				if (!serializedRules.isEmpty()) {
					session.setContextData(context.getIndex(), RecordContext.TYPE_ACCESS_CONTROL_RULE,
							serializedRules);
					return;
				}
			}

			// If we don't have any rules, force delete any previous values
			session.clearContextDataForType(context.getIndex(), RecordContext.TYPE_ACCESS_CONTROL_RULE);
		} catch (Exception e) {
			log.error("Unable to persist access rules for context: " + context.getIndex(), e);
		}
	}

	@Override
	public void exportContextData(Context ctx, Configuration config) {
		ContextAccessRulesManager contextManager = contextManagers.get(ctx.getIndex());
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
}