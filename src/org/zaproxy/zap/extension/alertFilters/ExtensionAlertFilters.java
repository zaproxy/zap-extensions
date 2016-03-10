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
package org.zaproxy.zap.extension.alertFilters;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.control.CoreFunctionality;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ContextDataFactory;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.ContextPanelFactory;

/*
 * A ZAP extension which implements Context Alert Filters, which
 * allow you to automatically override the risk levels of any alerts 
 * raised by the active and passive scan rules within a context.
 */
public class ExtensionAlertFilters extends ExtensionAdaptor implements ContextPanelFactory,
		ContextDataFactory, EventConsumer, SessionChangedListener {

	// The name is public so that other extensions can access it
	public static final String NAME = "ExtensionAlertFilters";
	
	// The i18n prefix, by default the package name
	protected static final String PREFIX = "alertFilters";

	public static final String CONTEXT_CONFIG_ALERT_FILTERS = Context.CONTEXT_CONFIG + ".alertFilters";
	public static final String CONTEXT_CONFIG_ALERT_FILTER = CONTEXT_CONFIG_ALERT_FILTERS + ".filter";
	
	private static final int TYPE_ALERT_FILTER = 500; // RecordContext.TYPE_USER

	/** The alertFilter panels, mapped to each context. */
	private Map<Integer, ContextAlertFilterPanel> alertFilterPanelsMap = new HashMap<>();

	/** The context managers, mapped to each context. */
	private Map<Integer, ContextAlertFilterManager> contextManagers = new HashMap<>();
	
	private ExtensionAlert extAlert = null;
	private AlertFilterAPI api = null;
	private int lastAlert = -1;

	private static Map<String, Integer> nameToId = new HashMap<String, Integer>();
	private static Map<Integer, String> idToName = new HashMap<Integer, String>();
	private static List<String> allRuleNames;
	private static ExtensionActiveScan extAscan;
	
    private Logger log = Logger.getLogger(this.getClass());

	/**
     * 
     */
    public ExtensionAlertFilters() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionAlertFilters(String name) {
        super(name);
 		initialize();
    }

	private static ExtensionActiveScan getExtAscan() {
		if (extAscan == null) {
			extAscan = 
					(ExtensionActiveScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.NAME);
		}
		return extAscan;
	}

	public static List<String> getAllRuleNames() {
		if (allRuleNames == null) {
			allRuleNames = new ArrayList<String>();
			PolicyManager pm = getExtAscan().getPolicyManager();
			ScanPolicy sp = pm.getDefaultScanPolicy();
			for (Plugin plugin : sp.getPluginFactory().getAllPlugin()) {
				allRuleNames.add(plugin.getName());
				nameToId.put(plugin.getName(), Integer.valueOf(plugin.getId()));
				idToName.put(Integer.valueOf(plugin.getId()), plugin.getName());
			}
	    	List<PluginPassiveScanner> listTest = new ArrayList<>(CoreFunctionality.getBuiltInPassiveScanRules());
	    	listTest.addAll(ExtensionFactory.getAddOnLoader().getPassiveScanRules());
	        for (PluginPassiveScanner scanner : listTest) {
	        	if (scanner.getName() != null) {
	        		allRuleNames.add(scanner.getName());
					nameToId.put(scanner.getName(), Integer.valueOf(scanner.getPluginId()));
					idToName.put(Integer.valueOf(scanner.getPluginId()), scanner.getName());
	        	}
	        }
			Collections.sort(allRuleNames);
		}
		return allRuleNames;
	}

	public static int getIdForRuleName(String name) {
		if (allRuleNames == null) {
			// init
			getAllRuleNames();
		}
		return nameToId.get(name);
	}

	public static String getRuleNameForId(int ruleId) {
		if (allRuleNames == null) {
			// init
			getAllRuleNames();
		}
		return idToName.get(Integer.valueOf(ruleId));
	}


	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setName(NAME);
        ZAP.getEventBus().registerConsumer(this, 
        		AlertEventPublisher.getPublisher().getPublisherName(), 
        		new String[] {AlertEventPublisher.ALERT_ADDED_EVENT});
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    extensionHook.addSessionListener(this);
	    
		// Register this as a context data factory
		Model.getSingleton().addContextDataFactory(this);

		if (getView() != null) {
			// Factory for generating Session Context alertFilters panels
			getView().addContextPanelFactory(this);
		}

		this.api = new AlertFilterAPI(this);
		API.getInstance().registerApiImplementor(api);

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

	
	/**
	 * Gets the context alert filter manager for a given context.
	 * 
	 * @param contextId the context id
	 * @return the context alert filter manager
	 */
	public ContextAlertFilterManager getContextAlertFilterManager(int contextId) {
		ContextAlertFilterManager manager = contextManagers.get(contextId);
		if (manager == null) {
			manager = new ContextAlertFilterManager(contextId);
			contextManagers.put(contextId, manager);
		}
		return manager;
	}

	@Override
	public void loadContextData(Session session, Context context) {
		try {
			List<String> encodedAlertFilters = session.getContextDataStrings(context.getIndex(),
					TYPE_ALERT_FILTER);
			ContextAlertFilterManager afManager = getContextAlertFilterManager(context.getIndex());
			for (String e : encodedAlertFilters) {
				AlertFilter af = AlertFilter.decode(context.getIndex(), e);
				afManager.addAlertFilter(af);
			}
		} catch (Exception ex) {
			log.error("Unable to load AlertFilters.", ex);
		}
	}

	@Override
	public void persistContextData(Session session, Context context) {
		try {
			List<String> encodedAlertFilters = new ArrayList<>();
			ContextAlertFilterManager afManager = getContextAlertFilterManager(context.getIndex());
			if (afManager != null) {
				for (AlertFilter af : afManager.getAlertFilters()) {
					encodedAlertFilters.add(AlertFilter.encode(af));
				}
				session.setContextData(context.getIndex(), TYPE_ALERT_FILTER, encodedAlertFilters);
			}
		} catch (Exception ex) {
			log.error("Unable to persist AlertFilters", ex);
		}
	}

	@Override
	public void exportContextData(Context ctx, Configuration config) {
		ContextAlertFilterManager m = getContextAlertFilterManager(ctx.getIndex());
		if (m != null) {
			for (AlertFilter af : m.getAlertFilters()) {
				config.addProperty(CONTEXT_CONFIG_ALERT_FILTER, 
						AlertFilter.encode(af));
			}
		}
	}

	@Override
	public void importContextData(Context ctx, Configuration config) {
		List<Object> list = config.getList(CONTEXT_CONFIG_ALERT_FILTER);
		ContextAlertFilterManager m = getContextAlertFilterManager(ctx.getIndex());
		for (Object o : list) {
			AlertFilter af = AlertFilter.decode(ctx.getIndex(), o.toString());
			m.addAlertFilter(af);
		}
	}

	@Override
	public AbstractContextPropertiesPanel getContextPanel(Context ctx) {
		return getContextPanel(ctx.getIndex());
	}

	/**
	 * Gets the context panel for a given context.
	 * 
	 * @param contextId the context id
	 * @return the context panel
	 */
	private ContextAlertFilterPanel getContextPanel(int contextId) {
		ContextAlertFilterPanel panel = this.alertFilterPanelsMap.get(contextId);
		if (panel == null) {
			panel = new ContextAlertFilterPanel(this, contextId);
			this.alertFilterPanelsMap.put(contextId, panel);
		}
		return panel;
	}

	@Override
	public void discardContexts() {
		this.contextManagers.clear();
		this.alertFilterPanelsMap.clear();
	}

	@Override
	public void discardContext(Context ctx) {
		this.contextManagers.remove(ctx.getIndex());
		this.alertFilterPanelsMap.remove(ctx.getIndex());
	}
	
	private ExtensionAlert getExtAlert() {
		if (extAlert == null) {
			extAlert = (ExtensionAlert) Control.getSingleton().getExtensionLoader().getExtension(
					ExtensionAlert.NAME);
		}
		return extAlert;
	}
	
	@Override
	public void eventReceived(Event event) {
		TableAlert tableAlert = Model.getSingleton().getDb().getTableAlert();

		String alertId = event.getParameters().get(AlertEventPublisher.ALERT_ID);
		if (alertId != null) {
			// From 2.4.3 an alertId is included with these events, which makes life much simpler!
			try {
				handleAlert(tableAlert.read(Integer.parseInt(alertId)));
			} catch (Exception e) {
				log.error("Error handling alert", e);
			}
		} else {
			// Required for pre 2.4.3 versions
			RecordAlert recordAlert;
			while (true) {
				try {
					this.lastAlert ++;
					recordAlert = tableAlert.read(this.lastAlert);
					if (recordAlert == null) {
						break;
					}
					handleAlert(recordAlert);
					
				} catch (DatabaseException e) {
					break;
				}
			}
			// The loop will always go 1 further than necessary
			this.lastAlert--;
		}
	}

	private void handleAlert(RecordAlert recordAlert) {
		String uri = recordAlert.getUri();
		log.debug("Alert: " + this.lastAlert + " URL: " + uri);
		// Loop through rules and apply as necessary..
		for (ContextAlertFilterManager mgr : this.contextManagers.values()) {
			Context context = Model.getSingleton().getSession().getContext(mgr.getContextId());
			if (context.isInContext(uri)) {
				log.debug("Is in context " + context.getIndex() + 
						" got " + mgr.getAlertFilters().size() + " filters");
				// Its in this context
				for (AlertFilter filter : mgr.getAlertFilters()) {
					if (! filter.isEnabled()) {
						// rule ids dont match
						log.debug("Filter disabled");
						continue;
					}
					if (filter.getRuleId() != recordAlert.getPluginId()) {
						// rule ids dont match
						log.debug("Filter didnt match plugin id: " + 
								filter.getRuleId() + " != " + recordAlert.getPluginId());
						continue;
					}
					if (filter.getUrl() != null && filter.getUrl().length() > 0) {
						if (filter.isRegex()) {
							Pattern p = Pattern.compile(filter.getUrl());
							if (! p.matcher(uri).matches()) {
								// URL pattern doesnt match
								log.debug("Filter didnt match URL regex: " + filter.getUrl() + " url: " + uri);
								continue;
							}
						} else if (!filter.getUrl().equals(uri)) {
							// URL doesnt match
							log.debug("Filter didnt match URL: " + filter.getUrl());
							continue;
						}
					}
					if (filter.getParameter() != null && filter.getParameter().length() > 0) {
						if (! filter.getParameter().equals(recordAlert.getParam())) {
							// Parameter doesnt match
							log.debug("Filter didnt match parameter: " + filter.getParameter() + 
									" != " + recordAlert.getParam());
							continue;
						}
					}
					Alert alert = new Alert(recordAlert);
					if (filter.getNewRisk() == -1) {
						alert.setRiskConfidence(alert.getRisk(), Alert.CONFIDENCE_FALSE_POSITIVE);
					} else {
						alert.setRiskConfidence(filter.getNewRisk(), alert.getConfidence());
					}
					try {
						log.debug("Filter matched, setting Alert with plugin id : " + recordAlert.getPluginId() + " to " + filter.getNewRisk());
						getExtAlert().updateAlert(alert);
						getExtAlert().updateAlertInTree(null, alert);
					} catch (Exception e) {
						log.error(e.getMessage(), e);
					}
					break;
				}
			}
		}

	}

	@Override
	public void sessionChanged(Session session) {
		this.lastAlert = -1;
	}

	@Override
	public void sessionAboutToChange(Session session) {
		// Ignore
	}

	@Override
	public void sessionScopeChanged(Session session) {
		// Ignore
	}

	@Override
	public void sessionModeChanged(Mode mode) {
		// Ignore
	}
}