/*
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP development team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.EventQueue;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.ImageIcon;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.view.SiteMapListener;
import org.zaproxy.zap.view.SiteMapTreeCellRenderer;

public class ExtensionWappalyzer extends ExtensionAdaptor implements SessionChangedListener, SiteMapListener {

	public static final String NAME = "ExtensionWappalyzer";
	
	private static final String RESOURCE = "/org/zaproxy/zap/extension/wappalyzer/resources";
	
	public static final ImageIcon WAPPALYZER_ICON = new ImageIcon(
			ExtensionWappalyzer.class.getResource( RESOURCE + "/wappalyzer.png"));
	
	private static final String FIELD_CONFIDENCE = "confidence:";
	private static final String FIELD_VERSION = "version:";

	private TechPanel techPanel = null;
	private PopupMenuEvidence popupMenuEvidence = null;
	
	private Map<String, String> categories = new HashMap<String, String>(); 
	private List<Application> applications = new ArrayList<Application>();
	
	private ExtensionSearch extSearch = null;

	private Map <String, TechTableModel> siteTechMap = new HashMap <String, TechTableModel>();

	private static final Logger logger = Logger.getLogger(ExtensionWappalyzer.class);

	/**
	 * The dependencies of the extension.
	 */
	private static final List<Class<?>> EXTENSION_DEPENDENCIES;

	static {
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionPassiveScan.class);
		EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}

	private WappalyzerPassiveScanner passiveScanner;

	/**
	 * TODO
	 * Implementaion
	 * 		Version handling
	 * 		Confidence handling
	 * 		Add API calls - need to test for daemon mode (esp revisits)
	 * Issues
	 * 		Handle load session - store tech in db?
	 * 		Sites pull down not populated if no tech found - is this actually a problem?
	 * 		One pattern still fails to compile
	 */
	
	public ExtensionWappalyzer() {
		super(NAME);
		this.setOrder(201);
		
		try {
			parseJson(getStringResource(RESOURCE + "/apps.json"));
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		}
	}
	
	@SuppressWarnings("unchecked")
	public void parseJson(String jsonStr) {
		
		try {
			JSONObject json = JSONObject.fromObject(jsonStr);
			
			JSONObject cats = json.getJSONObject("categories");
			
			for (Object cat : cats.entrySet()) {
				Map.Entry<String, String> mCat = (Map.Entry<String, String>) cat;
				this.categories.put(mCat.getKey(), mCat.getValue());
			}
			
			JSONObject apps = json.getJSONObject("apps");
			for (Object entry : apps.entrySet()) {
				Map.Entry<String, JSONObject> mApp = (Map.Entry<String, JSONObject>) entry;
				
				String appName = mApp.getKey();
				JSONObject appData = mApp.getValue();
				
				Application app = new Application();
				app.setName(appName);
				app.setWebsite(appData.getString("website"));
				app.setCategories(this.jsonToCategoryList(appData.get("cats")));
				app.setHeaders(this.jsonToAppPatternMapList(appData.get("headers")));
				app.setUrl(this.jsonToPatternList(appData.get("url")));
				app.setHtml(this.jsonToPatternList(appData.get("html")));
				app.setScript(this.jsonToPatternList(appData.get("script")));
				app.setMetas(this.jsonToAppPatternMapList(appData.get("meta")));
				app.setImplies(this.jsonToStringList(appData.get("implies")));
				
				URL icon = ExtensionWappalyzer.class.getResource( RESOURCE + "/icons/" + appName + ".png");
				if (icon != null) {
					app.setIcon(new ImageIcon(icon));
				}
				
				this.applications.add(app);
			}
			
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
		
	}
	
	private List<String> jsonToStringList(Object json) {
		List<String> list = new ArrayList<String>();
		if (json instanceof JSONArray) {
			for (Object obj : (JSONArray)json) {
				list.add(obj.toString());
			}
		} else if (json != null) {
			list.add(json.toString());
		}
		return list;
	}
	
	private List<String> jsonToCategoryList(Object json) {
		List<String> list = new ArrayList<String>();
		if (json instanceof JSONArray) {
			for (Object obj : (JSONArray)json) {
				String category = this.categories.get(obj.toString());
				if (category != null) {
					list.add(category);
				} else {
					logger.error("Failed to find category for " + obj.toString());
				}
			}
		}
		return list;
	}

	@SuppressWarnings("unchecked")
	private List<Map<String, AppPattern>> jsonToAppPatternMapList(Object json) {
		List<Map<String, AppPattern>> list = new ArrayList<Map<String, AppPattern>>();
		AppPattern ap;
		if (json instanceof JSONObject) {
			for (Object obj : ((JSONObject)json).entrySet()) {
				Map.Entry<String, String> entry = (Map.Entry<String, String>) obj;
				try {
					Map<String, AppPattern> map = new HashMap<String, AppPattern>();
					ap = this.strToAppPAttern(entry.getValue());
					map.put(entry.getKey(), ap);
					list.add(map);
				} catch (NumberFormatException e) {
					logger.error("Invalid field syntax " + entry.getKey() + " : " + entry.getValue(), e);
				} catch (PatternSyntaxException e) {
					logger.error("Invalid pattern syntax " + entry.getValue(), e);
				}
			}
		} else if (json != null) {
			logger.error("Unexpected header type for " + json.toString() + " " + json.getClass().getCanonicalName());
		}
		return list;
	}

	private List<AppPattern> jsonToPatternList(Object json) {
		List<AppPattern> list = new ArrayList<AppPattern>();
		if (json instanceof JSONArray) {
			for (Object obj : ((JSONArray)json).toArray()) {
				String objStr = obj.toString();
				if (obj instanceof JSONArray) {
					// Dereference it again
					objStr = ((JSONArray)obj).getString(0);
				}
				try {
					list.add(this.strToAppPAttern(objStr));
				} catch (PatternSyntaxException e) {
					logger.error("Invalid pattern syntax " + objStr, e);
				}
			}
		} else if (json != null) {
			try {
				list.add(this.strToAppPAttern(json.toString()));
			} catch (PatternSyntaxException e) {
				logger.error("Invalid pattern syntax " + json.toString(), e);
			}
		}
		return list;
	}
	
	private AppPattern strToAppPAttern(String str) {
		AppPattern ap = new AppPattern();
		String[] values = str.split("\\\\;");
		String pattern = values[0];
		for (int i=1; i < values.length; i++) {
			try {
				if (values[i].startsWith(FIELD_CONFIDENCE)) {
					ap.setConfidence(Integer.parseInt(values[i].substring(FIELD_CONFIDENCE.length())));
				} else if (values[i].startsWith(FIELD_VERSION)) {
					ap.setVersion(values[i].substring(FIELD_VERSION.length()));
				} else {
					logger.error("Unexpected field: " + values[i]);
				}
			} catch (Exception e) {
				logger.error("Invalid field syntax " + values[i], e);
			}
		}
		if (pattern.indexOf(FIELD_CONFIDENCE) > 0) {
			logger.warn("Confidence field in pattern?: " + pattern);
		}
		if (pattern.indexOf(FIELD_VERSION) > 0) {
			logger.warn("Version field in pattern?: " + pattern);
		}
		ap.setPattern(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
		return ap;
	}

	@Override
	public void init() {
		super.init();

		passiveScanner = new WappalyzerPassiveScanner();
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

	    extensionHook.addSessionListener(this);
        extensionHook.addSiteMapListener(this);
	    
	    if (getView() != null) {
	        @SuppressWarnings("unused")
			ExtensionHookView pv = extensionHook.getHookView();
	        extensionHook.getHookView().addStatusPanel(getTechPanel());
	        extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuEvidence());
	    }

		ExtensionPassiveScan extPScan = Control.getSingleton().getExtensionLoader().getExtension(ExtensionPassiveScan.class);
		extPScan.addPassiveScanner(passiveScanner);

	}

	private TechPanel getTechPanel() {
		if (techPanel == null) {
			techPanel = new TechPanel(this);
		}
		return techPanel;
	}

	private PopupMenuEvidence getPopupMenuEvidence () {
		if (popupMenuEvidence == null) {
			popupMenuEvidence = new PopupMenuEvidence(this);
		}
		return popupMenuEvidence;
	}

	
	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void unload() {
		super.unload();

		ExtensionPassiveScan extPScan = Control.getSingleton().getExtensionLoader().getExtension(ExtensionPassiveScan.class);
		extPScan.removePassiveScanner(passiveScanner);
	}

	@Override
	public List<Class<?>> getDependencies() {
		return EXTENSION_DEPENDENCIES;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("wappalyzer.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	private static String getStringResource(String resourceName) throws IOException {
		InputStream in = null;
		StringBuilder sb = new StringBuilder();
		try {
			in = ExtensionWappalyzer.class.getResourceAsStream(resourceName);
			int numRead=0;
            byte[] buf = new byte[1024];
            while((numRead = in.read(buf)) != -1){
            	sb.append(new String(buf, 0, numRead));
            }
            return sb.toString();
			
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					// Ignore
				}
			}
		}
	}
	
	public List<Application> getApplications() {
		return this.applications;
	}
	
	public TechTableModel getTechModelForSite(String site) {
		TechTableModel model = this.siteTechMap.get(site);
		if (model == null) {
			model = new TechTableModel();
			this.siteTechMap.put(site, model);
			if (getView() != null) {
				// Add to site pulldown
				this.getTechPanel().addSite(site);
			}
		}
		return model;
	}

	public void addApplicationsToSite(String site, Application app) {
		this.getTechModelForSite(site).addApplication(app);
		// Add implied apps
		for (String imp : app.getImplies()) {
			Application ia = this.getApplication(imp);
			if (ia != null) {
				this.addApplicationsToSite(site, ia);
			}
		}
	}

	private Application getApplication(String name) {
		for (Application app : this.applications) {
			if (name.equals(app.getName())) {
				return app;
			}
		}
		return null;
	}
	
	public Application getSelectedApp() {
		if (View.isInitialised()) {
			String appName = this.getTechPanel().getSelectedApplicationName();
			if (appName != null) {
				return this.getApplication(appName);
			}
		}
		return null;
	}

	public String getSelectedSite() {
		if (View.isInitialised()) {
			return this.getTechPanel().getCurrentSite();
		}
		return null;
	}

	private ExtensionSearch getExtensionSearch() {
		if (extSearch == null) {
			extSearch = (ExtensionSearch) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSearch.NAME);
		}
		return extSearch;
	}

	public void search (Pattern p, ExtensionSearch.Type type) {
		ExtensionSearch extSearch = this.getExtensionSearch();
		if (extSearch != null) {
			extSearch.search(p.pattern(), type, true, false);
		}
	}
	
	@Override
	public void nodeSelected(SiteNode node) {
		// Event from SiteMapListenner
		this.getTechPanel().nodeSelected(node);
	}

	@Override
	public void onReturnNodeRendererComponent(SiteMapTreeCellRenderer arg0,
			boolean arg1, SiteNode arg2) {
	}

	@Override
	public void sessionAboutToChange(Session arg0) {
		// Ignore
	}

	@Override
	public void sessionChanged(final Session session) {
	    if (getView() == null) {
	        return;
	    }

	    if (EventQueue.isDispatchThread()) {
		    sessionChangedEventHandler(session);

	    } else {
	        try {
	            EventQueue.invokeAndWait(new Runnable() {
	                @Override
	                public void run() {
	        		    sessionChangedEventHandler(session);
	                }
	            });
	        } catch (Exception e) {
	            logger.error(e.getMessage(), e);
	        }
	    }
	}
	
	private void sessionChangedEventHandler(Session session) {
		// Clear all scans
		siteTechMap = new HashMap <String, TechTableModel>();
		this.getTechPanel().reset();
		if (session == null) {
			// Closedown
			return;
		}
		
		// TODO Repopulate
		SiteNode root = (SiteNode)session.getSiteTree().getRoot();
		@SuppressWarnings("unchecked")
		Enumeration<SiteNode> en = root.children();
		while (en.hasMoreElements()) {
			String site = en.nextElement().getNodeName();
			if (site.indexOf("//") >= 0) {
				site = site.substring(site.indexOf("//") + 2);
			}
			this.getTechPanel().addSite(site);
		}

	}

	@Override
	public void sessionModeChanged(Mode arg0) {
		// Ignore
	}

	@Override
	public void sessionScopeChanged(Session arg0) {
		// Ignore
	}

	public static void main(String[] args) throws Exception {
		// Quick way to test the apps.json file parsing
		
		ConsoleAppender ca = new ConsoleAppender();
		ca.setWriter(new OutputStreamWriter(System.out));
		ca.setLayout(new PatternLayout("%-5p [%t]: %m%n"));
        Logger.getRootLogger().addAppender(ca);
		
		new ExtensionWappalyzer();
		
	}

}
