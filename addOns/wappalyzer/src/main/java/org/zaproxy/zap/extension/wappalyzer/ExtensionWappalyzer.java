/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.EventQueue;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.swing.ImageIcon;
import javax.swing.tree.TreeNode;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.view.ScanPanel;
import org.zaproxy.zap.view.SiteMapListener;
import org.zaproxy.zap.view.SiteMapTreeCellRenderer;

public class ExtensionWappalyzer extends ExtensionAdaptor
        implements SessionChangedListener, SiteMapListener, WappalyzerApplicationHolder {

    public static final String NAME = "ExtensionWappalyzer";

    public static final String RESOURCE = "/org/zaproxy/zap/extension/wappalyzer/resources";

    public static final ImageIcon WAPPALYZER_ICON =
            new ImageIcon(ExtensionWappalyzer.class.getResource(RESOURCE + "/wappalyzer.png"));

    private TechPanel techPanel = null;
    private PopupMenuEvidence popupMenuEvidence = null;

    private Map<String, String> categories = new HashMap<String, String>();
    private List<Application> applications = new ArrayList<Application>();

    private ExtensionSearch extSearch = null;

    private Map<String, TechTableModel> siteTechMap = new HashMap<String, TechTableModel>();
    private boolean enabled;
    private WappalyzerParam wappalyzerParam;

    private static final Logger logger = Logger.getLogger(ExtensionWappalyzer.class);

    /** The dependencies of the extension. */
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionPassiveScan.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private WappalyzerPassiveScanner passiveScanner;
    private WappalyzerAPI api;

    /**
     * TODO Implementaion Version handling Confidence handling - need to test for daemon mode (esp
     * revisits) Issues Handle load session - store tech in db? Sites pull down not populated if no
     * tech found - is this actually a problem? One pattern still fails to compile
     */
    public ExtensionWappalyzer() {
        super(NAME);
        this.setOrder(201);

        try {
            WappalyzerJsonParser parser = new WappalyzerJsonParser();
            WappalyzerData result = parser.parseDefaultAppsJson();
            this.applications = result.getApplications();
            this.categories = result.getCategories();
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    public void init() {
        super.init();
        enabled = true;
        wappalyzerParam = new WappalyzerParam();
        passiveScanner = new WappalyzerPassiveScanner(this);
    }

    WappalyzerPassiveScanner getPassiveScanner() {
        return passiveScanner;
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

        this.api = new WappalyzerAPI(this);
        extensionHook.addApiImplementor(this.api);
        extensionHook.addOptionsParamSet(wappalyzerParam);

        ExtensionPassiveScan extPScan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan.class);
        extPScan.addPassiveScanner(passiveScanner);
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();

        setWappalyzer(wappalyzerParam.isEnabled());
    }

    void setWappalyzer(boolean enabled) {
        if (this.enabled == enabled) {
            return;
        }
        this.enabled = enabled;

        wappalyzerParam.setEnabled(enabled);
        getPassiveScanner().setEnabled(enabled);

        if (View.isInitialised()) {
            getTechPanel().getEnableToggleButton().setSelected(enabled);
        }
    }

    boolean isWappalyzerEnabled() {
        return enabled;
    }

    private TechPanel getTechPanel() {
        if (techPanel == null) {
            techPanel = new TechPanel(this);
        }
        return techPanel;
    }

    private PopupMenuEvidence getPopupMenuEvidence() {
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

        ExtensionPassiveScan extPScan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan.class);
        extPScan.removePassiveScanner(passiveScanner);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("wappalyzer.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("wappalyzer.name");
    }

    @Override
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

    @Override
    public void addApplicationsToSite(String site, ApplicationMatch applicationMatch) {

        this.getTechModelForSite(site).addApplication(applicationMatch);
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

    public Set<String> getSites() {
        return Collections.unmodifiableSet(siteTechMap.keySet());
    }

    static String normalizeSite(URI uri) {
        String lead = uri.getScheme() + "://";
        try {
            return lead + uri.getAuthority();
        } catch (URIException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Unable to get authority from: " + uri.toString(), e);
            }
            // Shouldn't happen, but sure fallback
            return ScanPanel.cleanSiteName(uri.toString(), true);
        }
    }

    static String normalizeSite(String site) {
        try {
            site = normalizeSite(new URI(site == null ? "" : site, false));
        } catch (URIException ue) {
            // Shouldn't happen, but sure fallback
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Falling back to 'CleanSiteName'. Failed to create URI from: " + site, ue);
            }
            site = ScanPanel.cleanSiteName(site, true);
        }
        return site;
    }

    private ExtensionSearch getExtensionSearch() {
        if (extSearch == null) {
            extSearch =
                    (ExtensionSearch)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionSearch.NAME);
        }
        return extSearch;
    }

    public void search(Pattern p, ExtensionSearch.Type type) {
        ExtensionSearch extSearch = this.getExtensionSearch();
        if (extSearch != null) {
            extSearch.search(p.pattern(), type, true, false);
        }
    }

    @Override
    public void nodeSelected(SiteNode node) {
        // Event from SiteMapListenner
        this.getTechPanel().siteSelected(normalizeSite(node.getHistoryReference().getURI()));
    }

    @Override
    public void onReturnNodeRendererComponent(
            SiteMapTreeCellRenderer arg0, boolean arg1, SiteNode arg2) {}

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
                EventQueue.invokeAndWait(
                        new Runnable() {
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
        siteTechMap = new HashMap<String, TechTableModel>();
        this.getTechPanel().reset();
        if (session == null) {
            // Closedown
            return;
        }

        // TODO Repopulate
        SiteNode root = session.getSiteTree().getRoot();
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> en = root.children();
        while (en.hasMoreElements()) {
            String site =
                    normalizeSite(((SiteNode) en.nextElement()).getHistoryReference().getURI());
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

    @Override
    public void postInstall() {
        super.postInstall();
        if (getView() != null) {
            EventQueue.invokeLater(
                    () -> {
                        getTechPanel().setTabFocus();
                        // Un-comment to test icon rendering
                        /*
                         * getApplications() .forEach( app -> addApplicationsToSite( "http://localhost",
                         * new ApplicationMatch(app)));
                         */
                    });
        }
    }
}
