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
package org.zaproxy.zap.extension.httpsinfo;

import java.awt.EventQueue;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

public class ExtensionHttpsInfo extends ExtensionAdaptor
        implements SessionChangedListener, SiteMapListener, HttpsInfoCertificationHolder {

    public static final String NAME = "ExtensionHttpsInfo";

    public static final String RESOURCE = "/org/zaproxy/zap/extension/httpsinfo/resources";

    public static final ImageIcon HTTPSINFO_ICON =
            new ImageIcon(ExtensionHttpsInfo.class.getResource(RESOURCE + "/icon.png"));


    private HttpsInfoPanel httpsInfoPanel = null;

    private ExtensionSearch extSearch = null;

    private Map<String, HttpsInfoTableModel> siteHttpsInfoMap = new HashMap<>();
    private boolean enabled;
    private HttpsInfoParam httpsInfoParam;
    private List<Certification> certifications = new ArrayList<>();


    private static final Logger logger = LogManager.getLogger(ExtensionHttpsInfo.class);

    /**
     * The dependencies of the extension.
     */
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionPassiveScan.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private HttpsInfoScanner scanner;


    public ExtensionHttpsInfo() {
        super(NAME);
        this.setOrder(202);
    }

    @Override
    public void init() {
        super.init();

        HttpsInfoData result = new HttpsInfoData();
        this.certifications = result.getCertifications();

        enabled = true;
        httpsInfoParam = new HttpsInfoParam();
        scanner = new HttpsInfoScanner(this);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addSessionListener(this);
        extensionHook.addSiteMapListener(this);

        if (getView() != null) {
            @SuppressWarnings("unused")
            ExtensionHookView pv = extensionHook.getHookView();
            extensionHook.getHookView().addStatusPanel(getHttpsInfoPanel());
        }

        extensionHook.addOptionsParamSet(httpsInfoParam);

        ExtensionPassiveScan extPScan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan.class);
        extPScan.addPassiveScanner(scanner);
    }

    HttpsInfoScanner getScanner() {
        return scanner;
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();

        setHttpsInfo(httpsInfoParam.isEnabled());
    }


    void setHttpsInfo(boolean enabled) {
        if (this.enabled == enabled) {
            return;
        }
        this.enabled = enabled;

        httpsInfoParam.setEnabled(enabled);
        getScanner().setEnabled(enabled);

        if (View.isInitialised()) {
            getHttpsInfoPanel().getEnableToggleButton().setSelected(enabled);
        }
    }

    boolean isHttpsInfoEnabled() {
        return enabled;
    }

    private HttpsInfoPanel getHttpsInfoPanel() {
        if (httpsInfoPanel == null) {
            httpsInfoPanel = new HttpsInfoPanel(this);
        }
        return httpsInfoPanel;
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
        extPScan.removePassiveScanner(scanner);
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


    public Set<String> getSites() {
        return Collections.unmodifiableSet(siteHttpsInfoMap.keySet());
    }

    static String normalizeSite(URI uri) {
        String lead = uri.getScheme() + "://";
        try {
            return lead + uri.getAuthority();
        } catch (URIException e) {
            logger.debug("Unable to get authority from: {}", uri.toString(), e);
            // Shouldn't happen, but sure fallback
            return ScanPanel.cleanSiteName(uri.toString(), true);
        }
    }

    static String normalizeSite(String site) {
        try {
            site = normalizeSite(new URI(site == null ? "" : site, false));
        } catch (URIException ue) {
            // Shouldn't happen, but sure fallback
            logger.debug(
                    "Falling back to 'CleanSiteName'. Failed to create URI from: {}", site, ue);
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
        this.getHttpsInfoPanel().siteSelected(normalizeSite(node.getHistoryReference().getURI()));
    }

    @Override
    public void onReturnNodeRendererComponent(
            SiteMapTreeCellRenderer arg0, boolean arg1, SiteNode arg2) {
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
                EventQueue.invokeAndWait(() -> sessionChangedEventHandler(session));
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void sessionChangedEventHandler(Session session) {
        siteHttpsInfoMap = new HashMap<>();
        this.getHttpsInfoPanel().reset();
        if (session == null) {
            // Closedown
            return;
        }

        SiteNode root = session.getSiteTree().getRoot();
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> en = root.children();
        while (en.hasMoreElements()) {
            String site =
                    normalizeSite(((SiteNode) en.nextElement()).getHistoryReference().getURI());
            this.getHttpsInfoPanel().addSite(site);
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
            EventQueue.invokeLater(this::focusTab);
        }
    }

    private void focusTab() {
        getHttpsInfoPanel().setTabFocus();
    }

    public HttpsInfoTableModel getHttpsInfoModelForSite(String site) {
        HttpsInfoTableModel model = this.siteHttpsInfoMap.get(site);
        if (model == null) {
            model = new HttpsInfoTableModel();
            this.siteHttpsInfoMap.put(site, model);
            if (getView() != null) {
                this.getHttpsInfoPanel().addSite(site);
            }
        }
        return model;
    }

    @Override
    public void addCertificationToSite(String site, CertificateFound certificateFound) {
        this.getHttpsInfoModelForSite(site).addCertificate(certificateFound);
    }

    @Override
    public List<Certification> getCertifications() {
        return this.certifications;
    }
}
