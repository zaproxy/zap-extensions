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
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.swing.tree.TreeNode;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.ScanPanel;

public class ExtensionWappalyzer extends ExtensionAdaptor
        implements SessionChangedListener, ApplicationHolder, ExampleAlertProvider {

    public static final String NAME = "ExtensionWappalyzer";

    public static final String RESOURCE = "/org/zaproxy/zap/extension/wappalyzer/resources";

    public static final String TECHNOLOGIES_PATH = "resources/technologies/";
    public static final String CATEGORIES_PATH = "resources/categories.json";

    private TechPanel techPanel = null;
    private PopupMenuEvidence popupMenuEvidence = null;

    private List<Application> applications = new ArrayList<>();

    private ExtensionSearch extSearch = null;

    private Map<String, TechTableModel> siteTechMap;
    private boolean enabled;
    private TechDetectParam techDetectParam;

    private static final Logger LOGGER = LogManager.getLogger(ExtensionWappalyzer.class);

    /** The dependencies of the extension. */
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionPassiveScan2.class);

    private TechPassiveScanner passiveScanner;

    public enum Mode {
        QUICK(Constant.messages.getString("wappalyzer.mode.quick")),
        EXHAUSTIVE(Constant.messages.getString("wappalyzer.mode.exhaustive"));
        private final String name;

        Mode(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    /**
     * TODO implement Version handling Confidence handling - need to test for daemon mode (esp
     * revisits) Issues Handle load session - store tech in db? Sites pull down not populated if no
     * tech found - is this actually a problem?
     */
    public ExtensionWappalyzer() {
        super(NAME);
        this.setOrder(201);
    }

    @Override
    public void init() {
        super.init();

        recreateSiteTreeMap();

        // Prevent jsvg from logging too many, not so useful messages.
        setLogLevel(
                List.of(
                        "com.github.weisj.jsvg.util.ResourceUtil",
                        "com.github.weisj.jsvg.parser.css.impl.SimpleCssParser",
                        "com.github.weisj.jsvg.parser.css.impl.Lexer",
                        "com.github.weisj.jsvg.nodes.Image"),
                Level.OFF);

        List<String> technologyFiles = new ArrayList<>();
        try (ZipFile zip = new ZipFile(getAddOn().getFile())) {
            zip.stream()
                    .filter(ExtensionWappalyzer::isTechnology)
                    .map(ExtensionWappalyzer::techToResourcePath)
                    .forEach(technologyFiles::add);
        } catch (IOException e) {
            LOGGER.warn("Failed to enumerate Tech Detection technologies:", e);
        }

        TechData result =
                new TechsJsonParser().parse(CATEGORIES_PATH, technologyFiles, View.isInitialised());
        this.applications = result.getApplications();

        enabled = true;
        techDetectParam = new TechDetectParam();
        passiveScanner = new TechPassiveScanner(this);
    }

    private static boolean isTechnology(ZipEntry entry) {
        String name = entry.getName();
        return name.contains(TECHNOLOGIES_PATH) && name.endsWith(".json");
    }

    private static String techToResourcePath(ZipEntry entry) {
        String name = entry.getName();
        return name.substring(name.lastIndexOf(TECHNOLOGIES_PATH));
    }

    TechPassiveScanner getPassiveScanner() {
        return passiveScanner;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addSessionListener(this);

        if (hasView()) {
            @SuppressWarnings("unused")
            ExtensionHookView pv = extensionHook.getHookView();
            extensionHook.getHookView().addStatusPanel(getTechPanel());
            extensionHook.getHookMenu().addPopupMenuItem(this.getPopupMenuEvidence());
            extensionHook.getHookView().addOptionPanel(new TechOptionsPanel());
        }

        extensionHook.addApiImplementor(new TechApi(this));
        extensionHook.addOptionsParamSet(techDetectParam);

        getPscanExtension().getPassiveScannersManager().add(passiveScanner);
        extensionHook.addOptionsChangedListener(passiveScanner);
    }

    private static ExtensionPassiveScan2 getPscanExtension() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionPassiveScan2.class);
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();

        setWappalyzer(techDetectParam.isEnabled());
        passiveScanner.setMode(techDetectParam.getMode());
        passiveScanner.setRaiseAlerts(techDetectParam.isRaiseAlerts());
    }

    void setWappalyzer(boolean enabled) {
        if (this.enabled == enabled) {
            return;
        }
        this.enabled = enabled;

        techDetectParam.setEnabled(enabled);
        getPassiveScanner().setEnabled(enabled);

        if (hasView()) {
            ThreadUtils.invokeLater(
                    () -> getTechPanel().getEnableToggleButton().setSelected(enabled));
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

        getPscanExtension().getPassiveScannersManager().remove(passiveScanner);

        if (techPanel != null) {
            techPanel.unload();
        }
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
        TechTableModel model = this.siteTechMap.computeIfAbsent(site, s -> new TechTableModel());
        if (techPanel != null) {
            // Add to site pulldown
            this.techPanel.addSite(site);
        }
        return model;
    }

    @Override
    public void addApplicationsToSite(String site, ApplicationMatch applicationMatch) {

        if (!hasView() || EventQueue.isDispatchThread()) {
            this.getTechModelForSite(site).addApplication(applicationMatch);
        } else {
            EventQueue.invokeLater(
                    () -> this.getTechModelForSite(site).addApplication(applicationMatch));
        }
    }

    /**
     * Accept an {@code URI} which will be normalized into a site string usable by the Tech
     * Detection add-on and adds the provided {@code ApplicationMatch}
     *
     * @param uri The URI to be normalized and used
     * @param applicationMatch the ApplicationMatch for the tech to be added
     * @since 21.44.0
     */
    public void addApplicationsToSite(URI uri, ApplicationMatch applicationMatch) {
        this.addApplicationsToSite(normalizeSite(uri), applicationMatch);
    }

    public Application getSelectedApp() {
        if (hasView()) {
            String appName = this.getTechPanel().getSelectedApplicationName();
            if (appName != null) {
                return this.getApplication(appName);
            }
        }
        return null;
    }

    public String getSelectedSite() {
        if (hasView()) {
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
            LOGGER.debug("Unable to get authority from: {}", uri, e);
            // Shouldn't happen, but sure fallback
            return ScanPanel.cleanSiteName(uri.toString(), true);
        }
    }

    static String normalizeSite(String site) {
        try {
            site = normalizeSite(new URI(site == null ? "" : site, false));
        } catch (URIException ue) {
            // Shouldn't happen, but sure fallback
            LOGGER.debug(
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
        if (getExtensionSearch() != null) {
            getExtensionSearch().search(p.pattern(), type, true, false);
        }
    }

    @Override
    public void sessionAboutToChange(Session arg0) {
        // Ignore
    }

    @Override
    public void sessionChanged(final Session session) {
        if (!hasView()) {
            return;
        }
        ThreadUtils.invokeAndWaitHandled(() -> sessionChangedEventHandler(session));
    }

    private void recreateSiteTreeMap() {
        siteTechMap = Collections.synchronizedMap(new HashMap<>());
    }

    private void sessionChangedEventHandler(Session session) {
        // Clear all scans
        recreateSiteTreeMap();
        getPassiveScanner().reset();
        if (hasView()) {
            this.getTechPanel().reset();
            if (session == null) {
                // Closedown
                return;
            }

            // Repopulate
            SiteNode root = session.getSiteTree().getRoot();
            @SuppressWarnings("unchecked")
            Enumeration<TreeNode> en = root.children();
            while (en.hasMoreElements()) {
                String site =
                        normalizeSite(((SiteNode) en.nextElement()).getHistoryReference().getURI());
                this.getTechPanel().addSite(site);
            }
        }
    }

    @Override
    public void sessionModeChanged(org.parosproxy.paros.control.Control.Mode arg0) {
        // Ignore
    }

    @Override
    public void sessionScopeChanged(Session arg0) {
        // Ignore
    }

    @Override
    public void postInstall() {
        super.postInstall();
        if (hasView()) {
            EventQueue.invokeLater(this::focusTab);
        }
    }

    private void focusTab() {
        getTechPanel().setTabFocus();
        // Un-comment to test icon rendering
        /*
         * getApplications() .forEach( app -> addApplicationsToSite( "http://localhost",
         * new ApplicationMatch(app)));
         */
    }

    private static void setLogLevel(List<String> classnames, Level level) {
        boolean updateLoggers = false;
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = ctx.getConfiguration();
        for (String classname : classnames) {
            LoggerConfig loggerConfig = configuration.getLoggerConfig(classname);
            if (!classname.equals(loggerConfig.getName())) {
                configuration.addLogger(
                        classname,
                        LoggerConfig.newBuilder()
                                .withLoggerName(classname)
                                .withLevel(level)
                                .withConfig(configuration)
                                .build());
                updateLoggers = true;
            }
        }

        if (updateLoggers) {
            ctx.updateLoggers();
        }
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return passiveScanner.getExampleAlerts();
    }

    public String getHelpLink() {
        return passiveScanner.getHelpLink();
    }
}
