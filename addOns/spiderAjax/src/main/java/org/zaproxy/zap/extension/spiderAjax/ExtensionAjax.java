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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.event.KeyEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.tree.TreeNode;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.spiderAjax.internal.ContextDataManager;
import org.zaproxy.zap.extension.spiderAjax.internal.PopupMenuItemSpiderDialogWithContext;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * Main class of the plugin, it instantiates the rest of them.
 *
 * @author Guifre Ruiz Utges
 */
public class ExtensionAjax extends ExtensionAdaptor {

    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
    public static final String NAME = "ExtensionSpiderAjax";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionSelenium.class, ExtensionNetwork.class);

    private SpiderPanel spiderPanel = null;
    private PopupMenuAjaxSite popupMenuSpiderSite = null;
    private ZapMenuItem menuItemCustomScan;
    private AjaxSpiderDialog spiderDialog = null;
    private OptionsAjaxSpider optionsAjaxSpider = null;
    private List<String> excludeList = null;
    private boolean spiderRunning;
    private SpiderListener spiderListener;
    private AjaxSpiderAPI ajaxSpiderApi;
    private AjaxSpiderParam ajaxSpiderParam;
    private ExtensionNetwork extensionNetwork;

    private ContextDataManager contextDataManager;
    private List<AuthenticationHandler> authHandlers = new ArrayList<>();

    private ImageIcon icon;

    /**
     * initializes the extension
     *
     * @throws ClassNotFoundException
     */
    public ExtensionAjax() throws ClassNotFoundException {
        super(NAME);
        this.setI18nPrefix("spiderajax");
        this.setOrder(234);
    }

    @Override
    public void init() {
        super.init();

        // Prevent Crawljax from logging too many, not so useful, INFO messages.
        setLogLevel(
                List.of(
                        "com.crawljax.core.Crawler",
                        "com.crawljax.core.UnfiredCandidateActions",
                        "com.crawljax.core.state.StateMachine"),
                Level.WARN);
        setLogLevel(List.of("com.crawljax.forms.FormHandler"), Level.OFF);

        ajaxSpiderApi = new AjaxSpiderAPI(this);
        this.ajaxSpiderApi.addApiOptions(getAjaxSpiderParam());
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

    /**
     * starts the proxy and all elements of the UI
     *
     * @param extensionHook the extension
     */
    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        contextDataManager = new ContextDataManager(getModel(), getView(), extensionHook);

        extensionHook.addApiImplementor(ajaxSpiderApi);
        extensionHook.addOptionsParamSet(getAjaxSpiderParam());

        extensionHook.addSessionListener(new SpiderSessionChangedListener());

        if (hasView()) {

            extensionHook.getHookView().addStatusPanel(getSpiderPanel());
            extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAjaxSite());
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new PopupMenuItemSpiderDialogWithContext(this));
            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());
            ExtensionHelp.enableHelpKey(getSpiderPanel(), "addon.spiderajax.tab");
        }

        extensionNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);
    }

    public ContextDataManager getContextDataManager() {
        return contextDataManager;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            getSpiderPanel().unload();

            SpiderEventPublisher.unregisterPublisher();

            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightLabel(
                            getSpiderPanel().getScanStatus().getCountLabel());

            if (spiderDialog != null) {
                spiderDialog.dispose();
            }
        }

        contextDataManager.unload();

        super.unload();
    }

    @Override
    public void stop() {
        if (hasView()) {
            stopScan();
        }
        ajaxSpiderApi.stopSpider();
    }

    @Override
    public List<String> getActiveActions() {
        if (isSpiderRunning()) {
            List<String> activeActions = new ArrayList<>(1);
            activeActions.add(getMessages().getString("spiderajax.active.action"));
            return activeActions;
        }

        return super.getActiveActions();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    /**
     * Creates the panel with the config of the proxy
     *
     * @return the panel
     */
    protected SpiderPanel getSpiderPanel() {
        if (spiderPanel == null) {
            spiderPanel = new SpiderPanel(this);
            spiderPanel.setName(this.getMessages().getString("spiderajax.panel.title"));
            spiderPanel.setIcon(getIcon());
        }
        return spiderPanel;
    }

    /**
     * Gets the icon for the AJAX spider related functionality.
     *
     * <p>Should not be called if there's no view.
     *
     * @return the icon, never {@code null}.
     */
    public ImageIcon getIcon() {
        if (icon == null) {
            icon =
                    DisplayUtils.getScaledIcon(
                            getClass().getResource("/resource/icon/16/spiderAjax.png"));
        }
        return icon;
    }

    public AjaxSpiderParam getAjaxSpiderParam() {
        if (ajaxSpiderParam == null) {
            ajaxSpiderParam = new AjaxSpiderParam();
        }
        return ajaxSpiderParam;
    }

    /**
     * @return the PopupMenuAjaxSite object
     */
    private PopupMenuAjaxSite getPopupMenuAjaxSite() {
        if (popupMenuSpiderSite == null) {
            popupMenuSpiderSite =
                    new PopupMenuAjaxSite(
                            this.getMessages().getString("spiderajax.site.popup"), this);
        }
        return popupMenuSpiderSite;
    }

    private ZapMenuItem getMenuItemCustomScan() {
        if (menuItemCustomScan == null) {
            menuItemCustomScan =
                    new ZapMenuItem(
                            "spiderajax.menu.tools.label",
                            getView()
                                    .getMenuShortcutKeyStroke(
                                            KeyEvent.VK_X, KeyEvent.ALT_DOWN_MASK, false));
            menuItemCustomScan.setEnabled(Control.getSingleton().getMode() != Mode.safe);
            menuItemCustomScan.setIcon(getIcon());

            menuItemCustomScan.addActionListener(e -> showScanDialog((Target) null));
        }
        return menuItemCustomScan;
    }

    /**
     * @return
     */
    private OptionsAjaxSpider getOptionsSpiderPanel() {
        if (optionsAjaxSpider == null) {
            ExtensionSelenium extSelenium =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);
            optionsAjaxSpider =
                    new OptionsAjaxSpider(
                            this.getMessages(), extSelenium.createProvidedBrowsersComboBoxModel());
        }
        return optionsAjaxSpider;
    }

    public void showScanDialog(SiteNode node) {
        showScanDialog(node == null ? null : new Target(node));
    }

    public void showScanDialog(Target target) {
        if (spiderDialog == null) {
            spiderDialog =
                    new AjaxSpiderDialog(
                            this,
                            View.getSingleton().getMainFrame(),
                            DisplayUtils.getScaledDimension(700, 500));
            spiderDialog.init(target);
        } else if (target != null) {
            spiderDialog.init(target);
        } else {
            spiderDialog.updateBrowsers();
        }

        spiderDialog.setVisible(true);
    }

    /**
     * Starts a new spider scan using the given target.
     *
     * <p>The spider scan will use the most appropriate display name created from the given target.
     *
     * @param target the target that will be spidered
     * @see #startScan(String, AjaxSpiderTarget)
     * @throws IllegalStateException if the target is not allowed in the current {@link
     *     org.parosproxy.paros.control.Control.Mode mode}.
     */
    public void startScan(AjaxSpiderTarget target) {
        startScan(createDisplayName(target), target);
    }

    /**
     * Creates the display name for the given target.
     *
     * @param target the target that will be spidered
     * @return a {@code String} containing the display name, never {@code null}
     */
    public String createDisplayName(AjaxSpiderTarget target) {
        if (target.isSubtreeOnly()) {
            return abbreviateDisplayName(
                    HttpPrefixUriValidator.getNormalisedPrefix(target.getStartUri().toString()));
        } else if (target.getContext() != null) {
            return Constant.messages.getString("context.prefixName", target.getContext().getName());
        } else if (target.isInScopeOnly()) {
            return Constant.messages.getString("target.allInScope");
        } else if (target.getStartUri() == null) {
            return Constant.messages.getString("target.empty");
        }
        return abbreviateDisplayName(target.getStartUri().toString());
    }

    /**
     * Abbreviates (the middle of) the given display name if greater than 30 characters.
     *
     * @param displayName the display name that might be abbreviated
     * @return the, possibly, abbreviated display name
     */
    private static String abbreviateDisplayName(String displayName) {
        return StringUtils.abbreviateMiddle(displayName, "..", 30);
    }

    /**
     * Starts a new spider scan using the given target.
     *
     * @param displayName the name that will be used for this scan when it is displayed
     * @param target the target that will be spidered
     * @see #startScan(String, AjaxSpiderTarget)
     * @throws IllegalStateException if the target is not allowed in the current {@link
     *     org.parosproxy.paros.control.Control.Mode mode}.
     */
    public void startScan(String displayName, AjaxSpiderTarget target) {
        this.startScan(displayName, target, null);
    }

    /**
     * Starts a new spider scan using the given target.
     *
     * <p>The spider scan will use the most appropriate display name created from the given target.
     *
     * @param target the target that will be spidered
     * @param listener a listener that will be notified of the scan progress
     * @see #startScan(String, AjaxSpiderTarget)
     * @throws IllegalStateException if the target is not allowed in the current {@link
     *     org.parosproxy.paros.control.Control.Mode mode}.
     */
    public void startScan(AjaxSpiderTarget target, SpiderListener listener) {
        startScan(createDisplayName(target), target, listener);
    }

    /**
     * Starts a new spider scan, with the given display name and using the given target.
     *
     * <p><strong>Note:</strong> The preferred method to start the scan is with {@link
     * #startScan(AjaxSpiderTarget)}, unless a custom display name is really needed.
     *
     * @param displayName the name of the scan (to be displayed in UI)
     * @param target the target that will be spidered
     * @param listener a listener that will be notified of the scan progress
     * @throws IllegalStateException if the target is not allowed in the current {@link
     *     org.parosproxy.paros.control.Control.Mode mode}.
     */
    @SuppressWarnings("fallthrough")
    public void startScan(String displayName, AjaxSpiderTarget target, SpiderListener listener) {
        if (hasView()) {
            switch (Control.getSingleton().getMode()) {
                case safe:
                    throw new IllegalStateException("Scans are not allowed in Safe mode");
                case protect:
                    String uri = target.getStartUri().toString();
                    if (!getModel().getSession().isInScope(uri)) {
                        throw new IllegalStateException(
                                "Scans are not allowed on targets not in scope when in Protected mode: "
                                        + uri);
                    }
                case standard:
                case attack:
                default:
                    // No problem
                    break;
            }

            getSpiderPanel().startScan(displayName, target, listener);
        }
    }

    /** Stops a scan started via the UI */
    public void stopScan() {
        getSpiderPanel().stopScan();
    }

    URI getFirstUriInContext(Context context) {
        return findFirstUriInContext(context, getModel().getSession().getSiteTree().getRoot());
    }

    private static URI findFirstUriInContext(Context context, SiteNode node) {
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> en = node.children();
        while (en.hasMoreElements()) {
            SiteNode childNode = (SiteNode) en.nextElement();
            if (context.isInContext(childNode)) {
                return URI.create(childNode.getHistoryReference().getURI().toString());
            }

            URI uri = findFirstUriInContext(context, childNode);
            if (uri != null) {
                return uri;
            }
        }
        return null;
    }

    /**
     * @param ignoredRegexs
     */
    public void setExcludeList(List<String> ignoredRegexs) {
        this.excludeList = ignoredRegexs;
    }

    /**
     * @return the exclude list
     */
    public List<String> getExcludeList() {
        return excludeList;
    }

    /**
     * @return description of the plugin
     */
    @Override
    public String getDescription() {
        return this.getMessages().getString("spiderajax.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("spiderajax.name");
    }

    public SpiderThread createSpiderThread(
            String displayName, AjaxSpiderTarget target, SpiderListener spiderListener) {
        SpiderThread spiderThread =
                new SpiderThread(displayName, target, this, spiderListener, extensionNetwork);
        spiderThread.addSpiderListener(getSpiderListener());

        return spiderThread;
    }

    private SpiderListener getSpiderListener() {
        if (spiderListener == null) {
            createSpiderListener();
        }
        return spiderListener;
    }

    private synchronized void createSpiderListener() {
        if (spiderListener == null) {
            spiderListener = new ExtensionAjaxSpiderListener();
        }
    }

    public void addAuthenticationHandler(AuthenticationHandler handler) {
        authHandlers.add(handler);
    }

    public void removeAuthenticationHandler(AuthenticationHandler handler) {
        authHandlers.remove(handler);
    }

    protected List<AuthenticationHandler> getAuthenticationHandlers() {
        return Collections.unmodifiableList(authHandlers);
    }

    public boolean isSpiderRunning() {
        return spiderRunning;
    }

    private void setSpiderRunning(boolean running) {
        spiderRunning = running;
    }

    private class SpiderSessionChangedListener implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionAboutToChange(Session session) {
            ajaxSpiderApi.reset();
            if (hasView()) {
                getSpiderPanel().reset();
                if (spiderDialog != null) {
                    spiderDialog.reset();
                }
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {
            if (hasView()) {
                getSpiderPanel().sessionModeChanged(mode);
                getMenuItemCustomScan().setEnabled(mode != Mode.safe);
            }
        }
    }

    private class ExtensionAjaxSpiderListener implements SpiderListener {

        @Override
        public void spiderStarted() {
            setSpiderRunning(true);
        }

        @Override
        public void foundMessage(
                HistoryReference historyReference, HttpMessage httpMessage, ResourceState state) {
            // Nothing to do.
        }

        @Override
        public void spiderStopped() {
            setSpiderRunning(false);
        }
    }
}
