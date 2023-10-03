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
package org.zaproxy.zap.extension.quickstart;

import java.awt.Container;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.Vector;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import javax.swing.ComboBoxModel;
import javax.swing.SwingUtilities;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.callhome.ExtensionCallHome;
import org.zaproxy.addon.callhome.InvalidServiceUrlException;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.common.ZapUnknownHostException;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.ZAP.ProcessType;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.ext.ExtensionExtension;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.quickstart.AttackThread.Progress;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionQuickStart extends ExtensionAdaptor
        implements SessionChangedListener, CommandLineListener, OptionsChangedListener {

    public static final String NAME = "ExtensionQuickStart";
    public static final String RESOURCES = "/org/zaproxy/zap/extension/quickstart/resources";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionQuickStart.class);

    private QuickStartPanel quickStartPanel = null;
    private AttackThread attackThread = null;
    private TraditionalSpider traditionalSpider;
    private PlugableSpider plugableSpider;
    private PlugableHud hudProvider;
    private QuickStartParam quickStartParam;
    private HttpSender httpSender;

    private CommandLineArgument[] arguments = new CommandLineArgument[4];
    private static final int ARG_QUICK_URL_IDX = 0;
    private static final int ARG_QUICK_OUT_IDX = 1;
    private static final int ARG_QUICK_PROGRESS_IDX = 2;
    private static final int ARG_ZAPIT_URL_IDX = 3;
    private static final String SPIN_CHRS = "|/-\\|/-\\";

    private boolean runningFromCmdLine = false;
    private boolean showProgress = false;
    private int spinner = 0;

    private ExtensionReports extReport;

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(
                    ExtensionPassiveScan.class,
                    ExtensionAlert.class,
                    ExtensionReports.class,
                    ExtensionNetwork.class);

    private CompletableFuture<Void> newsFetcherFuture;

    public ExtensionQuickStart() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsChangedListener(this);
        extensionHook.addOptionsParamSet(getQuickStartParam());

        if (hasView()) {
            extensionHook.getHookView().addWorkPanel(getQuickStartPanel());

            ExtensionHelp.enableHelpKey(getQuickStartPanel(), "quickstart");
        }
        extensionHook.addSessionListener(this);

        extensionHook.addCommandLine(getCommandLineArguments());
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private ZapXmlConfiguration getNews()
            throws ConfigurationException, IOException, InvalidServiceUrlException {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionCallHome.class)
                .getNewsData();
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();
        if (View.isInitialised()) {
            getQuickStartPanel().optionsLoaded(this.getQuickStartParam());
        }
    }

    @Override
    public void postInit() {
        if (Constant.isSilent()) {
            LOGGER.info("Shh! No check-for-news - silent mode enabled");
            return;
        }

        newsFetcherFuture = CompletableFuture.runAsync(this::fetchNews);
    }

    private void fetchNews() {
        try {
            ZapXmlConfiguration xmlNews = getNews();
            if (!hasView()) {
                return;
            }

            String zapLocale = Constant.getLocale().toString();

            ConfigurationNode newsNode = getFirstChildNode(xmlNews.getRoot(), "news");
            if (newsNode != null) {
                String id = getFirstChildNodeString(newsNode, "id");
                ConfigurationNode localeNode = getFirstChildNode(newsNode, zapLocale);
                if (localeNode == null) {
                    localeNode = getFirstChildNode(newsNode, "default");
                }
                if (localeNode != null) {
                    String itemText = getFirstChildNodeString(localeNode, "item");

                    if (itemText != null && itemText.length() > 0) {
                        announceNews(
                                new NewsItem(
                                        id,
                                        itemText,
                                        new URI(
                                                getFirstChildNodeString(localeNode, "link"),
                                                true)));
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to read news : {}", e.getMessage(), e);
        }
    }

    @Override
    public void unload() {
        if (newsFetcherFuture == null) {
            return;
        }

        try {
            newsFetcherFuture.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for the news fetcher, exceptions might occur.");
        } catch (ExecutionException e) {
            LOGGER.warn("An error occurred while waiting for the news fetcher:", e);
        }
    }

    private ConfigurationNode getFirstChildNode(ConfigurationNode node, String childName) {
        List<ConfigurationNode> list = node.getChildren(childName);
        if (list.size() > 0) {
            return list.get(0);
        }
        return null;
    }

    private String getFirstChildNodeString(ConfigurationNode node, String childName) {
        ConfigurationNode child = this.getFirstChildNode(node, childName);
        if (child != null) {
            return child.getValue().toString();
        }
        return null;
    }

    private void announceNews(NewsItem newsItem) {
        if (!this.getQuickStartParam().getClearedNewsItem().equals(newsItem.getId())) {
            getQuickStartPanel().announceNews(newsItem);
        }
    }

    public QuickStartParam getQuickStartParam() {
        if (quickStartParam == null) {
            quickStartParam = new QuickStartParam();
        }
        return quickStartParam;
    }

    public void setLaunchPanel(QuickStartSubPanel panel) {
        if (quickStartPanel != null) {
            quickStartPanel.setExplorePanel(panel);
        }
    }

    public void setTraditionalSpider(TraditionalSpider spider) {
        this.traditionalSpider = spider;
        if (quickStartPanel != null) {
            quickStartPanel.setTraditionalSpider(traditionalSpider);
        }
    }

    public void addPlugableSpider(PlugableSpider pe) {
        this.plugableSpider = pe;
        if (quickStartPanel != null) {
            quickStartPanel.addPlugableSpider(pe);
        }
    }

    public void removePlugableSpider(PlugableSpider pe) {
        this.plugableSpider = pe;
        if (quickStartPanel != null) {
            quickStartPanel.removePlugableSpider(pe);
        }
    }

    public QuickStartPanel getQuickStartPanel() {
        if (quickStartPanel == null) {
            quickStartPanel = new QuickStartPanel(this);
            quickStartPanel.setName(Constant.messages.getString("quickstart.panel.title"));
            // Force it to be the first one
            quickStartPanel.setTabIndex(0);
            if (this.traditionalSpider != null) {
                quickStartPanel.setTraditionalSpider(traditionalSpider);
            }
            if (this.plugableSpider != null) {
                quickStartPanel.addPlugableSpider(this.plugableSpider);
            }
        }
        return quickStartPanel;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.name");
    }

    public void attack(URL url, boolean useStdSpider) {
        if (attackThread != null && attackThread.isAlive()) {
            return;
        }
        attackThread = new AttackThread(this, useStdSpider);
        attackThread.setURL(url);
        attackThread.setTraditionalSpider(traditionalSpider);
        attackThread.setPlugableSpider(plugableSpider);
        attackThread.start();
    }

    protected SiteNode accessNode(URL url, HttpRequestConfig config, boolean successOnly) {
        SiteNode startNode = null;
        // Request the URL
        try {
            final HttpMessage msg = new HttpMessage(new URI(url.toString(), true));
            getHttpSender().sendAndReceive(msg, config);
            getHttpSender().setUseGlobalState(false);

            if (successOnly && !HttpStatusCode.isSuccess(msg.getResponseHeader().getStatusCode())) {
                notifyProgress(
                        Progress.failed,
                        Constant.messages.getString(
                                "quickstart.progress.failed.code",
                                msg.getResponseHeader().getStatusCode()));

                return null;
            }

            if (msg.getResponseHeader().isEmpty()) {
                notifyProgress(Progress.failed);
                return null;
            }

            ExtensionHistory extHistory =
                    ((ExtensionHistory)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionHistory.NAME));
            extHistory.addHistory(msg, HistoryReference.TYPE_PROXIED);

            FutureTask<SiteNode> addSiteNodeTask =
                    new FutureTask<>(
                            () ->
                                    Model.getSingleton()
                                            .getSession()
                                            .getSiteTree()
                                            .addPath(msg.getHistoryRef()));

            SwingUtilities.invokeLater(addSiteNodeTask);
            startNode = addSiteNodeTask.get();

        } catch (ZapUnknownHostException e1) {
            if (e1.isFromOutgoingProxy()) {
                notifyProgress(
                        Progress.failed,
                        Constant.messages.getString(
                                "quickstart.progress.failed.badhost.proxychain", e1.getMessage()));
            } else {
                notifyProgress(
                        Progress.failed,
                        Constant.messages.getString(
                                "quickstart.progress.failed.badhost", e1.getMessage()));
            }
        } catch (URIException e) {
            notifyProgress(
                    Progress.failed,
                    Constant.messages.getString(
                            "quickstart.progress.failed.reason", e.getMessage()));
        } catch (Exception e1) {
            LOGGER.error(e1.getMessage(), e1);
            notifyProgress(
                    Progress.failed,
                    Constant.messages.getString(
                            "quickstart.progress.failed.reason", e1.getMessage()));
            return null;
        }
        return startNode;
    }

    private HttpSender getHttpSender() {
        if (httpSender == null) {
            httpSender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
            httpSender.setUseGlobalState(false);
        }
        return httpSender;
    }

    public void notifyProgress(AttackThread.Progress progress) {
        this.notifyProgress(progress, (String) null);
    }

    public void notifyProgress(AttackThread.Progress progress, String msg) {
        if (View.isInitialised()) {
            this.getQuickStartPanel().getAttackPanel().notifyProgress(progress, msg);
        } else if (this.runningFromCmdLine && this.showProgress) {
            if (msg != null) {
                System.out.println(msg);
            } else {
                System.out.println(
                        Constant.messages.getString(
                                "quickstart.cmdline.progress." + progress.name()));
            }
        }
        switch (progress) {
            case notstarted:
            case started:
            case spider:
            case ajaxspider:
            case ascan:
                this.runningFromCmdLine = true;
                break;
            case failed:
            case complete:
            case stopped:
                this.runningFromCmdLine = false;
                break;
        }
    }

    public void notifyProgress(AttackThread.Progress progress, int percent) {
        if (this.runningFromCmdLine && this.showProgress) {
            int scale = 5; // 20 chrs seems about right..
            System.out.print("[");
            for (int i = 0; i < 100 / scale; i++) {
                if (i + 1 <= percent / scale) {
                    System.out.print("=");
                } else {
                    System.out.print(" ");
                }
            }
            System.out.print("] " + percent + "% ");
            if (percent < 100) {
                // Print out a v simple spinner so its obvious something is still happening
                System.out.print(SPIN_CHRS.charAt(this.spinner % SPIN_CHRS.length()) + "\r");
                this.spinner++;
            } else {
                System.out.print("\n");
                this.spinner = 0;
            }
        }
    }

    public void stopAttack() {
        if (attackThread != null) {
            attackThread.stopAttack();
            attackThread = null;
        }
    }

    public void showOnStart(boolean showOnStart) {
        if (!showOnStart) {
            // Remove the tab right away
            Container parent = this.getQuickStartPanel().getParent();
            parent.remove(this.getQuickStartPanel());
        }

        // Save in configs
        ExtensionExtension extExt =
                (ExtensionExtension)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionExtension.NAME);
        if (extExt != null) {
            extExt.enableExtension(NAME, showOnStart);
        }
    }

    @Override
    public void sessionAboutToChange(Session arg0) {
        stopAttack();
    }

    @Override
    public void sessionChanged(Session arg0) {
        // Ignore
    }

    @Override
    public void sessionModeChanged(Mode mode) {
        if (hasView()) {
            this.getQuickStartPanel().getAttackPanel().setMode(mode);
        }
    }

    @Override
    public void sessionScopeChanged(Session arg0) {
        // Ignore
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_QUICK_URL_IDX].isEnabled()) {
            Vector<String> params = arguments[ARG_QUICK_URL_IDX].getArguments();
            if (params.size() == 1) {
                QuickAttacker quickAttacker;
                if (View.isInitialised()) {
                    quickAttacker = new UIQuickAttacker();
                } else {
                    quickAttacker = new HeadlessQuickAttacker();
                }

                if (!quickAttacker.attack(params.get(0))) {
                    return;
                }

                this.runningFromCmdLine = true;

                if (arguments[ARG_QUICK_PROGRESS_IDX].isEnabled()) {
                    this.showProgress = true;
                }

                while (this.runningFromCmdLine) {
                    // Loop until the attack thread completes
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ignore) {
                    }
                }

                if (arguments[ARG_QUICK_OUT_IDX].isEnabled()) {
                    quickAttacker.saveReport(
                            Paths.get(arguments[ARG_QUICK_OUT_IDX].getArguments().get(0)));
                } else {
                    quickAttacker.handleNoSavedReport();
                }
            }
        } else if (arguments[ARG_ZAPIT_URL_IDX].isEnabled()) {
            if (!ProcessType.cmdline.equals(ZAP.getProcessType())) {
                // For now only support the command line
                LOGGER.warn(
                        Constant.messages.getString("quickstart.cmdline.zapit.error.notCmdLine"));
                return;
            }
            Vector<String> params = arguments[ARG_ZAPIT_URL_IDX].getArguments();
            for (String param : params) {
                ZapItScan reconScan = new ZapItScan(this);
                String paramLc = param.toLowerCase(Locale.ROOT);
                if (!paramLc.startsWith(HttpHeader.SCHEME_HTTP)
                        && !paramLc.startsWith(HttpHeader.SCHEME_HTTPS)) {
                    // Scheme not specified, try both HTTP(S)
                    reconScan.recon(HttpHeader.SCHEME_HTTP + param);
                    reconScan.recon(HttpHeader.SCHEME_HTTPS + param);
                } else {
                    reconScan.recon(param);
                }
            }

        } else {
            return;
        }
    }

    private ExtensionReports getExtReport() {
        if (extReport == null) {
            extReport =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionReports.class);
        }
        return extReport;
    }

    private void saveScanReport(Path path) throws Exception {
        String template;
        String fileName = path.toString();
        String fileNameLc = fileName.toLowerCase();

        if (fileNameLc.endsWith(".html")) {
            template = "traditional-html";
        } else if (fileNameLc.endsWith(".md")) {
            template = "traditional-md";
        } else if (fileNameLc.endsWith(".json")) {
            template = "traditional-json";
        } else {
            template = "traditional-xml";
        }

        getExtReport().generateReport(template, fileName, "ZAP Report", "", false);
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_QUICK_URL_IDX] =
                new CommandLineArgument(
                        "-quickurl",
                        1,
                        null,
                        "",
                        "-quickurl <target url>   "
                                + Constant.messages.getString("quickstart.cmdline.url.help"));
        arguments[ARG_QUICK_OUT_IDX] =
                new CommandLineArgument(
                        "-quickout",
                        1,
                        null,
                        "",
                        "-quickout <filename>     "
                                + Constant.messages.getString("quickstart.cmdline.out.help"));
        arguments[ARG_QUICK_PROGRESS_IDX] =
                new CommandLineArgument(
                        "-quickprogress",
                        0,
                        null,
                        "",
                        "-quickprogress:          "
                                + Constant.messages.getString("quickstart.cmdline.progress.help"));
        arguments[ARG_ZAPIT_URL_IDX] =
                new CommandLineArgument(
                        "-zapit",
                        1,
                        null,
                        "",
                        "-zapit <target url>      "
                                + Constant.messages.getString("quickstart.cmdline.zapiturl.help"));
        return arguments;
    }

    @Override
    public List<String> getHandledExtensions() {
        return null;
    }

    @Override
    public boolean handleFile(File file) {
        // Not supported
        return false;
    }

    private abstract static class QuickAttacker {

        public abstract boolean attack(String url);

        protected final boolean isValid(Path file) {
            if (Files.notExists(file)) {
                if (file.getParent() == null || !Files.isWritable(file.getParent())) {
                    reportError(
                            Constant.messages.getString(
                                    "quickstart.cmdline.quickout.error.dirNotWritable",
                                    file.getParent() == null
                                            ? file.toAbsolutePath()
                                            : file.getParent().toAbsolutePath().normalize()));
                    return false;
                }
            } else if (!Files.isRegularFile(file)) {
                reportError(
                        Constant.messages.getString(
                                "quickstart.cmdline.quickout.error.notAFile",
                                file.toAbsolutePath().normalize()));
                return false;
            } else if (!Files.isWritable(file)) {
                reportError(
                        Constant.messages.getString(
                                "quickstart.cmdline.quickout.error.fileNotWritable",
                                file.toAbsolutePath().normalize()));
                return false;
            }

            return true;
        }

        protected abstract void reportError(String error);

        public abstract void saveReport(Path file);

        public abstract void handleNoSavedReport();
    }

    private class UIQuickAttacker extends QuickAttacker {

        @Override
        public boolean attack(String url) {
            getQuickStartPanel().getAttackPanel().setAttackUrl(url);
            return getQuickStartPanel().getAttackPanel().attackUrl();
        }

        @Override
        protected void reportError(String error) {
            View.getSingleton().showWarningDialog(error);
        }

        @Override
        public void saveReport(Path file) {
            if (!isValid(file)) {
                return;
            }
            try {
                saveScanReport(file);
                View.getSingleton()
                        .showMessageDialog(
                                Constant.messages.getString(
                                        "quickstart.cmdline.quickout.save.report.successful",
                                        file.toAbsolutePath().normalize()));
            } catch (Exception e) {
                reportError(
                        Constant.messages.getString(
                                "quickstart.cmdline.quickout.error.save.report"));
                LOGGER.error("Failed to generate report: ", e);
            }
        }

        @Override
        public void handleNoSavedReport() {
            // Do nothing, the user has the UI to generate the report if (s)he wants to.
        }
    }

    private class HeadlessQuickAttacker extends QuickAttacker {

        @Override
        public boolean attack(String url) {
            URL targetURL;
            try {
                targetURL = new URL(url);
                // Validate the actual request-uri of the HTTP message accessed.
                new URI(url, true);
            } catch (MalformedURLException | URIException e) {
                reportError(
                        Constant.messages.getString(
                                "quickstart.cmdline.quickurl.error.invalidUrl"));
                e.printStackTrace();
                return false;
            }

            ExtensionQuickStart.this.attack(targetURL, true);
            return true;
        }

        @Override
        protected void reportError(String error) {
            System.out.println(error);
        }

        @Override
        public void saveReport(Path file) {
            System.out.println(
                    Constant.messages.getString(
                            "quickstart.cmdline.outputto", file.toAbsolutePath().toString()));

            if (!isValid(file)) {
                return;
            }

            try {
                saveScanReport(file);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void handleNoSavedReport() {
            try {
                // Just output to stdout
                Path tmpFile = Files.createTempFile("ZAP-cmd-line-report", ".tmp");
                saveScanReport(tmpFile);
                System.out.println(new String(Files.readAllBytes(tmpFile), StandardCharsets.UTF_8));
                tmpFile.toFile().delete();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void backToMainPanel() {
        this.getQuickStartPanel().backToMainPanel();
    }

    public void setHudProvider(PlugableHud hp) {
        this.hudProvider = hp;
    }

    public PlugableHud getHudProvider() {
        return this.hudProvider;
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        this.getQuickStartPanel().optionsChanged(optionsParam);
    }

    public ComboBoxModel<String> getUrlModel() {
        return this.getQuickStartPanel().getUrlModel();
    }
}
