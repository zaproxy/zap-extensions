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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Vector;
import javax.swing.ComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JCheckBox;
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
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.callhome.ExtensionCallHome;
import org.zaproxy.addon.callhome.InvalidServiceUrlException;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.zap.extension.ext.ExtensionExtension;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.extension.spider.SpiderScan;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionQuickStart extends ExtensionAdaptor
        implements SessionChangedListener, CommandLineListener, OptionsChangedListener {

    public static final String NAME = "ExtensionQuickStart";
    public static final String RESOURCES = "/org/zaproxy/zap/extension/quickstart/resources";
    public static final ImageIcon ZAP_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(RESOURCES + "/zap64x64.png")));
    public static final ImageIcon HUD_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(
                                    RESOURCES + "/hud_logo_64px.png")));
    public static final ImageIcon HELP_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(QuickStartSubPanel.class.getResource(RESOURCES + "/help.png")));
    public static final ImageIcon ONLINE_DOC_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(
                                    RESOURCES + "/document-globe.png")));
    public static final ImageIcon PDF_DOC_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(
                                    RESOURCES + "/document-pdf-text.png")));

    private static final Logger LOGGER = LogManager.getLogger(ExtensionQuickStart.class);

    private QuickStartPanel quickStartPanel = null;
    private AttackThread attackThread = null;
    private TraditionalSpider traditionalSpider;
    private PlugableSpider plugableSpider;
    private PlugableHud hudProvider;
    private QuickStartParam quickStartParam;

    private CommandLineArgument[] arguments = new CommandLineArgument[3];
    private static final int ARG_QUICK_URL_IDX = 0;
    private static final int ARG_QUICK_OUT_IDX = 1;
    private static final int ARG_QUICK_PROGRESS_IDX = 2;
    private static final String SPIN_CHRS = "|/-\\|/-\\";

    private boolean runningFromCmdLine = false;
    private boolean showProgress = false;
    private int spinner = 0;

    private ExtensionReports extReport;

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(
                    Arrays.asList(ExtensionReports.class, ExtensionNetwork.class));

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

        if (ExtensionSpider.class.getAnnotation(Deprecated.class) == null) {
            setTraditionalSpider(new TraditionalSpiderImpl());
        }

        extensionHook.addOptionsChangedListener(this);
        extensionHook.addOptionsParamSet(getQuickStartParam());

        if (getView() != null) {
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

        new Thread("ZAP-NewsFetcher") {
            @Override
            public void run() {
                // Try to read the news page
                try {
                    ZapXmlConfiguration xmlNews = getNews();
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
        }.start();
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
        if (View.isInitialised()) {
            if (!this.getQuickStartParam().getClearedNewsItem().equals(newsItem.getId())) {
                getQuickStartPanel().announceNews(newsItem);
            }
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
        if (getView() != null) {
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

        getExtReport().generateReport(template, fileName, "OWASP ZAP Report", "", false);
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

    private class TraditionalSpiderImpl implements TraditionalSpider {

        private JCheckBox spiderCheckBox;

        @Override
        public String getLabel() {
            return Constant.messages.getString("quickstart.label.tradspider");
        }

        @Override
        public JCheckBox getComponent() {
            if (spiderCheckBox == null) {
                spiderCheckBox = new JCheckBox();
                spiderCheckBox.setSelected(getQuickStartParam().isTradSpiderEnabled());
                spiderCheckBox.addActionListener(
                        e ->
                                getQuickStartParam()
                                        .setTradSpiderEnabled(spiderCheckBox.isSelected()));
            }
            return spiderCheckBox;
        }

        @Override
        public boolean isSelected() {
            return getComponent().isSelected();
        }

        @Override
        public void setEnabled(boolean enabled) {
            getComponent().setEnabled(enabled);
        }

        @Override
        public Scan startScan(String displayName, Target target) {
            ExtensionSpider extension =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);

            int scanId = extension.startScan(displayName, target, null, null);
            return new ScanImpl(extension.getScan(scanId));
        }
    }

    private static class ScanImpl implements TraditionalSpider.Scan {

        private SpiderScan scan;

        public ScanImpl(SpiderScan scan) {
            this.scan = scan;
        }

        @Override
        public boolean isStopped() {
            return scan.isStopped();
        }

        @Override
        public void stopScan() {
            scan.stopScan();
        }

        @Override
        public int getProgress() {
            return scan.getProgress();
        }
    }
}
