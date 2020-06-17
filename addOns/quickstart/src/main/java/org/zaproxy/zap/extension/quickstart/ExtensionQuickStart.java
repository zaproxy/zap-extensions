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
import java.io.BufferedWriter;
import java.io.File;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Vector;
import javax.swing.ComboBoxModel;
import javax.swing.ImageIcon;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.report.ReportLastScan;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.Version;
import org.zaproxy.zap.extension.ext.ExtensionExtension;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionQuickStart extends ExtensionAdaptor
        implements SessionChangedListener, CommandLineListener, OptionsChangedListener {

    public static final String NAME = "ExtensionQuickStart";
    public static final String RESOURCES = "/org/zaproxy/zap/extension/quickstart/resources";
    public static ImageIcon ZAP_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(RESOURCES + "/zap64x64.png")));
    public static ImageIcon HUD_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(
                                    RESOURCES + "/hud_logo_64px.png")));
    public static ImageIcon HELP_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(QuickStartSubPanel.class.getResource(RESOURCES + "/help.png")));
    public static ImageIcon ONLINE_DOC_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(
                                    RESOURCES + "/document-globe.png")));
    public static ImageIcon PDF_DOC_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            QuickStartSubPanel.class.getResource(
                                    RESOURCES + "/document-pdf-text.png")));

    private static final String DEFAULT_NEWS_PAGE_URL_PREFIX = "https://bit.ly/owaspzap-news-";
    private static final String DEV_NEWS_PAGE = "dev";

    private static final Logger LOGGER = Logger.getLogger(ExtensionQuickStart.class);

    private QuickStartPanel quickStartPanel = null;
    private AttackThread attackThread = null;
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

    public ExtensionQuickStart() {
        super(NAME);
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

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();
        if (View.isInitialised()) {
            getQuickStartPanel().optionsLoaded(this.getQuickStartParam());
        }

        // Check for silent mode - only available in 2.8.0 so must use reflection for now
        try {
            Method isSilentMethod = Constant.class.getMethod("isSilent");
            Object res = isSilentMethod.invoke(null);
            if (res instanceof Boolean) {
                if ((Boolean) res) {
                    LOGGER.info("Shh! No check-for-news - silent mode enabled");
                    return;
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        new Thread("ZAP-NewsFetcher") {
            @Override
            public void run() {
                // Try to read the news page
                HttpMessage msg;
                String newsPageUrl = getNewsPageURL();
                try {
                    HttpSender httpSender =
                            new HttpSender(
                                    Model.getSingleton().getOptionsParam().getConnectionParam(),
                                    true,
                                    HttpSender.CHECK_FOR_UPDATES_INITIATOR);
                    httpSender.setFollowRedirect(true);
                    msg = new HttpMessage(new URI(newsPageUrl, true));
                    httpSender.sendAndReceive(msg, true);
                    if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
                        String zapLocale = Constant.getLocale().toString();

                        // Safely parse the XML
                        ZapXmlConfiguration xmlNews = new ZapXmlConfiguration();
                        xmlNews.load(new StringReader(msg.getResponseBody().toString()));

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
                                                            getFirstChildNodeString(
                                                                    localeNode, "link"),
                                                            true)));
                                }
                            }
                        }

                    } else {
                        LOGGER.debug(
                                "Response from "
                                        + newsPageUrl
                                        + " : "
                                        + msg.getResponseHeader().getStatusCode());
                    }
                } catch (Exception e) {
                    LOGGER.debug("Failed to read from " + newsPageUrl + " : " + e.getMessage(), e);
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

    private String getNewsPageURL() {
        String page = DEV_NEWS_PAGE;
        if (!Constant.isDevBuild() && !Constant.isDailyBuild()) {
            // Converts the ZAP version to something like 2-8
            try {
                Version zapVersion = new Version(Constant.PROGRAM_VERSION);
                page = zapVersion.getMajorVersion() + "-" + zapVersion.getMinorVersion();
            } catch (IllegalArgumentException e) {
                LOGGER.error("Failed to parse ZAP version " + Constant.PROGRAM_VERSION, e);
            }
        }

        return DEFAULT_NEWS_PAGE_URL_PREFIX + page;
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

    private void saveReportTo(Path file) throws Exception {
        try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
            writer.write(getScanReport());
        }
    }

    private String getScanReport() throws Exception {
        ReportLastScan report = new ReportLastScan();
        StringBuilder rpt = new StringBuilder();
        report.generate(rpt);
        return rpt.toString();
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_QUICK_URL_IDX] =
                new CommandLineArgument(
                        "-quickurl",
                        1,
                        null,
                        "",
                        "-quickurl [target url]: "
                                + Constant.messages.getString("quickstart.cmdline.url.help"));
        arguments[ARG_QUICK_OUT_IDX] =
                new CommandLineArgument(
                        "-quickout",
                        1,
                        null,
                        "",
                        "-quickout [output filename]: "
                                + Constant.messages.getString("quickstart.cmdline.out.help"));
        arguments[ARG_QUICK_PROGRESS_IDX] =
                new CommandLineArgument(
                        "-quickprogress",
                        0,
                        null,
                        "",
                        "-quickprogress: "
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
                saveReportTo(file);
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
                saveReportTo(file);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void handleNoSavedReport() {
            try {
                // Just output to stdout
                System.out.println(getScanReport());
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
