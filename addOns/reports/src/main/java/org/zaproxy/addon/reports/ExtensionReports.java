/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import com.lowagie.text.DocumentException;
import java.awt.Desktop;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.tree.DefaultTreeModel;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.FileTemplateResolver;
import org.xhtmlrenderer.pdf.ITextRenderer;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionReports extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionReports";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionReports.class);

    // The i18n prefix
    public static final String PREFIX = "reports";

    public static final String TEMPLATE_DEFN_FILENAME = "template.yaml";

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/reports/resources/";

    private static final ImageIcon REPORT_ICON =
            new ImageIcon(ExtensionReports.class.getResource(RESOURCES_DIR + "report.png"));

    private static final String SITE_PATTERN = "[[site]]";
    private static final String DATETIME_REGEX = "\\{\\{(.*)\\}\\}";
    private static final Pattern DATETIME_PATTERN = Pattern.compile(DATETIME_REGEX);
    private static final SimpleDateFormat SIMPLE_DATE_FORMAT =
            new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss");
    static final int RISK_FALSE_POSITIVE = -1;

    private ZapMenuItem reportMenu;
    private JButton reportButton;
    private ReportDialog reportDialog;
    private Map<String, Template> templateMap;
    private ReportParam reportParam;

    private ReportDataHandler reportDataHandler;

    public ExtensionReports() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getReportParam());
        extensionHook.addApiImplementor(new ReportApi(this));

        if (getView() != null) {
            extensionHook.getHookMenu().addReportMenuItem(getReportMenu());
            extensionHook.getHookView().addMainToolBarComponent(getReportButton());
        }
    }

    public ReportParam getReportParam() {
        if (reportParam == null) {
            reportParam = new ReportParam();
        }
        return reportParam;
    }

    private void unloadTemplates() {
        this.getTemplateMap().values().forEach(Template::unload);
    }

    @Override
    public void unload() {
        this.unloadTemplates();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private JButton getReportButton() {
        if (reportButton == null) {
            reportButton = new JButton();
            reportButton.setIcon(REPORT_ICON);
            reportButton.setToolTipText(
                    Constant.messages.getString("reports.toolbar.button.genreport"));
            reportButton.addActionListener(
                    e -> {
                        getReportDialog().init();
                        getReportDialog().setVisible(true);
                    });
        }
        return reportButton;
    }

    private ZapMenuItem getReportMenu() {
        if (reportMenu == null) {
            reportMenu = new ZapMenuItem(PREFIX + ".topmenu.reports.title");
            reportMenu.addActionListener(
                    e -> {
                        getReportDialog().init();
                        getReportDialog().setVisible(true);
                    });
        }
        return reportMenu;
    }

    private ReportDialog getReportDialog() {
        if (reportDialog == null) {
            reportDialog = new ReportDialog(this, View.getSingleton().getMainFrame());
        }
        return reportDialog;
    }

    protected AlertNode cloneAlertNode(AlertNode alertNode) {
        AlertNode clone = (AlertNode) alertNode.clone();
        if (alertNode.getUserObject() != null) {
            clone.setUserObject(alertNode.getUserObject());
        }
        return clone;
    }

    public static List<String> getSites() {
        List<String> list = new ArrayList<>();
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = siteMap.getRoot();
        if (root.getChildCount() > 0) {
            SiteNode child = (SiteNode) root.getFirstChild();
            while (child != null) {
                list.add(child.getName());
                child = (SiteNode) root.getChildAfter(child);
            }
        }
        return list;
    }

    public static boolean isIncluded(ReportData reportData, AlertNode alertNode) {
        Alert alert = alertNode.getUserObject();
        if (alert == null) {
            return false;
        }
        String uri = alert.getUri();
        // Filter by contexts
        List<org.zaproxy.zap.model.Context> contexts = reportData.getContexts();
        boolean include = true;
        if (contexts != null && contexts.size() > 0) {
            include = false;
            for (org.zaproxy.zap.model.Context context : contexts) {
                if (context.isIncluded(uri)) {
                    include = true;
                    break;
                }
            }
        }
        if (!include) {
            return false;
        }
        // Filter by sites
        List<String> sites = reportData.getSites();
        include = true;
        if (sites != null && sites.size() > 0) {
            include = false;
            for (String site : sites) {
                if (uri.startsWith(site)) {
                    include = true;
                    break;
                }
            }
        }
        if (!include) {
            return false;
        }
        if (!reportData.isIncludeConfidence(alert.getConfidence())) {
            return false;
        }
        if (!reportData.isIncludeRisk(alert.getRisk())) {
            return false;
        }
        return true;
    }

    public AlertNode getRootAlertNode()
            throws NoSuchMethodException, SecurityException, IllegalAccessException,
                    IllegalArgumentException, InvocationTargetException {
        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);

        Method treeModelMethod = extAlert.getClass().getDeclaredMethod("getTreeModel");
        treeModelMethod.setAccessible(true);

        DefaultTreeModel treeModel = (DefaultTreeModel) treeModelMethod.invoke(extAlert);

        return (AlertNode) treeModel.getRoot();
    }

    public AlertNode getFilteredAlertTree(ReportData reportData) {

        AlertNode root = null;

        try {
            root = getRootAlertNode();

            AlertNode filteredRoot = cloneAlertNode(root);
            AlertNode child;
            AlertNode instance;
            AlertNode filteredChild;
            if (root.getChildCount() > 0) {
                // Loop through the top level alert nodes, adding them to start with
                child = (AlertNode) root.getFirstChild();
                while (child != null) {
                    filteredChild = cloneAlertNode(child);
                    if (child.getChildCount() > 0) {
                        instance = (AlertNode) child.getFirstChild();
                        while (instance != null) {
                            if (isIncluded(reportData, instance)) {
                                filteredChild.add(cloneAlertNode(instance));
                            }
                            instance = (AlertNode) child.getChildAfter(instance);
                        }
                    }
                    if (filteredChild.getChildCount() > 0) {
                        filteredRoot.add(filteredChild);
                    }
                    child = (AlertNode) root.getChildAfter(child);
                }
            }
            root = filteredRoot;
        } catch (Exception e) {
            LOGGER.error("Failed to access alerts tree", e);
        }

        return root;
    }

    /**
     * Generate a report (default theme, all sites, all alerts)
     *
     * @param templateName the name of the template, e.g. traditional-html
     * @param reportFilename the full path of the file the report will be written to
     * @param title the title to be used in the report
     * @param display true if the report should be displayed using the default application
     * @return the file the report was written to
     * @throws IOException
     */
    public File generateReport(
            String templateName,
            String reportFilename,
            String title,
            String description,
            boolean display)
            throws IOException {
        return this.generateReport(
                templateName, reportFilename, title, description, display, null, getSites(), null);
    }

    /**
     * Generate a report (all alerts)
     *
     * @param templateName the name of the template, e.g. traditional-html
     * @param reportFilename the full path of the file the report will be written to
     * @param title the title to be used in the report
     * @param display true if the report should be displayed using the default application
     * @param theme the theme to be used
     * @param sites a list of the sites to include
     * @param contexts a list of the contexts to include
     * @return the file the report was written to
     * @throws IOException
     */
    public File generateReport(
            String templateName,
            String reportFilename,
            String title,
            String description,
            boolean display,
            String theme,
            List<String> sites,
            List<org.zaproxy.zap.model.Context> contexts)
            throws IOException {
        Template template = this.getTemplateByConfigName(templateName);
        if (template == null) {
            throw new IllegalArgumentException("Unknown template: " + templateName);
        }
        ReportData reportData = new ReportData();
        reportData.setTitle(title);
        reportData.setDescription(description);
        reportData.setSites(sites);
        reportData.setContexts(contexts);
        reportData.setTheme(theme);
        reportData.setSections(template.getSections());
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.setAlertTreeRootNode(getFilteredAlertTree(reportData));

        return this.generateReport(reportData, template, reportFilename, display);
    }

    public File generateReport(
            ReportData reportData, Template template, String reportFilename, boolean display)
            throws IOException {
        try {
            TemplateEngine templateEngine = new TemplateEngine();
            FileTemplateResolver templateResolver = new FileTemplateResolver();
            templateResolver.setTemplateMode(template.getMode());
            templateEngine.setTemplateResolver(templateResolver);

            templateEngine.setMessageResolver(new ReportMessageResolver(template));

            Context context = new Context();
            context.setVariable("alertTree", reportData.getAlertTreeRootNode());
            context.setVariable("reportTitle", reportData.getTitle());
            context.setVariable("description", reportData.getDescription());
            context.setVariable("helper", new ReportHelper());
            context.setVariable(
                    "alertCounts", getAlertCountsByRisk(reportData.getAlertTreeRootNode()));
            context.setVariable(
                    "alertCountsByRule", getAlertCountsByRule(reportData.getAlertTreeRootNode()));
            context.setVariable("reportData", reportData);

            ExtensionStats extStats =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionStats.class);
            if (extStats != null) {
                InMemoryStats stats = extStats.getInMemoryStats();
                if (stats != null) {
                    context.setVariable("stats", stats.getStats(""));
                }
            }

            synchronized (SIMPLE_DATE_FORMAT) {
                context.setVariable(
                        "generatedString", SIMPLE_DATE_FORMAT.format(System.currentTimeMillis()));
            }
            context.setVariable("zapVersion", Constant.PROGRAM_VERSION);

            if (reportDataHandler != null) {
                reportDataHandler.handle(reportData);
            }

            if ("PDF".equals(template.getFormat())) {
                if (reportFilename.toLowerCase().endsWith(".pdf")) {
                    reportFilename = reportFilename.substring(0, reportFilename.length() - 4);
                }
                reportFilename += ".html";
            }

            // Handle any resources
            File resourcesDir = template.getResourcesDir();
            if (resourcesDir.exists()) {
                String subDirName;
                int dotIndex = reportFilename.lastIndexOf(".");
                if (dotIndex > 0) {
                    subDirName = reportFilename.substring(0, dotIndex);
                } else {
                    subDirName = reportFilename + "_d";
                }
                File subDir = new File(subDirName);
                int i = 1;
                while (subDir.exists()) {
                    i += 1;
                    subDir = new File(subDirName + i);
                }
                LOGGER.debug(
                        "Copying resources from {} to {}",
                        resourcesDir.getAbsolutePath(),
                        subDir.getAbsolutePath());
                FileUtils.copyDirectory(resourcesDir, subDir);
                context.setVariable("resources", subDir.getName());
            }

            File file = new File(reportFilename);
            try (Writer writer = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
                templateEngine.process(
                        template.getReportTemplateFile().getAbsolutePath(), context, writer);
                Stats.incCounter("stats.reports.generated." + template.getConfigName());
            }

            if ("PDF".equals(template.getFormat())) {
                // Will have appended ".html" above
                reportFilename = reportFilename.substring(0, reportFilename.length() - 5);
                reportFilename += ".pdf";
                File pdfFile = new File(reportFilename);
                try (OutputStream outputStream = new FileOutputStream(pdfFile)) {
                    ITextRenderer renderer = new ITextRenderer();
                    renderer.setDocument(file);
                    renderer.layout();
                    try {
                        renderer.createPDF(outputStream);
                    } catch (DocumentException e) {
                        // Throw a standard exception so that add-ons using this method don't need
                        // to
                        // import it
                        throw new IOException("Invalid template: " + template.getConfigName(), e);
                    }
                }
                if (!file.delete()) {
                    LOGGER.debug("Failed to delete interim report {}", file.getAbsolutePath());
                }
                file = pdfFile;
            }

            LOGGER.debug("Generated report {}", file.getAbsolutePath());
            if (display) {
                if ("HTML".equals(template.getFormat())) {
                    DesktopUtils.openUrlInBrowser(file.toURI());
                } else {
                    Desktop desktop = Desktop.getDesktop();
                    desktop.open(file);
                }
            }
            return file;
        } catch (FileNotFoundException e) {
            Stats.incCounter("stats.reports.nofile." + template.getConfigName());
            throw e;
        } catch (IOException e) {
            Stats.incCounter("stats.reports.error." + template.getConfigName());
            throw e;
        }
    }

    public void setReportDataHandler(ReportDataHandler reportDataHandler) {
        this.reportDataHandler = reportDataHandler;
    }

    public interface ReportDataHandler {
        void handle(ReportData reportData);
    }

    private Map<Integer, Integer> getAlertCountsByRisk(AlertNode rootNode) {
        Map<Integer, Integer> alertCounts = new HashMap<>();
        Enumeration<?> childEnum = rootNode.children();
        while (childEnum.hasMoreElements()) {
            AlertNode child = (AlertNode) childEnum.nextElement();
            alertCounts.merge(child.getRisk(), 1, Integer::sum);
        }

        return alertCounts;
    }

    public List<HttpMessage> getHttpMessagesForRule(int ruleId, int max) {
        try {
            return getHttpMessagesForRule(this.getRootAlertNode(), ruleId, max);
        } catch (Exception e) {
            LOGGER.error("Failed to get HttpMessages for rule Id " + ruleId, e);
        }
        return new ArrayList<>();
    }

    List<HttpMessage> getHttpMessagesForRule(AlertNode rootNode, int ruleId, int max) {
        List<HttpMessage> list = new ArrayList<>();

        Enumeration<?> alertEnum = rootNode.children();
        while (alertEnum.hasMoreElements()) {
            AlertNode alertNode = (AlertNode) alertEnum.nextElement();
            if (alertNode.getUserObject().getPluginId() == ruleId) {
                Enumeration<?> instEnum = alertNode.children();
                while (instEnum.hasMoreElements() && list.size() < max) {
                    AlertNode instNode = (AlertNode) instEnum.nextElement();
                    if (instNode.getRisk() != RISK_FALSE_POSITIVE) {
                        list.add(instNode.getUserObject().getMessage());
                    }
                }
            }
        }

        return list;
    }

    public Map<Integer, Integer> getAlertCountsByRule() {
        try {
            return this.getAlertCountsByRule(this.getRootAlertNode());
        } catch (Exception e) {
            LOGGER.error("Failed to access alerts tree", e);
        }
        return new HashMap<>();
    }

    Map<Integer, Integer> getAlertCountsByRule(AlertNode rootNode) {
        Map<Integer, Integer> alertCounts = new HashMap<>();
        Enumeration<?> childEnum = rootNode.children();
        while (childEnum.hasMoreElements()) {
            AlertNode child = (AlertNode) childEnum.nextElement();
            if (child.getRisk() != RISK_FALSE_POSITIVE) {
                alertCounts.merge(
                        child.getUserObject().getPluginId(), child.getChildCount(), Integer::sum);
            }
        }

        return alertCounts;
    }

    public static boolean isTemplateDir(File dir) {
        if (!dir.isDirectory()) {
            return false;
        }
        File templateYaml;
        for (File file : dir.listFiles()) {
            if (file.isDirectory()) {
                templateYaml = new File(file, TEMPLATE_DEFN_FILENAME);
                if (templateYaml.exists() && templateYaml.canRead()) {
                    return true;
                }
            }
        }
        return false;
    }

    public int reloadTemplates(File templateDir) {
        this.unloadTemplates();
        return loadTemplateDir(templateDir);
    }

    private int loadTemplateDir(File dir) {
        templateMap = new HashMap<>();
        File templateYaml;
        Template template;
        for (File file : dir.listFiles()) {
            if (file.isDirectory()) {
                templateYaml = new File(file, TEMPLATE_DEFN_FILENAME);
                if (templateYaml.exists() && templateYaml.canRead()) {
                    try {
                        template = new Template(templateYaml);
                        templateMap.put(template.getDisplayName(), template);
                    } catch (IOException e) {
                        LOGGER.error(
                                "Failed to access template definition {}",
                                templateYaml.getAbsolutePath());
                    }
                }
            }
        }
        return templateMap.size();
    }

    private Map<String, Template> getTemplateMap() {
        if (templateMap == null) {
            loadTemplateDir(new File(this.getReportParam().getTemplateDirectory()));
        }
        return templateMap;
    }

    public List<Template> getTemplates() {
        return new ArrayList<>(getTemplateMap().values());
    }

    public List<String> getTemplateNames() {
        return this.getTemplateMap().values().stream()
                .map(Template::getDisplayName)
                .collect(Collectors.toList());
    }

    public Template getTemplateByDisplayName(String name) {
        return this.getTemplateMap().get(name);
    }

    public Template getTemplateByConfigName(String name) {
        for (Template template : this.getTemplateMap().values()) {
            if (template.getConfigName().equals(name)) {
                return template;
            }
        }
        return null;
    }

    public static String getNameFromPattern(String pattern, String site) {
        return getNameFromPattern(pattern, site, new Date());
    }

    public static String getNameFromPattern(String pattern, String site, Date date) {
        String name = pattern;
        if (site == null) {
            site = "";
        } else {
            // remove anything that could cause problems with file name
            int i = site.indexOf("//");
            if (i >= 0) {
                site = site.substring(i + 2);
            }
            i = site.indexOf(":");
            if (i >= 0) {
                site = site.substring(0, i);
            }
            i = site.indexOf("/");
            if (i >= 0) {
                site = site.substring(0, i);
            }
        }
        while (name.contains(SITE_PATTERN)) {
            name = name.replace(SITE_PATTERN, site);
        }
        StringBuilder sb = new StringBuilder();
        int lastIndex = 0;
        Matcher matcher = DATETIME_PATTERN.matcher(name);
        while (matcher.find() && matcher.groupCount() > 0) {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(matcher.group(1));

            sb.append(name, lastIndex, matcher.start()).append(simpleDateFormat.format(date));

            lastIndex = matcher.end();
        }
        if (lastIndex < name.length()) {
            sb.append(name, lastIndex, name.length());
        }
        return sb.toString();
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }
}
