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

import java.awt.Component;
import java.awt.EventQueue;
import java.awt.Frame;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ReportDialog extends StandardFieldsDialog {

    private static final Logger LOGGER = LogManager.getLogger(ReportDialog.class);

    private static final String FIELD_TITLE = "reports.dialog.field.title";
    private static final String FIELD_TEMPLATE = "reports.dialog.field.template";
    private static final String FIELD_REPORT_DIR = "reports.dialog.field.reportdir";
    private static final String FIELD_REPORT_NAME = "reports.dialog.field.reportname";
    private static final String FIELD_DESCRIPTION = "reports.dialog.field.description";
    private static final String FIELD_CONTEXTS = "reports.dialog.field.contexts";
    private static final String FIELD_SITES = "reports.dialog.field.sites";
    private static final String FIELD_GENERATE_ANYWAY = "reports.dialog.field.generateanyway";
    private static final String FIELD_DISPLAY_REPORT = "reports.dialog.field.display";
    private static final String FIELD_TEMPLATE_DIR = "reports.dialog.field.templatedir";
    private static final String FIELD_REPORT_NAME_PATTERN = "reports.dialog.field.namepattern";
    private static final String FIELD_CONFIDENCE_HEADER = "reports.dialog.field.confidence";
    private static final String FIELD_CONFIDENCE_0 = "reports.dialog.field.confidence.0";
    private static final String FIELD_CONFIDENCE_1 = "reports.dialog.field.confidence.1";
    private static final String FIELD_CONFIDENCE_2 = "reports.dialog.field.confidence.2";
    private static final String FIELD_CONFIDENCE_3 = "reports.dialog.field.confidence.3";
    private static final String FIELD_CONFIDENCE_4 = "reports.dialog.field.confidence.4";
    private static final String FIELD_RISK_HEADER = "reports.dialog.field.risk";
    private static final String FIELD_RISK_0 = "reports.dialog.field.risk.0";
    private static final String FIELD_RISK_1 = "reports.dialog.field.risk.1";
    private static final String FIELD_RISK_2 = "reports.dialog.field.risk.2";
    private static final String FIELD_RISK_3 = "reports.dialog.field.risk.3";
    private static final String FIELD_SECTIONS = "reports.dialog.field.sections";
    private static final String FIELD_THEME = "reports.dialog.field.theme";

    private static final String[] TAB_LABELS = {
        "reports.dialog.tab.scope",
        "reports.dialog.tab.template",
        "reports.dialog.tab.filter",
        "reports.dialog.tab.options",
    };

    private static final int TAB_SCOPE = 0;
    private static final int TAB_TEMPLATE = 1;
    private static final int TAB_FILTER = 2;
    private static final int TAB_OPTIONS = 3;

    private static final long serialVersionUID = 1L;

    private ExtensionReports extension = null;
    private JButton[] extraButtons = null;
    private DefaultListModel<Context> contextsModel;

    private JList<Context> contextsSelector;
    private JList<String> sitesSelector;
    private String currentTemplateDir;
    private JScrollPane sectionsPane;
    private Map<String, JCheckBox> sectionsMap;

    public ReportDialog(ExtensionReports ext, Frame owner) {
        super(owner, "reports.dialog.title", DisplayUtils.getScaledDimension(600, 500), TAB_LABELS);

        this.extension = ext;
        // The first time init to the default options set, after that keep own copies
        reset(true);
    }

    public void init() {
        this.removeAllFields();
        // Ensure the contexts and sites get re-read as they may well have changed
        this.contextsModel = null;
        this.contextsSelector = null;
        this.sitesSelector = null;

        ReportParam reportParam = extension.getReportParam();

        // All these first as they are used by other fields
        this.addTextField(
                TAB_OPTIONS, FIELD_REPORT_NAME_PATTERN, reportParam.getReportNamePattern());

        currentTemplateDir = reportParam.getTemplateDirectory();
        this.addFileSelectField(
                TAB_OPTIONS,
                FIELD_TEMPLATE_DIR,
                new File(currentTemplateDir),
                JFileChooser.DIRECTORIES_ONLY,
                null);
        ZapTextField templateDirField = (ZapTextField) this.getField(FIELD_TEMPLATE_DIR);
        templateDirField
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {

                            boolean ignoreEvents = false;

                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                if (ignoreEvents) {
                                    // Will reenter if we reset an invalid directory
                                    return;
                                }
                                String selectedTemplateDir = templateDirField.getText();
                                if (selectedTemplateDir.contentEquals(currentTemplateDir)) {
                                    return;
                                }

                                File file = new File(selectedTemplateDir);

                                EventQueue.invokeLater(
                                        () -> {
                                            if (ExtensionReports.isTemplateDir(file)) {
                                                int templateCount = extension.reloadTemplates(file);
                                                currentTemplateDir = file.getAbsolutePath();
                                                reportParam.setTemplateDirectory(
                                                        currentTemplateDir);
                                                reset();
                                                View.getSingleton()
                                                        .showMessageDialog(
                                                                ReportDialog.this,
                                                                Constant.messages.getString(
                                                                        "reports.dialog.info.reloadtemplates",
                                                                        templateCount,
                                                                        currentTemplateDir));
                                            } else if (ExtensionReports.isTemplateDir(
                                                    new File(currentTemplateDir))) {
                                                // Existing one ok, go back to it
                                                View.getSingleton()
                                                        .showWarningDialog(
                                                                ReportDialog.this,
                                                                Constant.messages.getString(
                                                                        "reports.dialog.error.notemplates"));
                                                ignoreEvents = true;
                                                templateDirField.setText(currentTemplateDir);
                                                ignoreEvents = false;
                                            } else {
                                                // Existing one bad, use default
                                                currentTemplateDir =
                                                        ReportParam.DEFAULT_TEMPLATES_DIR;
                                                extension.reloadTemplates(
                                                        new File(currentTemplateDir));
                                                reportParam.setTemplateDirectory(
                                                        currentTemplateDir);
                                                reset();
                                                View.getSingleton()
                                                        .showWarningDialog(
                                                                ReportDialog.this,
                                                                Constant.messages.getString(
                                                                        "reports.dialog.error.badtemplates",
                                                                        currentTemplateDir));
                                            }
                                        });
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                // Ignore
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                // Ignore
                            }
                        });

        this.addPadding(TAB_OPTIONS);

        this.addTextField(TAB_SCOPE, FIELD_TITLE, reportParam.getTitle());

        this.addTextField(TAB_SCOPE, FIELD_REPORT_NAME, "");
        this.addFileSelectField(
                TAB_SCOPE,
                FIELD_REPORT_DIR,
                new File(reportParam.getReportDirectory()),
                JFileChooser.DIRECTORIES_ONLY,
                null);
        this.addMultilineField(TAB_SCOPE, FIELD_DESCRIPTION, reportParam.getDescription());
        this.addCustomComponent(
                TAB_SCOPE, FIELD_CONTEXTS, getNewJScrollPane(getContextsSelector(), 400, 50));
        this.addCustomComponent(
                TAB_SCOPE, FIELD_SITES, getNewJScrollPane(getSitesSelector(), 400, 100));
        this.addCheckBoxField(TAB_SCOPE, FIELD_GENERATE_ANYWAY, false);
        this.addCheckBoxField(TAB_SCOPE, FIELD_DISPLAY_REPORT, reportParam.isDisplayReport());

        Template defaultTemplate = extension.getTemplateByConfigName(reportParam.getTemplate());
        List<String> templates = extension.getTemplateNames();
        Collections.sort(templates);
        this.addComboField(
                TAB_TEMPLATE,
                FIELD_TEMPLATE,
                templates,
                defaultTemplate != null ? defaultTemplate.getDisplayName() : null);

        List<String> themes = new ArrayList<>();
        if (defaultTemplate != null) {
            themes = defaultTemplate.getThemeNames();
        }

        this.addComboField(TAB_TEMPLATE, FIELD_THEME, themes, null);

        this.addCustomComponent(TAB_TEMPLATE, FIELD_SECTIONS, getSectionsScrollPane());
        resetTemplateFields();
        this.addPadding(TAB_TEMPLATE);

        setReportName();
        ((JComboBox<?>) this.getField(FIELD_TEMPLATE))
                .addActionListener(
                        e -> {
                            setReportName();
                            resetTemplateFields();
                        });
        getSitesSelector().addListSelectionListener(e -> setReportName());

        this.addTextFieldReadOnly(TAB_FILTER, FIELD_RISK_HEADER, "");
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_3, reportParam.isIncRisk3());
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_2, reportParam.isIncRisk2());
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_1, reportParam.isIncRisk1());
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_0, reportParam.isIncRisk0());

        this.addTextFieldReadOnly(TAB_FILTER, FIELD_CONFIDENCE_HEADER, "");
        this.addCheckBoxField(TAB_FILTER, FIELD_CONFIDENCE_4, reportParam.isIncConfidence4());
        this.addCheckBoxField(TAB_FILTER, FIELD_CONFIDENCE_3, reportParam.isIncConfidence3());
        this.addCheckBoxField(TAB_FILTER, FIELD_CONFIDENCE_2, reportParam.isIncConfidence2());
        this.addCheckBoxField(TAB_FILTER, FIELD_CONFIDENCE_1, reportParam.isIncConfidence1());
        this.addCheckBoxField(TAB_FILTER, FIELD_CONFIDENCE_0, reportParam.isIncConfidence0());
        this.addPadding(TAB_FILTER);

        this.pack();
    }

    private JScrollPane getSectionsScrollPane() {
        if (sectionsPane == null) {
            sectionsPane = new JScrollPane();
        }
        return sectionsPane;
    }

    @SuppressWarnings("unchecked")
    private void resetTemplateFields() {
        JPanel sectionPanel = new JPanel();
        sectionPanel.setLayout(new BoxLayout(sectionPanel, BoxLayout.Y_AXIS));

        Template template = extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE));
        if (template != null) {
            JComboBox<String> themeCombo = ((JComboBox<String>) this.getField(FIELD_THEME));
            themeCombo.removeAllItems();
            for (String theme : template.getThemeNames()) {
                themeCombo.addItem(theme);
            }
            if (template.getThemeNames().size() > 0) {
                String defaultTheme = extension.getReportParam().getTheme(template.getConfigName());
                if (defaultTheme != null) {
                    themeCombo.setSelectedItem(template.getThemeName(defaultTheme));
                } else {
                    themeCombo.setSelectedIndex(0);
                }
            }

            List<String> sections = template.getSections();
            sectionsMap = new HashMap<>();
            if (sections.isEmpty()) {
                sectionPanel.add(
                        new JLabel(
                                Constant.messages.getString("reports.dialog.field.sections.none")));
            } else {
                List<Object> sectionList =
                        extension.getReportParam().getSections(template.getConfigName());
                for (String section : sections) {
                    JCheckBox cb =
                            new JCheckBox(
                                    template.getI18nString(
                                            "report.template.section." + section, null));
                    cb.setSelected(
                            sectionList == null
                                    || sectionList.isEmpty()
                                    || sectionList.contains(section));
                    sectionsMap.put(section, cb);
                    sectionPanel.add(cb);
                }
            }
        }
        getSectionsScrollPane().setViewportView(sectionPanel);
    }

    private void setReportName() {
        String pattern = this.getStringValue(FIELD_REPORT_NAME_PATTERN);
        String name =
                ExtensionReports.getNameFromPattern(pattern, getSitesSelector().getSelectedValue());
        Template template = extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE));
        if (template != null) {
            ((ZapTextField) this.getField(FIELD_REPORT_NAME))
                    .setText(name + "." + template.getExtension());
        }
    }

    private JScrollPane getNewJScrollPane(Component view, int width, int height) {
        JScrollPane pane = new JScrollPane(view);
        pane.setPreferredSize(DisplayUtils.getScaledDimension(width, height));
        pane.setMinimumSize((DisplayUtils.getScaledDimension(width, height)));
        return pane;
    }

    private DefaultListModel<Context> getContextsModel() {
        if (contextsModel == null) {
            contextsModel = new DefaultListModel<>();
            for (Context context : Model.getSingleton().getSession().getContexts()) {
                contextsModel.addElement(context);
            }
        }
        return contextsModel;
    }

    private JList<Context> getContextsSelector() {
        if (contextsSelector == null) {
            contextsSelector = new JList<>(getContextsModel());
            contextsSelector.setCellRenderer(
                    new DefaultListCellRenderer() {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public Component getListCellRendererComponent(
                                JList<?> list,
                                Object value,
                                int index,
                                boolean isSelected,
                                boolean cellHasFocus) {
                            JLabel label =
                                    (JLabel)
                                            super.getListCellRendererComponent(
                                                    list, value, index, isSelected, cellHasFocus);
                            if (value instanceof Context) {
                                label.setText(((Context) value).getName());
                            }
                            return label;
                        }
                    });
        }
        return contextsSelector;
    }

    private JList<String> getSitesSelector() {
        if (sitesSelector == null) {
            List<String> list = ExtensionReports.getSites();
            String[] arr = new String[list.size()];
            list.toArray(arr);
            sitesSelector = new JList<String>(arr);
        }
        return sitesSelector;
    }

    @Override
    public String getHelpIndex() {
        return "reports";
    }

    private void reset(boolean refreshUi) {

        if (refreshUi) {
            init();
            repaint();
        }
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("reports.dialog.button.generate");
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton resetButton =
                    new JButton(Constant.messages.getString("reports.dialog.button.reset"));
            resetButton.addActionListener(e -> reset(true));

            extraButtons = new JButton[] {resetButton};
        }

        return extraButtons;
    }

    private ReportData getReportData(Template template) {
        ReportData reportData = new ReportData();
        reportData.setTitle(this.getStringValue(FIELD_TITLE));
        reportData.setDescription(this.getStringValue(FIELD_DESCRIPTION));
        reportData.setContexts(this.getContextsSelector().getSelectedValuesList());
        reportData.setSites(this.getSitesSelector().getSelectedValuesList());
        reportData.setTheme(template.getThemeForName(getStringValue(FIELD_THEME)));
        if (reportData.getSites().isEmpty()) {
            // None selected so add all
            reportData.setSites(ExtensionReports.getSites());
        }
        reportData.setIncludeConfidence(0, this.getBoolValue(FIELD_CONFIDENCE_0));
        reportData.setIncludeConfidence(1, this.getBoolValue(FIELD_CONFIDENCE_1));
        reportData.setIncludeConfidence(2, this.getBoolValue(FIELD_CONFIDENCE_2));
        reportData.setIncludeConfidence(3, this.getBoolValue(FIELD_CONFIDENCE_3));
        reportData.setIncludeConfidence(4, this.getBoolValue(FIELD_CONFIDENCE_4));
        reportData.setIncludeRisk(0, this.getBoolValue(FIELD_RISK_0));
        reportData.setIncludeRisk(1, this.getBoolValue(FIELD_RISK_1));
        reportData.setIncludeRisk(2, this.getBoolValue(FIELD_RISK_2));
        reportData.setIncludeRisk(3, this.getBoolValue(FIELD_RISK_3));

        for (Entry<String, JCheckBox> entry : sectionsMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                reportData.addSection(entry.getKey());
            }
        }

        // Always do this last as it depends on the other fields
        reportData.setAlertTreeRootNode(extension.getFilteredAlertTree(reportData));
        return reportData;
    }

    @Override
    public void save() {
        boolean displayReport = this.getBoolValue(FIELD_DISPLAY_REPORT);
        Template template = extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE));
        ReportData reportData = getReportData(template);

        // Always save all of the options
        ReportParam reportParam = extension.getReportParam();
        reportParam.setDisplayReport(displayReport);
        reportParam.setTitle(reportData.getTitle());
        reportParam.setDescription(reportData.getDescription());
        reportParam.setTemplate(template.getConfigName());
        reportParam.setTheme(
                template.getConfigName(),
                template.getThemeForName(this.getStringValue(FIELD_THEME)));
        reportParam.setReportDirectory(this.getStringValue(FIELD_REPORT_DIR));
        reportParam.setTemplateDirectory(this.getStringValue(FIELD_TEMPLATE_DIR));
        reportParam.setReportNamePattern(this.getStringValue(FIELD_REPORT_NAME_PATTERN));
        reportParam.setIncConfidence0(this.getBoolValue(FIELD_CONFIDENCE_0));
        reportParam.setIncConfidence1(this.getBoolValue(FIELD_CONFIDENCE_1));
        reportParam.setIncConfidence2(this.getBoolValue(FIELD_CONFIDENCE_2));
        reportParam.setIncConfidence3(this.getBoolValue(FIELD_CONFIDENCE_3));
        reportParam.setIncConfidence4(this.getBoolValue(FIELD_CONFIDENCE_4));
        reportParam.setIncRisk0(this.getBoolValue(FIELD_RISK_0));
        reportParam.setIncRisk1(this.getBoolValue(FIELD_RISK_1));
        reportParam.setIncRisk2(this.getBoolValue(FIELD_RISK_2));
        reportParam.setIncRisk3(this.getBoolValue(FIELD_RISK_3));

        extension.getReportParam().setSections(template.getConfigName(), reportData.getSections());

        try {
            reportParam.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save Reports configuration", e);
        }

        try {
            this.extension.generateReport(
                    reportData, template, getReportFile().getAbsolutePath(), displayReport);

        } catch (Exception e) {
            View.getSingleton()
                    .showWarningDialog(
                            thisDialog,
                            Constant.messages.getString(
                                    "reports.dialog.error.generate", e.getMessage()));
            LOGGER.error(
                    "Failed to generate a report using template {}",
                    extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE)),
                    e);
        }
    }

    private File getReportFile() {
        return new File(
                this.getStringValue(FIELD_REPORT_DIR), this.getStringValue(FIELD_REPORT_NAME));
    }

    @Override
    public void setVisible(boolean show) {
        super.setVisible(show);
    }

    @Override
    public String validateFields() {
        Template template = extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE));
        if (template == null) {
            return Constant.messages.getString("reports.dialog.error.notemplate");
        }

        File f = getReportFile();
        if (!f.exists()) {
            if (!f.getParentFile().canWrite()) {
                return Constant.messages.getString(
                        "reports.dialog.error.dirperms", f.getParentFile().getAbsolutePath());
            }
        } else if (!f.canWrite()) {
            return Constant.messages.getString(
                    "reports.dialog.error.fileperms", f.getAbsolutePath());
        }
        ReportData reportData = getReportData(template);
        AlertNode root = extension.getFilteredAlertTree(reportData);
        if (root.getChildCount() == 0 && !this.getBoolValue(FIELD_GENERATE_ANYWAY)) {
            return Constant.messages.getString("reports.dialog.error.noalerts");
        }
        if (sectionsMap.size() > 0 && reportData.getSections().isEmpty()) {
            return Constant.messages.getString("reports.dialog.error.nosections");
        }

        return null;
    }

    void reset() {
        reset(true);
    }
}
