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
package org.zaproxy.addon.reports.automation;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.apache.commons.lang.WordUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportParam;
import org.zaproxy.addon.reports.Template;
import org.zaproxy.addon.reports.automation.ReportJob.Parameters;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ReportJobDialog extends StandardFieldsDialog {

    private static final String FIELD_NAME = "reports.automation.dialog.field.name";
    private static final String FIELD_TITLE = "reports.dialog.field.title";
    private static final String FIELD_TEMPLATE = "reports.dialog.field.template";
    private static final String FIELD_REPORT_DIR = "reports.dialog.field.reportdir";
    private static final String FIELD_REPORT_NAME = "reports.dialog.field.reportname";
    private static final String FIELD_DESCRIPTION = "reports.dialog.field.description";
    private static final String FIELD_DISPLAY_REPORT = "reports.dialog.field.display";
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
        "reports.dialog.tab.scope", "reports.dialog.tab.template", "reports.dialog.tab.filter"
    };

    private static final int TAB_SCOPE = 0;
    private static final int TAB_TEMPLATE = 1;
    private static final int TAB_FILTER = 2;

    private static final long serialVersionUID = 1L;

    private static final String VARIABLE_TOKEN = "${";

    private ExtensionReports extension = null;
    private ReportJob job;

    private JScrollPane sectionsPane;
    private Map<String, JCheckBox> sectionsMap;

    public ReportJobDialog(ReportJob job) {
        super(
                View.getSingleton().getMainFrame(),
                "reports.automation.dialog.title",
                DisplayUtils.getScaledDimension(600, 450),
                TAB_LABELS);
        this.job = job;
        this.extension =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionReports.class);

        Parameters params = job.getData().getParameters();

        this.addTextField(TAB_SCOPE, FIELD_NAME, this.job.getData().getName());
        this.addTextField(TAB_SCOPE, FIELD_TITLE, params.getReportTitle());

        this.addTextField(TAB_SCOPE, FIELD_REPORT_NAME, params.getReportFile());

        String dir = params.getReportDir();
        if (StringUtils.isEmpty(dir)) {
            dir = ReportParam.DEFAULT_TEMPLATES_DIR;
        }
        this.addFileSelectField(
                TAB_SCOPE, FIELD_REPORT_DIR, new File(dir), JFileChooser.DIRECTORIES_ONLY, null);
        if (dir.contains(VARIABLE_TOKEN)) {
            setFieldValue(FIELD_REPORT_DIR, dir);
        }
        this.addMultilineField(TAB_SCOPE, FIELD_DESCRIPTION, params.getReportDescription());
        this.addCheckBoxField(
                TAB_SCOPE, FIELD_DISPLAY_REPORT, JobUtils.unBox(params.getDisplayReport()));

        Template defaultTemplate = extension.getTemplateByConfigName(params.getTemplate());
        List<String> templates = extension.getTemplateNames();
        Collections.sort(templates);
        this.addComboField(
                TAB_TEMPLATE,
                FIELD_TEMPLATE,
                templates,
                defaultTemplate != null ? defaultTemplate.getDisplayName() : null);

        ((JComboBox<?>) this.getField(FIELD_TEMPLATE))
                .addActionListener(
                        e -> {
                            resetTemplateFields();
                        });

        List<String> themes = new ArrayList<>();
        String theme = null;
        if (defaultTemplate != null) {
            themes = defaultTemplate.getThemeNames();
            theme = defaultTemplate.getThemeName(params.getTheme());
        }

        this.addComboField(TAB_TEMPLATE, FIELD_THEME, themes, theme);

        this.addCustomComponent(TAB_TEMPLATE, FIELD_SECTIONS, getSectionsScrollPane());
        resetTemplateFields();
        this.addPadding(TAB_TEMPLATE);

        this.addTextFieldReadOnly(TAB_FILTER, FIELD_RISK_HEADER, "");
        List<String> stdRisks;
        List<String> risks = job.getData().getRisks();
        if (risks != null) {
            stdRisks =
                    risks.stream()
                            .map(r -> WordUtils.capitalize(r.trim().toLowerCase(Locale.ROOT)))
                            .collect(Collectors.toList());
        } else {
            stdRisks = Arrays.asList(Alert.MSG_RISK);
        }
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_3, stdRisks.contains(Alert.MSG_RISK[3]));
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_2, stdRisks.contains(Alert.MSG_RISK[2]));
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_1, stdRisks.contains(Alert.MSG_RISK[1]));
        this.addCheckBoxField(TAB_FILTER, FIELD_RISK_0, stdRisks.contains(Alert.MSG_RISK[0]));

        this.addTextFieldReadOnly(TAB_FILTER, FIELD_CONFIDENCE_HEADER, "");
        List<String> stdConfs;
        List<String> confs = job.getData().getConfidences();
        if (confs != null) {
            stdConfs =
                    confs.stream()
                            .map(r -> WordUtils.capitalize(r.trim().toLowerCase(Locale.ROOT)))
                            .collect(Collectors.toList());
        } else {
            stdConfs = Arrays.asList(Alert.MSG_CONFIDENCE);
        }
        this.addCheckBoxField(
                TAB_FILTER, FIELD_CONFIDENCE_4, stdConfs.contains(Alert.MSG_CONFIDENCE[4]));
        this.addCheckBoxField(
                TAB_FILTER, FIELD_CONFIDENCE_3, stdConfs.contains(Alert.MSG_CONFIDENCE[3]));
        this.addCheckBoxField(
                TAB_FILTER, FIELD_CONFIDENCE_2, stdConfs.contains(Alert.MSG_CONFIDENCE[2]));
        this.addCheckBoxField(
                TAB_FILTER, FIELD_CONFIDENCE_1, stdConfs.contains(Alert.MSG_CONFIDENCE[1]));
        this.addCheckBoxField(
                TAB_FILTER, FIELD_CONFIDENCE_0, stdConfs.contains(Alert.MSG_CONFIDENCE[0]));
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
            String originalValue = this.getStringValue(FIELD_THEME);
            JComboBox<String> themeCombo = ((JComboBox<String>) this.getField(FIELD_THEME));
            themeCombo.removeAllItems();
            for (String theme : template.getThemeNames()) {
                themeCombo.addItem(theme);
            }
            if (!template.getThemeNames().isEmpty()) {
                // Try the current value in the dialog
                if (template.getThemeForName(originalValue) != null) {
                    themeCombo.setSelectedItem(originalValue);
                } else {
                    // Use the user's default theme for this template
                    String defaultTheme =
                            extension.getReportParam().getTheme(template.getConfigName());
                    if (defaultTheme != null) {
                        themeCombo.setSelectedItem(template.getThemeName(defaultTheme));
                    } else {
                        // fall back to the first one
                        themeCombo.setSelectedIndex(0);
                    }
                }
            }

            List<String> sections = template.getSections();
            sectionsMap = new HashMap<>();
            if (sections.isEmpty()) {
                sectionPanel.add(
                        new JLabel(
                                Constant.messages.getString("reports.dialog.field.sections.none")));
            } else {
                List<String> sectionList = job.getData().getSections();
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

    @Override
    public void save() {
        Template template = extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE));
        job.getData().setName(this.getStringValue(FIELD_NAME));
        job.getData().getParameters().setTemplate(template.getConfigName());
        job.getData().getParameters().setReportTitle(this.getStringValue(FIELD_TITLE));
        job.getData().getParameters().setReportFile(this.getStringValue(FIELD_REPORT_NAME));
        job.getData().getParameters().setReportDir(this.getStringValue(FIELD_REPORT_DIR));
        job.getData().getParameters().setReportDescription(this.getStringValue(FIELD_DESCRIPTION));
        job.getData().getParameters().setDisplayReport(this.getBoolValue(FIELD_DISPLAY_REPORT));
        job.getData()
                .getParameters()
                .setTheme(template.getThemeForName(this.getStringValue(FIELD_THEME)));

        List<String> sections = new ArrayList<>();
        for (Entry<String, JCheckBox> entry : sectionsMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                sections.add(entry.getKey());
            }
        }
        if (sections.isEmpty()) {
            job.getData().setSections(null);
        } else {
            job.getData().setSections(sections);
        }

        String[] riskFields = {FIELD_RISK_0, FIELD_RISK_1, FIELD_RISK_2, FIELD_RISK_3};
        List<String> risks = new ArrayList<>();
        for (int i = 0; i < riskFields.length; i++) {
            if (this.getBoolValue(riskFields[i])) {
                risks.add(ReportJob.riskIntToString(i));
            }
        }
        if (risks.isEmpty()) {
            job.getData().setRisks(null);
        } else {
            job.getData().setRisks(risks);
        }

        String[] confFields = {
            FIELD_CONFIDENCE_0,
            FIELD_CONFIDENCE_1,
            FIELD_CONFIDENCE_2,
            FIELD_CONFIDENCE_3,
            FIELD_CONFIDENCE_4
        };
        List<String> confs = new ArrayList<>();
        for (int i = 0; i < confFields.length; i++) {
            if (this.getBoolValue(confFields[i])) {
                confs.add(ReportJob.confidenceIntToString(i));
            }
        }
        if (confs.isEmpty()) {
            job.getData().setConfidences(null);
        } else {
            job.getData().setConfidences(confs);
        }
        this.job.resetAndSetChanged();
    }

    private File getReportFile() {
        return new File(
                this.getStringValue(FIELD_REPORT_DIR), this.getStringValue(FIELD_REPORT_NAME));
    }

    @Override
    public String validateFields() {
        Template template = extension.getTemplateByDisplayName(getStringValue(FIELD_TEMPLATE));
        if (template == null) {
            return Constant.messages.getString("reports.dialog.error.notemplate");
        }

        if (getStringValue(FIELD_REPORT_DIR).contains(VARIABLE_TOKEN)
                || getStringValue(FIELD_REPORT_NAME).contains(VARIABLE_TOKEN)) {
            return null;
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

        return null;
    }
}
