/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.exportreport.export.ExportReport;
import org.zaproxy.zap.extension.exportreport.filechooser.FileList;
import org.zaproxy.zap.extension.exportreport.filechooser.Utils;
import org.zaproxy.zap.extension.exportreport.utility.SharedFunctions;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class ExtensionExportReport extends ExtensionAdaptor implements CommandLineListener {

    private static final Logger logger = Logger.getLogger(ExtensionExportReport.class);

    private static final String NAME = "ExtensionExportReport";
    private static final String FONT = "Arial";

    private ZapMenuItem menuExportReport = null;
    private FrameExportReport frameER = null;

    protected final Map<String, String> alertTypeRisk = new HashMap<>();

    /* Nav Panel creation. */
    private PanelSource cardSource = null;
    private PanelAlertRisk cardAlertRisk = null;
    private PanelAlertDetails cardAlertDetails = null;

    /* Field Limit Constants */
    private final int textfieldLimit = 30;
    private final int textareaLimit = 600;

    /* Relational CONSTANT for export types. */
    private ArrayList<String> alertSeverity = new ArrayList<String>();
    private ArrayList<String> alertDetails = new ArrayList<String>();
    private ArrayList<String> alertAdditional = new ArrayList<String>();
    private FileList fileList = new FileList();
    private int maxList = 0;
    public static final int SOURCE_COUNT = 8;

    private static final int ARG_EXPORT_REPORT_IDX = 0;
    private static final int ARG_SOURCE_INFO_IDX = 1;
    private static final int ARG_ALERT_SEVERITY_IDX = 2;
    private static final int ARG_ALERT_DETAILS_IDX = 3;
    private CommandLineArgument[] arguments = new CommandLineArgument[4];

    private ExportReportAPI exportReportAPI;
    public ExtensionExportReport() {
        super();
        initialize();
    }

    private void initialize() {
        this.setName(NAME);
        SharedFunctions.fontExists(FONT);
    }

    @Override
    public void init() {
        // PanelAlertRisk
        alertSeverity.clear();
        alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.high.label"));
        alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.medium.label"));
        alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.low.label"));
        alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.info.label"));

        // PanelAlertDetails
        alertDetails.clear();
        alertDetails.add(Constant.messages.getString("exportreport.details.cweid.label"));
        alertDetails.add(Constant.messages.getString("exportreport.details.wascid.label"));
        alertDetails.add(Constant.messages.getString("exportreport.details.description.label"));
        alertDetails.add(Constant.messages.getString("exportreport.details.otherinfo.label"));
        alertDetails.add(Constant.messages.getString("exportreport.details.solution.label"));
        alertDetails.add(Constant.messages.getString("exportreport.details.reference.label"));

        alertAdditional.clear();
        alertAdditional.add(Constant.messages.getString("exportreport.details.requestheader.label"));
        alertAdditional.add(Constant.messages.getString("exportreport.details.responseheader.label"));
        alertAdditional.add(Constant.messages.getString("exportreport.details.requestbody.label"));
        alertAdditional.add(Constant.messages.getString("exportreport.details.responsebody.label"));

        fileList.add(Utils.HTML, Utils.HTML_TYPE, Utils.HTML, Utils.HTML_DESCRIPTION, Utils.HTML_ICON, true);
        fileList.add(Utils.BOOTSTRAP, Utils.BOOTSTRAP_TYPE, Utils.BOOTSTRAP, Utils.BOOTSTRAP_DESCRIPTION, Utils.BOOTSTRAP_ICON, false);
        fileList.add(Utils.XML, Utils.XML_TYPE, Utils.XML, Utils.XML_DESCRIPTION, Utils.XML_ICON, true);
        fileList.add(Utils.JSON, Utils.JSON_TYPE, Utils.JSON, Utils.JSON_DESCRIPTION, Utils.JSON_ICON, true);
        fileList.add(Utils.PDF, Utils.PDF_TYPE, Utils.PDF, Utils.PDF_DESCRIPTION, Utils.PDF_ICON, false);
        fileList.add(Utils.DOC, Utils.DOC_TYPE, Utils.DOC, Utils.DOC_DESCRIPTION, Utils.DOC_ICON, false);

        maxList = alertDetails.size() + alertAdditional.size();

        exportReportAPI = new ExportReportAPI(this);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            extensionHook.getHookMenu().addReportMenuItem(getMenuExportReport());
        }
        API.getInstance().registerApiImplementor(exportReportAPI);
        extensionHook.addCommandLine(getCommandLineArguments());
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (frameER != null) {
            frameER.dispose();
            frameER = null;
        }
    }

    private ZapMenuItem getMenuExportReport() {
        if (menuExportReport == null) {
            menuExportReport = new ZapMenuItem("exportreport.menu.export.label");
            // menuExportReport.setText(Constant.messages.getString("exportreport.menu.export.label"));
            menuExportReport.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    if (frameER != null) {
                        frameER.requestFocusInWindow();
                        return;
                    }

                    getNewOptionFrame();

                    // -Change the default close operation
                    WindowAdapter exitListener = new WindowAdapter() {
                        @Override
                        public void windowClosing(WindowEvent e) {
                            emitFrame();
                        }
                    };
                    frameER.addWindowListener(exitListener);
                    frameER.setSize(400, 500);
                    frameER.setResizable(false);
                    frameER.setVisible(true);
                    frameER.centerFrame();// frameER.setLocationRelativeTo(null);
                }
            });
        }
        return menuExportReport;
    }

    public void getNewOptionFrame() {
        frameER = new FrameExportReport(this, extensionGetCardSource(), extensionGetCardAlertRisk(), extensionGetCardAlertDetails());
    }

    private PanelSource extensionGetCardSource() {
        cardSource = new PanelSource(this);
        return cardSource;
    }

    private PanelAlertRisk extensionGetCardAlertRisk() {
        cardAlertRisk = new PanelAlertRisk(this, alertSeverity);
        return cardAlertRisk;
    }

    private PanelAlertDetails extensionGetCardAlertDetails() {
        cardAlertDetails = new PanelAlertDetails(this, alertDetails, alertAdditional);
        return cardAlertDetails;
    }

    public int extensionGetMaxList() {
        return maxList;
    }

    /* Source Card return data */
    public String extensionGetTitle() {
        // System.out.println(cardSource.getTitle());
        return cardSource.getTitle();
    }

    public String extensionGetBy() {
        // System.out.println(cardSource.getBy());
        return cardSource.getBy();
    }

    public String extensionGetFor() {
        // System.out.println(cardSource.getFor());
        return cardSource.getFor();
    }

    public String extensionGetScanDate() {
        // System.out.println(cardSource.getScanDate());
        return cardSource.getScanDate();
    }

    public String extensionGetReportDate() {
        // System.out.println(cardSource.getReportDate());
        return cardSource.getReportDate();
    }

    public String extensionGetScanVer() {
        // System.out.println(cardSource.getScanVer());
        return cardSource.getScanVer();
    }

    public String extensionGetReportVer() {
        // System.out.println(cardSource.getReportVer());
        return cardSource.getReportVer();
    }

    public String extensionGetDescription() {
        // System.out.println(cardSource.getDescription());
        return cardSource.getDescription();
    }

    /* Alert Risk Card return data */
    public ArrayList<String> getIncludedAlertSeverity() {
        // for (int i = 0; i < cardAlertRisk.getSourceListModel().size(); i++) {
        // System.out.println(cardAlertRisk.getSourceListModel().get(i));
        // }
        return cardAlertRisk.getSourceListModel();
    }

    /* Alert Details Card return data */
    public ArrayList<String> getIncludedAlertDetails() {
        // for (int i = 0; i < cardAlertDetails.getSourceListModel().size(); i++) {
        // System.out.println(cardAlertDetails.getSourceListModel().get(i));
        // }
        return cardAlertDetails.getSourceListModel();
    }

    public int getTextfieldLimit() {
        return textfieldLimit;
    }

    public int getTextfieldNoLimit() {
        return -1;
    }

    public int getTextareaLimit() {
        return textareaLimit;
    }

    @Override
    public String getAuthor() {
        return "Author: Goran Sarenkapa - JordanGS";
    }

    public void emitFrame() {
        frameER.setVisible(false);
        frameER.dispose();
        frameER = null;
    }

    public void generateReport() {
        ExportReport report = new ExportReport();
        report.generateReport(this.getView(), this);
        this.emitFrame();
    }

    public boolean generateReport(String absolutePath, String fileExtension, ArrayList<String> sourceDetails, ArrayList<String> alertSeverity, ArrayList<String> alertDetails) {
        ExportReport report = new ExportReport();
        return report.generateReport(this, absolutePath, fileExtension, sourceDetails, alertSeverity, alertDetails);
    }

    public boolean canWrite(String path) {
        File file = new File(path);
        try {
            new FileOutputStream(file, true).close();
        } catch (IOException e) {
            logger.error(path + " is not writable: " + e.getLocalizedMessage());
            return false;
        }
        return true;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_EXPORT_REPORT_IDX].isEnabled() &&
                arguments[ARG_SOURCE_INFO_IDX].isEnabled() &&
                arguments[ARG_ALERT_SEVERITY_IDX].isEnabled() &&
                arguments[ARG_ALERT_DETAILS_IDX].isEnabled()) {

            String absolutePath = arguments[ARG_EXPORT_REPORT_IDX].getArguments().get(0);

            File f = new File(absolutePath);
            String file = f.getName();
            String fileExtension = fileList.compareExtension(file);

            if (!canWrite(absolutePath)) {
                CommandLine.error(Constant.messages.getString("exportreport.message.console.error.file.writable", absolutePath));
                return;
            }

            boolean valid = false;

            if (fileExtension.length() > 0) {
                valid = true;
            }
            if (!valid) {
                CommandLine.error(Constant.messages.getString("exportreport.message.console.error.file.extension", fileExtension));
                return;
            }

            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.path"));
            ArrayList<String> sourceDetails = new ArrayList<String>(Arrays.asList((arguments[ARG_SOURCE_INFO_IDX].getArguments().get(0)).split(";")));
            ArrayList<String> alertSeverityFlags = new ArrayList<String>(Arrays.asList((arguments[ARG_ALERT_SEVERITY_IDX].getArguments().get(0)).split(";")));
            ArrayList<String> alertDetailsFlags = new ArrayList<String>(Arrays.asList((arguments[ARG_ALERT_DETAILS_IDX].getArguments().get(0)).split(";")));

            if (sourceDetails.size() != SOURCE_COUNT) {
                CommandLine.error(Constant.messages.getString("exportreport.message.console.error.source", Constant.messages.getString("exportreport.menu.source.label"), sourceDetails.size(), SOURCE_COUNT, Constant.messages.getString("exportreport.source.title.label"), Constant.messages.getString("exportreport.source.by.label"), Constant.messages.getString("exportreport.source.for.label"), Constant.messages.getString("exportreport.source.scandate.label"), Constant.messages.getString("exportreport.source.reportdate.label"), Constant.messages.getString("exportreport.source.scanver.label"), Constant.messages.getString("exportreport.source.reportver.label"), Constant.messages.getString("exportreport.source.description.label")));
                return;
            }

            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.length", Constant.messages.getString("exportreport.menu.source.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));
            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.content", Constant.messages.getString("exportreport.menu.source.label"), Constant.messages.getString("exportreport.message.console.info.status.unchecked")));

            if (alertSeverityFlags.size() != alertSeverity.size()) {
                CommandLine.error(Constant.messages.getString("exportreport.message.console.error.risk.severity", Constant.messages.getString("exportreport.menu.risk.label"), alertSeverityFlags.size(), alertSeverity.size(), Constant.messages.getString("exportreport.risk.severity.high.label"), Constant.messages.getString("exportreport.risk.severity.medium.label"), Constant.messages.getString("exportreport.risk.severity.low.label"), Constant.messages.getString("exportreport.risk.severity.info.label")));
                return;
            }
            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.length", Constant.messages.getString("exportreport.menu.risk.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));

            if (!validList(alertSeverityFlags)) {
                CommandLine.info(Constant.messages.getString("exportreport.message.console.error.valid.list", Constant.messages.getString("exportreport.menu.risk.label")));
                return;
            }
            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.content", Constant.messages.getString("exportreport.menu.risk.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));

            if (alertDetailsFlags.size() != maxList) {
                CommandLine.error(Constant.messages.getString("exportreport.message.console.error.details", Constant.messages.getString("exportreport.menu.details.label"), alertDetailsFlags.size(), maxList, Constant.messages.getString("exportreport.details.cweid.label"), Constant.messages.getString("exportreport.details.wascid.label"), Constant.messages.getString("exportreport.details.description.label"), Constant.messages.getString("exportreport.details.otherinfo.label"), Constant.messages.getString("exportreport.details.solution.label"), Constant.messages.getString("exportreport.details.reference.label"), Constant.messages.getString("exportreport.details.requestheader.label"), Constant.messages.getString("exportreport.details.responseheader.label"), Constant.messages.getString("exportreport.details.requestbody.label"), Constant.messages.getString("exportreport.details.responsebody.label")));
                return;
            }
            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.length", Constant.messages.getString("exportreport.menu.details.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));

            if (!validList(alertDetailsFlags)) {
                CommandLine.info(Constant.messages.getString("exportreport.message.console.error.valid.list", Constant.messages.getString("exportreport.menu.details.label")));
                return;
            }
            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.content", Constant.messages.getString("exportreport.menu.details.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));

            CommandLine.info(Constant.messages.getString("exportreport.message.console.info.pass.generate"));

            ArrayList<String> alertSeverityTemp = generateList(alertSeverityFlags, alertSeverity);

            ArrayList<String> alertDetailsFull = new ArrayList<String>();
            alertDetailsFull.addAll(0, alertDetails);
            alertDetailsFull.addAll(alertDetails.size(), alertAdditional);
            ArrayList<String> alertDetailsTemp = generateList(alertDetailsFlags, alertDetailsFull);

            try {
                if (generateReport(absolutePath, fileExtension, sourceDetails, alertSeverityTemp, alertDetailsTemp)) {
                    CommandLine.info(Constant.messages.getString("exportreport.message.console.info.pass.path", absolutePath));
                }
            } catch (Exception e) {
                CommandLine.error(Constant.messages.getString("exportreport.message.console.error.exception", e.getMessage()), e);
            }
        } else {
            return;
        }

    }

    public ArrayList<String> getAlertSeverity() {
        return alertSeverity;
    }

    public ArrayList<String> getAlertDetails() {
        return alertDetails;
    }

    public ArrayList<String> getAlertAdditional() {
        return alertAdditional;
    }

    public FileList getFileList() {
        return fileList;
    }

    public ArrayList<String> generateList(ArrayList<String> flagList, ArrayList<String> list) {
        ArrayList<String> temp = new ArrayList<String>();
        for (int i = 0; i < list.size(); i++) {
            if (flagList.get(i).equals("t")) {
                temp.add(list.get(i));
            }
        }
        return temp;
    }

    private CommandLineArgument[] getCommandLineArguments() {
        // String name, int numOfArguments, String pattern, String errorMessage, String helpMessage
        arguments[0] = new CommandLineArgument("-export_report", 1, null, "", Constant.messages.getString("exportreport.cmdline.export.help"));
        arguments[1] = new CommandLineArgument("-source_info", 1, null, "", Constant.messages.getString("exportreport.cmdline.source.help"));
        arguments[2] = new CommandLineArgument("-alert_severity", 1, null, "", Constant.messages.getString("exportreport.cmdline.risk.help"));
        arguments[3] = new CommandLineArgument("-alert_details", 1, null, "", Constant.messages.getString("exportreport.cmdline.details.help"));
        return arguments;
    }

    public boolean validList(ArrayList<String> list) {
        for (int i = 0; i < list.size(); i++) {
            if (!list.get(i).equals("t") && !list.get(i).equals("f")) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean handleFile(File file) {
        // Cant handle any files
        return false;
    }

    @Override
    public List<String> getHandledExtensions() {
        // Cant handle any extensions
        return null;
    }
}