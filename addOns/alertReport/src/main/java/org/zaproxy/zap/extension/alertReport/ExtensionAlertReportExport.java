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
package org.zaproxy.zap.extension.alertReport;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * Extension to Export Alert Selected in PDF to send to customer
 *
 * @author leandroferrari
 */
public class ExtensionAlertReportExport extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAlertReportExports";
    private AlertReportExportMenuItem alertReportExportMenuItem = null;
    private OptionsAlertReportExportPanel optionsAlertExportPanel = null;
    private ZapMenuItem menuItemAlertExport = null;
    private AlertReportExportParam params;
    private List<Alert> alertsDB = null;
    private static final Logger logger = Logger.getLogger(ExtensionAlertReportExport.class);

    public AlertReportExportParam getParams() {
        if (params == null) params = new AlertReportExportParam();
        return params;
    }

    private OptionsAlertReportExportPanel getOptionsAlertExportPanel() {
        if (optionsAlertExportPanel == null) {
            optionsAlertExportPanel = new OptionsAlertReportExportPanel();
        }
        return optionsAlertExportPanel;
    }

    /** */
    public ExtensionAlertReportExport() {
        super(ExtensionAlertReportExport.NAME);
        this.setI18nPrefix("alertreport");
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(getAlertExportMsgPopupMenu());
            extensionHook.getHookView().addOptionPanel(getOptionsAlertExportPanel());
            extensionHook.addOptionsParamSet(getParams());
            extensionHook.getHookMenu().addReportMenuItem(getMenuItemAlertReport());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private ZapMenuItem getMenuItemAlertReport() {
        if (menuItemAlertExport == null) {
            menuItemAlertExport = new ZapMenuItem("alertreport.export.menu.report.generate");
            menuItemAlertExport.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            alertReportExportMenuItem.generateAlertReport(true);
                        }
                    });
        }
        return menuItemAlertExport;
    }

    private AlertReportExportMenuItem getAlertExportMsgPopupMenu() {
        if (alertReportExportMenuItem == null) {
            alertReportExportMenuItem =
                    new AlertReportExportMenuItem(
                            this.getMessages().getString("alertreport.export.message.menuitem"));
            alertReportExportMenuItem.setExtension(this);
        }
        return alertReportExportMenuItem;
    }

    @Override
    public String getDescription() {
        return this.getMessages().getString("alertreport.export.message.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL("http://www.talsoft.com.ar");
        } catch (MalformedURLException e) {
            return null;
        }
    }

    /**
     * get Alerts from DB
     *
     * @return
     */
    public List<Alert> getAllAlerts() {
        List<Alert> allAlerts = new ArrayList<>();

        TableAlert tableAlert = getModel().getDb().getTableAlert();
        Vector<Integer> v;
        try {
            // TODO this doesnt work, but should be used when its fixed :/
            // v = tableAlert.getAlertListBySession(getModel().getSession().getSessionId());
            v = tableAlert.getAlertList();

            for (int i = 0; i < v.size(); i++) {
                int alertId = v.get(i).intValue();
                RecordAlert recAlert = tableAlert.read(alertId);
                Alert alert = new Alert(recAlert);
                if (!allAlerts.contains(alert)) {
                    allAlerts.add(alert);
                }
            }
        } catch (DatabaseException e) {
            logger.error(e.getMessage(), e);
        }
        alertsDB = allAlerts;
        return allAlerts;
    }

    /**
     * Get fileName of alert pdf
     *
     * @param alert
     * @return
     */
    public String getFileName() {

        JFileChooser chooser =
                new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
        // set filename alert
        String extensionFile = ".pdf";
        if (this.getParams().getFormatReport().equals("ODT")) extensionFile = ".odt";
        File fileproposal =
                new File(
                        params.getCompanyName().replace(" ", "")
                                + "_"
                                + params.getTitleReport().replace(" ", "")
                                + "_"
                                + params.getCustomerName().replace(" ", "")
                                + extensionFile);
        chooser.setSelectedFile(fileproposal);
        chooser.setFileFilter(
                new FileFilter() {
                    @Override
                    public boolean accept(File file) {
                        String extensionFile = ".pdf";
                        if (getParams().getFormatReport().equals("ODT")) extensionFile = ".odt";
                        if (file.isDirectory()) {
                            return true;
                        } else if (file.isFile() && file.getName().endsWith(extensionFile)) {
                            return true;
                        }
                        return false;
                    }

                    @Override
                    public String getDescription() {
                        return getParams().getFormatReport() + " File";
                    }
                });
        File file = null;
        String fileName = "";
        int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            file = chooser.getSelectedFile();
            if (file == null) {
                return "";
            }
            fileName = file.getAbsolutePath();
            if (!fileName.endsWith(extensionFile)) {
                fileName += extensionFile;
            }
        }
        return fileName;
    }

    /**
     * get alerts from same Plugin ID
     *
     * @param alertSelected
     * @return
     */
    public List<Alert> getAlertsSelected(Alert alertSelected) {
        // check if read from db
        if (alertsDB == null) alertsDB = this.getAllAlerts();
        List<Alert> alerts = new ArrayList<>();
        for (int i = 0; i < alertsDB.size(); i++) {
            Alert alert = alertsDB.get(i);
            if (alertSelected.getName().equals(alert.getName())) alerts.add(alert);
        }

        return alerts;
    }
    /** Clear alertsDB in memory */
    public void clearAlertsDB() {
        this.alertsDB = null;
    }
}
