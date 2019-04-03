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

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JFormattedTextField;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpringLayout;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.exportreport.utility.SharedFunctions;
import org.zaproxy.zap.extension.exportreport.utility.SpringUtilities;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

@SuppressWarnings("serial")
public class PanelSource extends JPanel {
    private JTextField txtTitle = null;
    private JFormattedTextField txtScanDate = null;
    private JTextField txtReportDate = null;
    private JTextField txtScanVer = null;
    private JTextField txtReportVer = null;
    private JTextArea txtDescription = null;
    private JTextField txtBy = null;
    private JTextField txtFor = null;
    ExtensionExportReport extension = null;

    public PanelSource(ExtensionExportReport extension) {
        this.extension = extension;
        initialize();
    }

    private void initialize() {
        String strLabel = Constant.messages.getString("exportreport.menu.source.label");

        String strTitle = Constant.messages.getString("exportreport.source.title.label");
        String ttTitle = Constant.messages.getString("exportreport.source.title.tooltip");

        String strBy = Constant.messages.getString("exportreport.source.by.label");
        String ttBy = Constant.messages.getString("exportreport.source.by.tooltip");

        String strFor = Constant.messages.getString("exportreport.source.for.label");
        String ttFor = Constant.messages.getString("exportreport.source.for.tooltip");

        String strScanDate = Constant.messages.getString("exportreport.source.scandate.label");
        String ttScanDate = Constant.messages.getString("exportreport.source.scandate.tooltip");

        String strReportDate = Constant.messages.getString("exportreport.source.reportdate.label");
        String ttReportDate = Constant.messages.getString("exportreport.source.reportdate.tooltip");

        String strScanVer = Constant.messages.getString("exportreport.source.scanver.label");
        String ttScanVer = Constant.messages.getString("exportreport.source.scanver.tooltip");

        String strReportVer = Constant.messages.getString("exportreport.source.reportver.label");
        String ttReportVer = Constant.messages.getString("exportreport.source.reportver.tooltip");

        String strDescription = Constant.messages.getString("exportreport.source.description.label");
        String ttDescription = Constant.messages.getString("exportreport.source.description.tooltip");

        JPanel top = null;
        JPanel container = null;
        JPanel content = null;
        SpringLayout sl = null;

        top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        container = new JPanel();
        content = new JPanel();

        this.setLayout(new BorderLayout());
        this.add(top, BorderLayout.PAGE_START);
        SharedFunctions.createLabel(top, strLabel, SharedFunctions.getTitleFont());

        int[] pad = { 0, 0, 295, 360 };
        content.setLayout(new SpringLayout());
        sl = new SpringLayout();
        container.setLayout(sl);
        this.add(container, BorderLayout.CENTER);
        sl = SharedFunctions.setupConstraints(sl, content, container, pad);
        container.add(content);

        SharedFunctions.createLabel(content, strTitle, SharedFunctions.getLabelFont());
        txtTitle = SharedFunctions.createTextField(content, Model.getSingleton().getSession().getSessionName().toString(), ttTitle, true, extension.getTextfieldLimit());

        SharedFunctions.createLabel(content, strBy, SharedFunctions.getLabelFont());
        txtBy = SharedFunctions.createTextField(content, "", ttBy, true, extension.getTextfieldLimit());

        SharedFunctions.createLabel(content, strFor, SharedFunctions.getLabelFont());
        txtFor = SharedFunctions.createTextField(content, "", ttFor, true, extension.getTextfieldLimit());

        String date = SharedFunctions.getCurrentTimeStamp();  // Set the Scan date as the current timestamp to give user idea of format.

        SharedFunctions.createLabel(content, strScanDate, SharedFunctions.getLabelFont());
        txtScanDate = SharedFunctions.createDateField(content, date, ttScanDate);

        SharedFunctions.createLabel(content, strReportDate, SharedFunctions.getLabelFont());
        txtReportDate = SharedFunctions.createTextField(content, date, ttReportDate, false, extension.getTextfieldNoLimit());

        SharedFunctions.createLabel(content, strScanVer, SharedFunctions.getLabelFont());
        txtScanVer = SharedFunctions.createTextField(content, Constant.messages.getString("exportreport.message.notice.notavailable"), ttScanVer, false, extension.getTextfieldNoLimit());

        SharedFunctions.createLabel(content, strReportVer, SharedFunctions.getLabelFont());
        txtReportVer = SharedFunctions.createTextField(content, Constant.PROGRAM_NAME + " " + Constant.PROGRAM_VERSION, ttReportVer, false, extension.getTextfieldNoLimit());

        SharedFunctions.createLabel(content, strDescription, SharedFunctions.getLabelFont());

        txtDescription = SharedFunctions.createTextArea(2, 0, ttDescription, extension.getTextareaLimit());
        JScrollPane sp = new JScrollPane(txtDescription);
        content.add(sp);

        SpringUtilities.makeCompactGrid(content, 8, 2, 6, 6, 6, 6);  // Lay out the panel, rows, cols, initX, initY, xPad, yPad
    }

    public String getTitle() {
        return txtTitle.getText();
    }

    public String getBy() {
        return txtBy.getText();
    }

    public String getFor() {
        return txtFor.getText();
    }

    public String getScanDate() {
        return txtScanDate.getText();
    }

    public String getReportDate() {
        return txtReportDate.getText();
    }

    public String getScanVer() {
        return txtScanVer.getText();
    }

    public String getReportVer() {
        return txtReportVer.getText();
    }

    public String getDescription() {
        return txtDescription.getText();
    }
}