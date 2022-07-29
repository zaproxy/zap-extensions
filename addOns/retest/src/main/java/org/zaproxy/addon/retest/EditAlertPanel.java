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
package org.zaproxy.addon.retest;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.TitledBorder;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.ScrollableSizeHint;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class EditAlertPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private static final Insets DEFAULT_INSETS = new Insets(1, 1, 1, 1);

    private JScrollPane alertPane = null;
    private JXPanel alertDisplay = null;
    private CardLayout cardLayout = null;

    private ZapNumberSpinner alertEditPlugin = null;
    private JComboBox<String> alertEditName = null;
    private ZapTextField alertEditUrl = null;
    private JComboBox<String> alertEditMethod = null;
    private ZapTextField alertEditAttack = null;
    private JComboBox<String> alertEditParam = null;
    private ZapTextField alertEditEvidence = null;
    private JComboBox<String> alertEditConfidence = null;
    private JComboBox<String> alertEditRisk = null;
    private ZapTextArea alertOtherInfo = null;
    private DefaultComboBoxModel<String> nameListModel = null;

    private List<Vulnerability> vulnerabilities = null;

    public EditAlertPanel() {
        super();
        initialize();
    }

    private void initialize() {
        cardLayout = new CardLayout();
        this.setLayout(cardLayout);
        this.setName("AlertView");
        this.add(getAlertPane(), getAlertPane().getName());
    }

    private JScrollPane getAlertPane() {
        if (alertPane == null) {
            alertPane = new JScrollPane();
            alertPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            alertPane.setViewportView(getAlertDisplay());
            alertPane.setName("alertPane");
        }
        return alertPane;
    }

    private ZapTextArea createZapTextArea() {
        ZapTextArea zapTextArea = new ZapTextArea(3, 30);
        zapTextArea.setLineWrap(true);
        zapTextArea.setWrapStyleWord(true);
        zapTextArea.setEditable(true);
        return zapTextArea;
    }

    private JScrollPane createJScrollPane(String name) {
        JScrollPane jScrollPane = new JScrollPane();
        jScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        jScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        jScrollPane.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        name,
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));
        return jScrollPane;
    }

    private JPanel getAlertDisplay() {
        if (alertDisplay == null) {
            alertDisplay = new JXPanel();
            alertDisplay.setLayout(new GridBagLayout());
            alertDisplay.setScrollableHeightHint(ScrollableSizeHint.NONE);
            alertDisplay.setName("alertDisplay");

            alertEditPlugin = new ZapNumberSpinner();
            if (alertEditPlugin.getEditor() instanceof JSpinner.DefaultEditor) {
                ((JSpinner.DefaultEditor) alertEditPlugin.getEditor())
                        .getTextField()
                        .setHorizontalAlignment(JTextField.LEFT);
            }

            alertEditName = new JComboBox<>();
            alertEditName.setEditable(true);
            nameListModel = new DefaultComboBoxModel<>();
            List<String> allVulns = getAllVulnerabilityNames();
            for (String vuln : allVulns) {
                nameListModel.addElement(vuln);
            }
            alertEditName.setModel(nameListModel);

            alertEditMethod = new JComboBox<>();
            alertEditMethod.setEditable(true);
            DefaultComboBoxModel<String> methodListModel = new DefaultComboBoxModel<>();
            String[] allMethods = HttpRequestHeader.METHODS;
            for (String method : allMethods) {
                methodListModel.addElement(method);
            }
            alertEditMethod.setModel(methodListModel);

            alertEditUrl = new ZapTextField();
            alertEditAttack = new ZapTextField();

            DefaultComboBoxModel<String> paramListModel = new DefaultComboBoxModel<>();
            paramListModel.addElement(""); // Default is empty so user can type anything in
            alertEditParam = new JComboBox<>();
            alertEditParam.setModel(paramListModel);
            alertEditParam.setEditable(true);

            alertEditEvidence = new ZapTextField();
            alertEditConfidence = new JComboBox<>(Alert.MSG_CONFIDENCE);
            alertEditRisk = new JComboBox<>(Alert.MSG_RISK);

            alertOtherInfo = createZapTextArea();
            JScrollPane otherSp =
                    createJScrollPane(Constant.messages.getString("retest.edit.dialog.other"));
            otherSp.setViewportView(alertOtherInfo);

            int gbcRow = 0;

            JLabel pluginLabel =
                    new JLabel(Constant.messages.getString("retest.edit.dialog.scanruleid"));
            pluginLabel.setLabelFor(alertEditPlugin);

            JLabel nameLabel = new JLabel(Constant.messages.getString("retest.edit.dialog.name"));
            nameLabel.setLabelFor(alertEditName);

            JLabel urlLabel = new JLabel(Constant.messages.getString("retest.edit.dialog.url"));
            urlLabel.setLabelFor(alertEditUrl);

            JLabel methodLabel =
                    new JLabel(Constant.messages.getString("retest.edit.dialog.method"));
            methodLabel.setLabelFor(alertEditMethod);

            JLabel attackLabel =
                    new JLabel(Constant.messages.getString("retest.edit.dialog.attack"));
            attackLabel.setLabelFor(alertEditAttack);

            JLabel paramLabel =
                    new JLabel(Constant.messages.getString("retest.edit.dialog.parameter"));
            paramLabel.setLabelFor(alertEditParam);

            JLabel evidenceLabel =
                    new JLabel(Constant.messages.getString("retest.edit.dialog.evidence"));
            evidenceLabel.setLabelFor(alertEditEvidence);

            JLabel confidenceLabel =
                    new JLabel(Constant.messages.getString("retest.edit.dialog.confidence"));
            confidenceLabel.setLabelFor(alertEditConfidence);

            JLabel riskLabel = new JLabel(Constant.messages.getString("retest.edit.dialog.risk"));
            riskLabel.setLabelFor(alertEditRisk);

            alertDisplay.add(pluginLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditPlugin, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;

            alertDisplay.add(nameLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditName, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(urlLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditUrl, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(methodLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditMethod, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(attackLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditAttack, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(paramLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditParam, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(evidenceLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(
                    alertEditEvidence, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(confidenceLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(
                    alertEditConfidence, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;
            alertDisplay.add(riskLabel, LayoutHelper.getGBC(0, gbcRow, 1, 0, DEFAULT_INSETS));
            alertDisplay.add(alertEditRisk, LayoutHelper.getGBC(1, gbcRow, 1, 1, DEFAULT_INSETS));
            gbcRow++;

            alertDisplay.add(
                    otherSp,
                    LayoutHelper.getGBC(
                            0, gbcRow, 2, 1.0D, 1.0D, GridBagConstraints.BOTH, DEFAULT_INSETS));
        }
        return alertDisplay;
    }

    public void displayAlert(AlertData alertData) {
        alertEditPlugin.setValue(alertData.getScanRuleId());
        nameListModel.addElement(alertData.getAlertName());
        alertEditName.setSelectedItem(alertData.getAlertName());
        alertEditUrl.setText(alertData.getUrl());
        alertEditMethod.setSelectedItem(alertData.getMethod());
        alertEditRisk.setSelectedItem(alertData.getRisk());
        alertEditConfidence.setSelectedItem(alertData.getConfidence());
        alertEditParam.setSelectedItem(alertData.getParam());
        alertEditAttack.setText(alertData.getAttack());
        alertEditAttack.discardAllEdits();
        alertEditEvidence.setText(alertData.getEvidence());
        alertEditEvidence.discardAllEdits();
        setAlertOtherInfo(alertData.getOtherInfo());
        cardLayout.show(this, getAlertPane().getName());
    }

    private List<Vulnerability> getAllVulnerabilities() {
        if (vulnerabilities == null) {
            vulnerabilities = Vulnerabilities.getAllVulnerabilities();
        }
        return vulnerabilities;
    }

    private List<String> getAllVulnerabilityNames() {
        List<Vulnerability> vulns = this.getAllVulnerabilities();
        List<String> names = new ArrayList<>(vulns.size());
        for (Vulnerability v : vulns) {
            names.add(v.getAlert());
        }
        Collections.sort(names);
        return names;
    }

    private void setAlertOtherInfo(String otherInfo) {
        alertOtherInfo.setText(otherInfo);
        alertOtherInfo.discardAllEdits();
        alertOtherInfo.setCaretPosition(0);
    }

    public AlertData getAlertData() {
        AlertData alertData = new AlertData();
        alertData.setStatus(AlertData.Status.NOT_VERIFIED);
        alertData.setScanRuleId(alertEditPlugin.getValue());
        alertData.setAlertName((String) alertEditName.getSelectedItem());
        alertData.setUrl(alertEditUrl.getText());
        alertData.setMethod((String) alertEditMethod.getSelectedItem());
        alertData.setAttack(alertEditAttack.getText());
        alertData.setParam((String) alertEditParam.getSelectedItem());
        alertData.setEvidence((String) alertEditConfidence.getSelectedItem());
        alertData.setConfidence((String) alertEditConfidence.getSelectedItem());
        alertData.setRisk((String) alertEditRisk.getSelectedItem());
        alertData.setOtherInfo(alertOtherInfo.getText());
        return alertData;
    }
}
