/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.customreport;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.parosproxy.paros.Constant;

public class AlertDetailsPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private JCheckBox description = null;
    private JCheckBox otherInfo = null;
    private JCheckBox solution = null;
    private JCheckBox reference = null;
    private JCheckBox cweid = null;
    private JCheckBox wascid = null;
    private JCheckBox attack = null;
    private JCheckBox param = null;
    private JCheckBox evidence = null;
    private JCheckBox requestHeader = null;
    private JCheckBox responseHeader = null;
    private JCheckBox requestBody = null;
    private JCheckBox responseBody = null;

    public AlertDetailsPanel() {
        initialize();
        description.setSelected(true);
        otherInfo.setSelected(true);
        solution.setSelected(true);
        reference.setSelected(true);
        cweid.setSelected(true);
        wascid.setSelected(true);
        attack.setSelected(true);
        param.setSelected(true);
        evidence.setSelected(true);
    }

    private void initialize() {

        JPanel optionpanel = new JPanel();
        optionpanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Include Description
        description = new JCheckBox();
        description.setText(Constant.messages.getString("customreport.alertdetails.description"));
        gbc.gridy = 0;
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 0, 2, 100);
        optionpanel.add(description, gbc);

        // Include Other Info
        otherInfo = new JCheckBox();
        otherInfo.setText(Constant.messages.getString("customreport.alertdetails.otherinfo"));
        gbc.gridy++;
        optionpanel.add(otherInfo, gbc);

        // Include Solution
        solution = new JCheckBox();
        solution.setText(Constant.messages.getString("customreport.alertdetails.solution"));
        gbc.gridy++;
        optionpanel.add(solution, gbc);

        // Include Reference
        reference = new JCheckBox();
        reference.setText(Constant.messages.getString("customreport.alertdetails.reference"));
        gbc.gridy++;
        optionpanel.add(reference, gbc);

        // Include CWE Id
        cweid = new JCheckBox();
        cweid.setText(Constant.messages.getString("customreport.alertdetails.cweid"));
        gbc.gridy++;
        optionpanel.add(cweid, gbc);

        // Include WASC ID
        wascid = new JCheckBox();
        wascid.setText(Constant.messages.getString("customreport.alertdetails.wascid"));
        gbc.gridy++;
        optionpanel.add(wascid, gbc);

        // Include Attack
        attack = new JCheckBox();
        attack.setText(Constant.messages.getString("customreport.alertdetails.attack"));
        gbc.gridy++;
        optionpanel.add(attack, gbc);

        // Include Param
        param = new JCheckBox();
        param.setText(Constant.messages.getString("customreport.alertdetails.param"));
        gbc.gridy++;
        optionpanel.add(param, gbc);

        // Include Evidence
        evidence = new JCheckBox();
        evidence.setText(Constant.messages.getString("customreport.alertdetails.evidence"));
        gbc.gridy++;
        optionpanel.add(evidence, gbc);

        // Include Request Header
        requestHeader = new JCheckBox();
        requestHeader.setText(
                Constant.messages.getString("customreport.alertdetails.requestheader"));
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(2, 0, 2, 0);
        optionpanel.add(requestHeader, gbc);

        // Include Response Header
        responseHeader = new JCheckBox();
        responseHeader.setText(
                Constant.messages.getString("customreport.alertdetails.responseheader"));
        gbc.gridy++;
        optionpanel.add(responseHeader, gbc);

        // Include Request Body
        requestBody = new JCheckBox();
        requestBody.setText(Constant.messages.getString("customreport.alertdetails.requestbody"));
        gbc.gridy++;
        optionpanel.add(requestBody, gbc);

        // Include Response Body
        responseBody = new JCheckBox();
        responseBody.setText(Constant.messages.getString("customreport.alertdetails.responsebody"));
        gbc.gridy++;
        optionpanel.add(responseBody, gbc);

        this.setLayout(new BorderLayout());
        this.add(
                new JLabel(Constant.messages.getString("customreport.alertdetails.label")),
                BorderLayout.NORTH);
        this.add(new JScrollPane(optionpanel), BorderLayout.CENTER);
    }

    public boolean description() {
        return description.isSelected();
    }

    public boolean otherInfo() {
        return otherInfo.isSelected();
    }

    public boolean solution() {
        return solution.isSelected();
    }

    public boolean reference() {
        return reference.isSelected();
    }

    public boolean cweid() {
        return cweid.isSelected();
    }

    public boolean wascid() {
        return wascid.isSelected();
    }

    public boolean attack() {
        return attack.isSelected();
    }

    public boolean param() {
        return param.isSelected();
    }

    public boolean evidence() {
        return evidence.isSelected();
    }

    public boolean requestHeader() {
        return requestHeader.isSelected();
    }

    public boolean responseHeader() {
        return responseHeader.isSelected();
    }

    public boolean requestBody() {
        return requestBody.isSelected();
    }

    public boolean responseBody() {
        return responseBody.isSelected();
    }
}
