/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence;

import java.awt.Frame;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.JScrollPane;
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class SequenceAscanDialog extends StandardFieldsDialog {

    private static final String FIELD_POLICY = "sequence.scan.dialog.label.policy";
    private static final String FIELD_SEQS = "sequence.scan.dialog.label.sequences";

    private static final long serialVersionUID = 1L;
    private ExtensionSequence ext;

    private JList<String> seqList;
    private DefaultListModel<String> model;

    public SequenceAscanDialog(ExtensionSequence ext, Frame owner) {
        super(owner, "sequence.scan.dialog.title", DisplayUtils.getScaledDimension(500, 300));
        this.ext = ext;

        String defaultPolicyName = "";
        try {
            ScanPolicy defaultPolicy = ext.getDefaultScanPolicy();
            if (defaultPolicy != null) {
                defaultPolicyName = defaultPolicy.getName();
            }
        } catch (ConfigurationException e) {
            // Ignore
        }

        this.addComboField(
                FIELD_POLICY,
                ext.getExtActiveScan().getPolicyManager().getAllPolicyNames(),
                defaultPolicyName);

        model = new DefaultListModel<>();
        model.addAll(ext.getSequenceNames());
        seqList = new JList<>(model);
        this.addCustomComponent(FIELD_SEQS, new JScrollPane(seqList), 100);
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("sequence.scan.dialog.button.scan");
    }

    @Override
    public void save() {
        new Thread(
                        () ->
                                ext.activeScanSequences(
                                        this.getStringValue(FIELD_POLICY),
                                        seqList.getSelectedValuesList()),
                        "ZAP-SequenceActiveScanGui")
                .start();
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(FIELD_POLICY)) {
            return Constant.messages.getString("sequence.scan.dialog.error.policy");
        }
        if (seqList.isSelectionEmpty()) {
            return Constant.messages.getString("sequence.scan.dialog.error.sequences");
        }
        return null;
    }

    @Override
    public String getHelpIndex() {
        return "addon.sequence";
    }
}
