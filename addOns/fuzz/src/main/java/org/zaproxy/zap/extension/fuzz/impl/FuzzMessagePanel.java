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
package org.zaproxy.zap.extension.fuzz.impl;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListener;
import org.zaproxy.zap.view.messagelocation.SelectMessageLocationsPanel;

public class FuzzMessagePanel extends SelectMessageLocationsPanel {

    private static final long serialVersionUID = -1511437565770653938L;

    // Maintain a local copy of these so we can remove them when editing - this will prevent users
    // from adding more fuzzer locations
    private List<MessageLocationProducerFocusListener> focusListeners = new ArrayList<>();

    public FuzzMessagePanel(FuzzerDialog<?, ?, ?> fuzzerDialog) {
        super();

        JButton editButton =
                new JButton(Constant.messages.getString("fuzz.fuzzer.dialog.button.edit"));
        editButton.setToolTipText(
                Constant.messages.getString("fuzz.fuzzer.dialog.button.edit.tooltip"));

        editButton.addActionListener(
                e -> {
                    fuzzerDialog.setMessageEditable(!fuzzerDialog.isEditable());
                    if (fuzzerDialog.isEditable()) {
                        editButton.setText(
                                Constant.messages.getString("fuzz.fuzzer.dialog.button.save"));
                        editButton.setToolTipText(
                                Constant.messages.getString(
                                        "fuzz.fuzzer.dialog.button.save.tooltip"));
                        for (MessageLocationProducerFocusListener fl : focusListeners) {
                            super.removeFocusListener(fl);
                        }
                    } else {
                        editButton.setText(
                                Constant.messages.getString("fuzz.fuzzer.dialog.button.edit"));
                        editButton.setToolTipText(
                                Constant.messages.getString(
                                        "fuzz.fuzzer.dialog.button.edit.tooltip"));
                        for (MessageLocationProducerFocusListener fl : focusListeners) {
                            super.addFocusListener(fl);
                        }
                    }
                });
        this.addOptions(editButton, OptionsLocation.END);
    }

    @Override
    public void addFocusListener(MessageLocationProducerFocusListener fl) {
        focusListeners.add(fl);
        super.addFocusListener(fl);
    }

    @Override
    public void removeFocusListener(MessageLocationProducerFocusListener fl) {
        focusListeners.remove(fl);
        super.removeFocusListener(fl);
    }
}
