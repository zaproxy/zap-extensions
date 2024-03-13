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
package org.zaproxy.addon.grpc;

import java.awt.Component;
import java.awt.Frame;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.zaproxy.zap.utils.ZapTextArea;

@SuppressWarnings("serial")
public class ProtoBufEditorDialog extends AbstractDialog {
    private ZapTextArea encodedtxtDisplay = null;
    private ZapTextArea decodedtxtDisplay = null;

    private JScrollPane encodedtxtScrollPane = null;

    private JScrollPane decodedtxtScrollPane = null;

    private JButton DecodeTextButton = null;
    private JButton EncodeTextButton = null;

    public ProtoBufEditorDialog(Frame frame, boolean isModel) {
        super(frame, isModel);
        initialize();
    }

    private void initialize() {
        this.setTitle(Constant.messages.getString("grpc.protobufeditordialog.title"));

        JPanel panel = new JPanel();
        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);
        Component buttonsGlue = Box.createHorizontalGlue();
        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createParallelGroup()
                                        .addComponent(
                                                getEncodedTxtScrollPane(),
                                                GroupLayout.DEFAULT_SIZE,
                                                GroupLayout.PREFERRED_SIZE,
                                                GroupLayout.PREFERRED_SIZE)
                                        .addComponent(
                                                getDecodedTxtScrollPane(),
                                                GroupLayout.DEFAULT_SIZE,
                                                GroupLayout.PREFERRED_SIZE,
                                                GroupLayout.PREFERRED_SIZE))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(buttonsGlue)
                                        .addComponent(getEncodeButton())
                                        .addComponent(getDecodeButton())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(
                                                getEncodedTxtScrollPane(),
                                                GroupLayout.DEFAULT_SIZE,
                                                GroupLayout.PREFERRED_SIZE,
                                                GroupLayout.PREFERRED_SIZE)
                                        .addComponent(
                                                getDecodedTxtScrollPane(),
                                                GroupLayout.DEFAULT_SIZE,
                                                GroupLayout.PREFERRED_SIZE,
                                                GroupLayout.PREFERRED_SIZE))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addComponent(buttonsGlue)
                                        .addComponent(getEncodeButton())
                                        .addComponent(getDecodeButton())));
        setContentPane(panel);
        this.addWindowListener(
                new java.awt.event.WindowAdapter() {

                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        clearAndDispose();
                    }
                });

        pack();
    }

    private JScrollPane getEncodedTxtScrollPane() {
        if (encodedtxtScrollPane == null) {
            encodedtxtScrollPane = new JScrollPane();
            encodedtxtScrollPane.setHorizontalScrollBarPolicy(
                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            encodedtxtScrollPane.setViewportView(getEncodedtxtDisplay());
        }
        return encodedtxtScrollPane;
    }

    private JScrollPane getDecodedTxtScrollPane() {
        if (decodedtxtScrollPane == null) {
            decodedtxtScrollPane = new JScrollPane();
            decodedtxtScrollPane.setHorizontalScrollBarPolicy(
                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            decodedtxtScrollPane.setVerticalScrollBarPolicy(
                    ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            decodedtxtScrollPane.setViewportView(getDecodedtxtDisplay());
        }
        return decodedtxtScrollPane;
    }

    private void clearAndDispose() {
        this.setVisible(false);
        this.dispose();
    }

    private ZapTextArea getDecodedtxtDisplay() {
        if (decodedtxtDisplay == null) {
            decodedtxtDisplay = new ZapTextArea("", 15, 40);
            decodedtxtDisplay.setBorder(
                    BorderFactory.createCompoundBorder(
                            BorderFactory.createTitledBorder(
                                    Constant.messages.getString(
                                            "grpc.protobufeditordialog.decode")),
                            BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        }
        return decodedtxtDisplay;
    }

    private ZapTextArea getEncodedtxtDisplay() {
        if (encodedtxtDisplay == null) {
            encodedtxtDisplay = new ZapTextArea("", 1, 40);
            encodedtxtDisplay.setBorder(
                    BorderFactory.createCompoundBorder(
                            BorderFactory.createTitledBorder(
                                    Constant.messages.getString(
                                            "grpc.protobufeditordialog.encode")),
                            BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        }

        return encodedtxtDisplay;
    }

    private JButton getDecodeButton() {
        if (DecodeTextButton == null) {
            DecodeTextButton =
                    new JButton(
                            Constant.messages.getString("grpc.protobufeditordialog.decode.button"));

            // DecodeTextButton.addActionListener(e->decodeText());
        }
        return DecodeTextButton;
    }

    private JButton getEncodeButton() {
        if (EncodeTextButton == null) {
            EncodeTextButton =
                    new JButton(
                            Constant.messages.getString("grpc.protobufeditordialog.encode.button"));
            // EncodeTextButton.addActionListener(e->encodeText());

        }
        return EncodeTextButton;
    }
}
