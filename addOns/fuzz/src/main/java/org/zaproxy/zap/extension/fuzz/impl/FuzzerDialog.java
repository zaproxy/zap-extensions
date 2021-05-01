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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.border.EtchedBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandlersRegistry;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class FuzzerDialog<
                M extends Message, FO extends FuzzerOptions, FMP extends FuzzerMessageProcessor<M>>
        extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private JButton[] extraButtons = null;

    private FuzzMessageLocationsPanel fuzzLocationsPanel;

    private boolean outgoingMessage;
    private FuzzMessagePanel fuzzMessagePanel;

    private PayloadGeneratorsContainer payloadGeneratorsUIHandlers;

    private JPanel messageFuzzLocationsPanel = null;
    private FuzzerOptionsPanel<FO> optionsPanel = null;

    private List<PayloadGeneratorMessageLocation<?>> fuzzLocations;
    private FuzzerMessageProcessorsTablePanel<M, FMP> fuzzerMessageProcessorsTablePanel;

    public FuzzerDialog(
            Frame owner,
            FuzzerOptions defaultOptions,
            M message,
            boolean outgoing,
            FuzzerHandlerOptionsPanel<FO> fuzzerHandlerOptionsPanel,
            FuzzerMessageProcessors<M, FMP> fuzzerMessageProcessors) {
        super(
                owner,
                "fuzz.fuzzer.dialog.title",
                new Dimension(900, 600),
                new String[] {
                    "fuzz.fuzzer.dialog.tab.fuzzLocations",
                    "fuzz.fuzzer.dialog.tab.options",
                    "fuzz.fuzzer.dialog.tab.messageprocessors"
                });

        setModalityType(ModalityType.DOCUMENT_MODAL);

        this.removeAllFields();

        this.fuzzLocations = Collections.emptyList();

        this.payloadGeneratorsUIHandlers =
                new PayloadGeneratorsContainer(
                        PayloadGeneratorUIHandlersRegistry.getInstance()
                                .getPayloadGeneratorUIHandlers(),
                        PayloadGeneratorUIHandlersRegistry.getInstance()
                                .getNameDefaultPayloadGenerator());

        outgoingMessage = outgoing;
        this.fuzzMessagePanel = new FuzzMessagePanel();
        if (outgoingMessage) {
            fuzzMessagePanel.addComponent(new RequestSplitComponent<>(), new ZapXmlConfiguration());
            HttpPanelManager.getInstance().addRequestPanel(fuzzMessagePanel);
            withExtensionFuzz(ext -> ext.getClientMessagePanelManager().addPanel(fuzzMessagePanel));
        } else {
            fuzzMessagePanel.addComponent(
                    new ResponseSplitComponent<>(), new ZapXmlConfiguration());
            HttpPanelManager.getInstance().addResponsePanel(fuzzMessagePanel);
            withExtensionFuzz(ext -> ext.getServerMessagePanelManager().addPanel(fuzzMessagePanel));
        }
        fuzzMessagePanel.setMessage(message, true);

        fuzzLocationsPanel =
                new FuzzMessageLocationsPanel(this, fuzzMessagePanel, payloadGeneratorsUIHandlers);
        fuzzMessagePanel.addFocusListener(fuzzLocationsPanel.getFocusListenerAddButtonEnabler());

        optionsPanel =
                new FuzzerOptionsPanel<>(
                        Constant.messages.getMessageBundle("fuzz"),
                        defaultOptions,
                        fuzzerHandlerOptionsPanel);

        this.setCustomTabPanel(0, getMessageFuzzLocationsPanel());
        this.setCustomTabPanel(1, optionsPanel);
        if (fuzzerMessageProcessors.isEmpty()) {
            setTabsVisible(new String[] {"fuzz.fuzzer.dialog.tab.messageprocessors"}, false);
        } else {
            fuzzerMessageProcessorsTablePanel =
                    new FuzzerMessageProcessorsTablePanel<>(this, message, fuzzerMessageProcessors);
            this.setCustomTabPanel(2, fuzzerMessageProcessorsTablePanel);
        }
    }

    private static void withExtensionFuzz(Consumer<ExtensionFuzz> consumer) {
        ExtensionFuzz extFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        if (extFuzz != null) {
            consumer.accept(extFuzz);
        }
    }

    @Override
    public void dispose() {
        super.dispose();

        if (outgoingMessage) {
            HttpPanelManager.getInstance().removeRequestPanel(fuzzMessagePanel);
            withExtensionFuzz(
                    ext -> ext.getClientMessagePanelManager().removePanel(fuzzMessagePanel));
        } else {
            HttpPanelManager.getInstance().removeResponsePanel(fuzzMessagePanel);
            withExtensionFuzz(
                    ext -> ext.getServerMessagePanelManager().removePanel(fuzzMessagePanel));
        }
    }

    public boolean setSelectedContainer(String containerName) {
        if (containerName == null || containerName.isEmpty()) {
            throw new IllegalArgumentException(
                    "Parameter containerName must not be null nor empty.");
        }
        return fuzzMessagePanel.setSelectedView(containerName);
    }

    public boolean addMessageLocation(MessageLocation messageLocation) {
        if (messageLocation == null) {
            throw new IllegalArgumentException("Parameter messageLocation must not be null.");
        }
        return fuzzLocationsPanel.addMessageLocation(messageLocation);
    }

    @Override
    public String getHelpIndex() {
        return "addon.fuzzer.dialogue";
    }

    private JPanel getMessageFuzzLocationsPanel() {
        if (messageFuzzLocationsPanel == null) {
            messageFuzzLocationsPanel = new JPanel(new BorderLayout());

            JPanel rightPanel = new JPanel();
            GroupLayout leftPanelLayout = new GroupLayout(rightPanel);
            rightPanel.setLayout(leftPanelLayout);

            leftPanelLayout.setAutoCreateGaps(true);
            leftPanelLayout.setAutoCreateContainerGaps(true);

            JLabel fuzzLocationsLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "fuzz.fuzzer.dialog.messagelocations.locations.label"));

            leftPanelLayout.setHorizontalGroup(
                    leftPanelLayout
                            .createParallelGroup()
                            .addComponent(fuzzLocationsLabel)
                            .addComponent(fuzzLocationsPanel));

            leftPanelLayout.setVerticalGroup(
                    leftPanelLayout
                            .createSequentialGroup()
                            .addComponent(fuzzLocationsLabel)
                            .addComponent(fuzzLocationsPanel));

            JSplitPane splitPane =
                    new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, fuzzMessagePanel, rightPanel);
            splitPane.setResizeWeight(0.6d);

            messageFuzzLocationsPanel.add(splitPane);
            messageFuzzLocationsPanel.setBorder(
                    BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
        }

        return messageFuzzLocationsPanel;
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("fuzz.fuzzer.dialog.button.start");
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton resetButton =
                    new JButton(Constant.messages.getString("fuzz.fuzzer.dialog.button.reset"));
            resetButton.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            fuzzLocationsPanel.reset();
                            optionsPanel.reset();
                            fuzzMessagePanel.reset();
                            if (fuzzerMessageProcessorsTablePanel != null) {
                                fuzzerMessageProcessorsTablePanel.reset();
                            }
                        }
                    });

            extraButtons = new JButton[] {resetButton};
        }
        return extraButtons;
    }

    @Override
    public void save() {
        fuzzLocations = fuzzLocationsPanel.getFuzzMessageLocations();
    }

    @Override
    protected boolean validateFieldsCustomMessage() {
        return optionsPanel.validateFields();
    }

    @Override
    public String validateFields() {
        if (!fuzzLocationsPanel.hasLocations()) {
            return Constant.messages.getString("fuzz.fuzzer.dialog.warn.noFuzzLocations");
        }
        if (!fuzzLocationsPanel.hasAllLocationsWithPayloads()) {
            return Constant.messages.getString("fuzz.fuzzer.dialog.warn.noPayloadsSomeLocations");
        }
        return null;
    }

    public List<PayloadGeneratorMessageLocation<?>> getFuzzLocations() {
        return fuzzLocations;
    }

    public FO getFuzzerOptions() {
        return optionsPanel.getFuzzerOptions();
    }

    public List<FMP> getFuzzerMessageProcessors() {
        return fuzzerMessageProcessorsTablePanel.getMessageProcessors();
    }
}
