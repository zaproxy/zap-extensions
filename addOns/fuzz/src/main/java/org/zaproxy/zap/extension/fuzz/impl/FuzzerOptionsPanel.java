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
import java.awt.event.ItemEvent;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.LayoutStyle;
import javax.swing.border.EtchedBorder;
import org.zaproxy.zap.extension.fuzz.FuzzOptions;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.PositiveValuesSlider;

public class FuzzerOptionsPanel<FO extends FuzzerOptions> extends JPanel {

    private static final long serialVersionUID = -6701853630031984651L;

    private final ZapNumberSpinner retriesOnIOErrorNumberSpinner;
    private final JCheckBox maxErrorsAllowedEnabledCheckBox;
    private final ZapNumberSpinner maxErrorsAllowedNumberSpinner;
    private final JRadioButton depthFirstPayloadReplacementStrategyRadioButton;
    private final JRadioButton breadthFirstPayloadReplacementStrategyRadioButton;
    private final JSlider defaultThreadsPerFuzzerSlider;
    private final ZapNumberSpinner defaultFuzzDelayInMsSpinner;

    private final FuzzerHandlerOptionsPanel<FO> fuzzerHandlerOptions;

    private final FuzzerOptions defaultOptions;

    public FuzzerOptionsPanel(
            ResourceBundle resourceBundle,
            FuzzerOptions defaultOptions,
            FuzzerHandlerOptionsPanel<FO> fuzzerHandlerOptions) {
        super(new BorderLayout());

        this.defaultOptions = defaultOptions;
        this.fuzzerHandlerOptions = fuzzerHandlerOptions;

        retriesOnIOErrorNumberSpinner =
                new ZapNumberSpinner(0, defaultOptions.getRetriesOnIOError(), Integer.MAX_VALUE);
        JLabel retriesOnIOErrorLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.retriesOnIOError"));
        retriesOnIOErrorLabel.setLabelFor(retriesOnIOErrorNumberSpinner);

        maxErrorsAllowedEnabledCheckBox = new JCheckBox();
        maxErrorsAllowedEnabledCheckBox.setSelected(true);
        JLabel maxErrorsAllowedEnabledLabel =
                new JLabel(
                        resourceBundle.getString(
                                "fuzz.fuzzer.dialog.tab.options.label.maxErrorsAllowedEnabled"));
        maxErrorsAllowedEnabledLabel.setLabelFor(maxErrorsAllowedEnabledCheckBox);
        maxErrorsAllowedNumberSpinner =
                new ZapNumberSpinner(0, defaultOptions.getMaxErrorsAllowed(), Integer.MAX_VALUE);
        JLabel maxErrorsAllowedLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.maxErrorsAllowed"));
        maxErrorsAllowedLabel.setLabelFor(maxErrorsAllowedNumberSpinner);
        maxErrorsAllowedEnabledCheckBox.addItemListener(
                e ->
                        maxErrorsAllowedNumberSpinner.setEnabled(
                                ItemEvent.SELECTED == e.getStateChange()));

        JLabel currentDefaultThreadsPerFuzzerLabel = new JLabel();
        defaultThreadsPerFuzzerSlider =
                createDefaultThreadsPerFuzzerSlider(
                        defaultOptions.getThreadCount(),
                        FuzzOptions.MAX_THREADS_PER_FUZZER,
                        currentDefaultThreadsPerFuzzerLabel);
        JLabel defaultFuzzThreadsPerFuzzerLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.threads"));
        defaultFuzzThreadsPerFuzzerLabel.setLabelFor(defaultThreadsPerFuzzerSlider);
        currentDefaultThreadsPerFuzzerLabel.setText(
                Integer.toString(defaultOptions.getThreadCount()));

        defaultFuzzDelayInMsSpinner =
                new ZapNumberSpinner(
                        0, (int) defaultOptions.getSendMessageDelay(), FuzzOptions.MAX_DELAY_IN_MS);
        JLabel defaultFuzzDelayLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.delayInMs"));
        defaultFuzzDelayLabel.setLabelFor(defaultFuzzDelayInMsSpinner);

        ButtonGroup replacementStrategyButtonGroup = new ButtonGroup();
        depthFirstPayloadReplacementStrategyRadioButton =
                new JRadioButton(
                        resourceBundle.getString(
                                "fuzz.options.label.payloadReplacementStrategy.depthFirst"));
        replacementStrategyButtonGroup.add(depthFirstPayloadReplacementStrategyRadioButton);
        breadthFirstPayloadReplacementStrategyRadioButton =
                new JRadioButton(
                        resourceBundle.getString(
                                "fuzz.options.label.payloadReplacementStrategy.breadthFirst"));
        replacementStrategyButtonGroup.add(breadthFirstPayloadReplacementStrategyRadioButton);
        JLabel payloadReplacementStrategyLabel =
                new JLabel(
                        resourceBundle.getString("fuzz.options.label.payloadReplacementStrategy"));
        payloadReplacementStrategyLabel.setLabelFor(
                depthFirstPayloadReplacementStrategyRadioButton);

        if (MessageLocationsReplacementStrategy.DEPTH_FIRST
                == defaultOptions.getPayloadsReplacementStrategy()) {
            depthFirstPayloadReplacementStrategyRadioButton.setSelected(true);
        } else {
            breadthFirstPayloadReplacementStrategyRadioButton.setSelected(true);
        }

        JPanel innerPanel = new JPanel();
        GroupLayout layout = new GroupLayout(innerPanel);
        innerPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(retriesOnIOErrorLabel))
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(
                                                                retriesOnIOErrorNumberSpinner)))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addGroup(
                                                                layout.createParallelGroup()
                                                                        .addComponent(
                                                                                maxErrorsAllowedEnabledLabel))
                                                        .addGroup(
                                                                layout.createParallelGroup()
                                                                        .addComponent(
                                                                                maxErrorsAllowedEnabledCheckBox)))
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addPreferredGap(
                                                                maxErrorsAllowedEnabledLabel,
                                                                maxErrorsAllowedLabel,
                                                                LayoutStyle.ComponentPlacement
                                                                        .INDENT)
                                                        .addGroup(
                                                                layout.createSequentialGroup()
                                                                        .addGroup(
                                                                                layout.createParallelGroup()
                                                                                        .addComponent(
                                                                                                maxErrorsAllowedLabel))
                                                                        .addGroup(
                                                                                layout.createParallelGroup()
                                                                                        .addComponent(
                                                                                                maxErrorsAllowedNumberSpinner)))))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addComponent(payloadReplacementStrategyLabel)
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addPreferredGap(
                                                                payloadReplacementStrategyLabel,
                                                                depthFirstPayloadReplacementStrategyRadioButton,
                                                                LayoutStyle.ComponentPlacement
                                                                        .INDENT)
                                                        .addComponent(
                                                                depthFirstPayloadReplacementStrategyRadioButton))
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addPreferredGap(
                                                                payloadReplacementStrategyLabel,
                                                                breadthFirstPayloadReplacementStrategyRadioButton,
                                                                LayoutStyle.ComponentPlacement
                                                                        .INDENT)
                                                        .addComponent(
                                                                breadthFirstPayloadReplacementStrategyRadioButton)))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addComponent(
                                                                defaultFuzzThreadsPerFuzzerLabel)
                                                        .addComponent(
                                                                currentDefaultThreadsPerFuzzerLabel))
                                        .addComponent(defaultThreadsPerFuzzerSlider))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(defaultFuzzDelayLabel)
                                        .addComponent(defaultFuzzDelayInMsSpinner))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(fuzzerHandlerOptions.getPanel())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(retriesOnIOErrorLabel)
                                        .addComponent(retriesOnIOErrorNumberSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(maxErrorsAllowedEnabledLabel)
                                        .addComponent(maxErrorsAllowedEnabledCheckBox))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(maxErrorsAllowedLabel)
                                        .addComponent(maxErrorsAllowedNumberSpinner))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(payloadReplacementStrategyLabel)
                                        .addComponent(
                                                depthFirstPayloadReplacementStrategyRadioButton)
                                        .addComponent(
                                                breadthFirstPayloadReplacementStrategyRadioButton))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(
                                                                defaultFuzzThreadsPerFuzzerLabel)
                                                        .addComponent(
                                                                currentDefaultThreadsPerFuzzerLabel))
                                        .addComponent(defaultThreadsPerFuzzerSlider))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(defaultFuzzDelayLabel)
                                        .addComponent(defaultFuzzDelayInMsSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(fuzzerHandlerOptions.getPanel())));

        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(innerPanel);
        scrollPane.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));

        add(scrollPane);
    }

    private JSlider createDefaultThreadsPerFuzzerSlider(
            int value, int maxThreadsPerFuzzer, final JLabel currentValueFeedbackLabel) {
        final JSlider threadsSlider = new PositiveValuesSlider(value, maxThreadsPerFuzzer);
        threadsSlider.addChangeListener(
                e -> currentValueFeedbackLabel.setText(Integer.toString(threadsSlider.getValue())));
        return threadsSlider;
    }

    public boolean validateFields() {
        FuzzerOptions baseOptions =
                new FuzzerOptions(
                        defaultThreadsPerFuzzerSlider.getValue(),
                        retriesOnIOErrorNumberSpinner.getValue().intValue(),
                        getMaxErrorsAllowed(),
                        defaultFuzzDelayInMsSpinner.getValue(),
                        TimeUnit.MILLISECONDS,
                        getSelectedStrategy());

        return fuzzerHandlerOptions.validate(baseOptions);
    }

    private int getMaxErrorsAllowed() {
        if (!maxErrorsAllowedEnabledCheckBox.isSelected()) {
            return -1;
        }
        return maxErrorsAllowedNumberSpinner.getValue().intValue();
    }

    private MessageLocationsReplacementStrategy getSelectedStrategy() {
        MessageLocationsReplacementStrategy strategy;
        if (depthFirstPayloadReplacementStrategyRadioButton.isSelected()) {
            strategy = MessageLocationsReplacementStrategy.DEPTH_FIRST;
        } else {
            strategy = MessageLocationsReplacementStrategy.BREADTH_FIRST;
        }
        return strategy;
    }

    public FO getFuzzerOptions() {
        FuzzerOptions baseOptions =
                new FuzzerOptions(
                        defaultThreadsPerFuzzerSlider.getValue(),
                        retriesOnIOErrorNumberSpinner.getValue().intValue(),
                        getMaxErrorsAllowed(),
                        defaultFuzzDelayInMsSpinner.getValue(),
                        TimeUnit.MILLISECONDS,
                        getSelectedStrategy());

        return fuzzerHandlerOptions.getOptions(baseOptions);
    }

    public void reset() {
        defaultThreadsPerFuzzerSlider.setValue(defaultOptions.getThreadCount());
        retriesOnIOErrorNumberSpinner.setValue(defaultOptions.getRetriesOnIOError());
        maxErrorsAllowedEnabledCheckBox.setSelected(true);
        maxErrorsAllowedNumberSpinner.setValue(defaultOptions.getMaxErrorsAllowed());
        defaultFuzzDelayInMsSpinner.setValue((int) defaultOptions.getSendMessageDelay());
        depthFirstPayloadReplacementStrategyRadioButton.setSelected(
                MessageLocationsReplacementStrategy.DEPTH_FIRST
                        == defaultOptions.getPayloadsReplacementStrategy());
        fuzzerHandlerOptions.reset();
    }
}
