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
package org.zaproxy.addon.oast.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.HashMap;
import java.util.Map;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.addon.oast.OastService;
import org.zaproxy.addon.oast.OastState;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;

@SuppressWarnings("serial")
public class OastPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private static final DateTimeFormatter ISO_HH_MM_SS =
            new DateTimeFormatterBuilder()
                    .appendValue(ChronoField.HOUR_OF_DAY, 2)
                    .appendLiteral(':')
                    .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
                    .optionalStart()
                    .appendLiteral(':')
                    .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
                    .toFormatter();

    private JToolBar mainToolBar;
    private JPanel mainPanel = null;
    private JScrollPane scrollPane = null;
    private Map<String, JLabel> serviceStateLabels = null;
    private OastTable resultsTable = null;
    private OastTableModel model = null;
    private final ExtensionOast extensionOast;

    private static final ImageIcon REGISTERED_ICON = getImageIcon("/resource/icon/16/152.png");
    private static final ImageIcon UNREGISTERED_ICON =
            DisplayUtils.isDarkLookAndFeel()
                    ? getImageIcon("/resource/icon/16/158.png")
                    : getImageIcon("/resource/icon/16/159.png");
    private static final ImageIcon REGISTERED_ACTIVE_ICON =
            getImageIcon("/org/zaproxy/addon/oast/resources/icons/oast_active_registered.png");
    private static final ImageIcon UNREGISTERED_ACTIVE_ICON =
            DisplayUtils.isDarkLookAndFeel()
                    ? getImageIcon(
                            "/org/zaproxy/addon/oast/resources/icons/oast_active_unregistered_dark.png")
                    : getImageIcon(
                            "/org/zaproxy/addon/oast/resources/icons/oast_active_unregistered.png");

    public OastPanel(ExtensionOast extensionOast) {
        super();
        this.extensionOast = extensionOast;

        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("oast.panel.name"));
        this.setIcon(getImageIcon("/resource/icon/16/callbacks.png"));
        this.add(getMainPanel(), getMainPanel().getName());
    }

    private javax.swing.JPanel getMainPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.setName("OastPanel");
            mainPanel.add(getToolBar(), BorderLayout.PAGE_START);
            mainPanel.add(getJScrollPane(), BorderLayout.CENTER);
        }

        return mainPanel;
    }

    private JToolBar getToolBar() {
        if (mainToolBar == null) {
            mainToolBar = new JToolBar();
            mainToolBar.setEnabled(true);
            mainToolBar.setFloatable(false);
            mainToolBar.setRollover(true);
            mainToolBar.setName("Callback Toolbar");

            mainToolBar.add(getClearButton());
            mainToolBar.add(getPollNowButton());
            mainToolBar.add(Box.createHorizontalGlue());
            getServiceStateLabels().forEach((k, v) -> mainToolBar.add(v));
            mainToolBar.add(getOptionsButton());
        }
        return mainToolBar;
    }

    private Map<String, JLabel> getServiceStateLabels() {
        if (serviceStateLabels == null) {
            serviceStateLabels = new HashMap<>();
            for (Map.Entry<String, OastService> e : extensionOast.getOastServices().entrySet()) {
                if (e.getKey().equals(extensionOast.getCallbackService().getName())) {
                    continue;
                }

                JLabel serviceStateLabel =
                        new JLabel(
                                e.getKey(), getStatusIcon(e.getKey(), false), SwingConstants.RIGHT);
                serviceStateLabel.setBorder(new EmptyBorder(0, 0, 0, 10));
                serviceStateLabels.put(e.getKey(), serviceStateLabel);
                OastService service = e.getValue();
                service.addOastStateChangedListener(this::oastStateChangedListener);
            }
        }
        return serviceStateLabels;
    }

    private void oastStateChangedListener(OastState state) {
        SwingUtilities.invokeLater(
                () -> {
                    JLabel serviceStateLabel = serviceStateLabels.get(state.getServiceName());
                    if (!state.isRegistered()) {
                        serviceStateLabel.setIcon(getStatusIcon(state.getServiceName(), false));
                        serviceStateLabel.setText(state.getServiceName());
                        return;
                    }
                    serviceStateLabel.setIcon(getStatusIcon(state.getServiceName(), true));
                    if (state.getLastPollTime() != null) {
                        String lastPoll = state.getLastPollTime().format(ISO_HH_MM_SS);
                        serviceStateLabel.setText(
                                Constant.messages.getString(
                                        "oast.panel.currentState.lastPoll",
                                        state.getServiceName(),
                                        lastPoll));
                        serviceStateLabel.setToolTipText(
                                Constant.messages.getString(
                                        "oast.panel.currentState.tooltip.lastPolled",
                                        state.getServiceName()));
                    }
                });
    }

    private JButton getClearButton() {
        JButton clearButton =
                new JButton(Constant.messages.getString("oast.panel.clear.button.label"));
        clearButton.setToolTipText(Constant.messages.getString("oast.panel.clear.button.toolTip"));
        clearButton.setIcon(getImageIcon("/resource/icon/fugue/broom.png"));
        clearButton.addActionListener(e -> extensionOast.deleteAllCallbacks());
        return clearButton;
    }

    private JButton getPollNowButton() {
        JButton pollNowButton =
                new JButton(Constant.messages.getString("oast.panel.pollNow.button.label"));
        pollNowButton.setToolTipText(
                Constant.messages.getString("oast.panel.pollNow.button.toolTip"));
        pollNowButton.setIcon(getImageIcon("/resource/icon/16/124.png"));
        pollNowButton.addActionListener(e -> extensionOast.pollAllServices());
        return pollNowButton;
    }

    private JButton getOptionsButton() {
        JButton optionsButton = new JButton();
        optionsButton.setToolTipText(
                Constant.messages.getString("oast.panel.options.button.label"));
        optionsButton.setIcon(getImageIcon("/resource/icon/16/041.png"));
        optionsButton.addActionListener(
                e ->
                        Control.getSingleton()
                                .getMenuToolsControl()
                                .options(Constant.messages.getString("oast.options.title")));
        return optionsButton;
    }

    private JScrollPane getJScrollPane() {
        if (scrollPane == null) {
            scrollPane = new JScrollPane();
            scrollPane.setFont(FontUtils.getFont("Dialog"));
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setViewportView(getResultsTable());
        }

        return scrollPane;
    }

    private OastTable getResultsTable() {
        if (this.resultsTable == null) {
            this.model = new OastTableModel();
            this.resultsTable = new OastTable(model);
        }
        return this.resultsTable;
    }

    public void addOastRequest(OastRequest oastRequest) {
        model.addEntry(oastRequest);
    }

    public void clearOastRequests() {
        model.clear();
    }

    private static ImageIcon getImageIcon(String resourceName) {
        return DisplayUtils.getScaledIcon(new ImageIcon(OastPanel.class.getResource(resourceName)));
    }

    private ImageIcon getStatusIcon(String serviceName, boolean registered) {
        OastService activeScanService = extensionOast.getActiveScanOastService();
        if (activeScanService != null && activeScanService.getName().equals(serviceName)) {
            return registered ? REGISTERED_ACTIVE_ICON : UNREGISTERED_ACTIVE_ICON;
        } else {
            return registered ? REGISTERED_ICON : UNREGISTERED_ICON;
        }
    }
}
