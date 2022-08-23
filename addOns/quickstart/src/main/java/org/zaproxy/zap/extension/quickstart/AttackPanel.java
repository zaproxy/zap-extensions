/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import java.awt.GridBagLayout;
import java.net.URL;
import java.util.List;
import javax.swing.Box;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.search.SearchPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

@SuppressWarnings("serial")
public class AttackPanel extends QuickStartSubPanel {
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_VALUE_URL_FIELD = "http://";

    private JButton attackButton;
    private JButton stopButton;
    private JComboBox<String> urlField;
    private DefaultComboBoxModel<String> urlModel;
    private JButton selectButton;
    private JLabel progressLabel;
    private JPanel contentPanel;
    private JLabel lowerPadding;
    private int paddingY;

    private TraditionalSpider traditionalSpider;
    private JLabel traditionalSpiderLabel;
    private int traditionalSpiderY;

    /** Optional class that adds the ajax spider - may be added after init or not at all */
    private PlugableSpider plugableSpider;

    private JLabel plugableSpiderLabel;
    private int plugableSpiderY;

    public AttackPanel(ExtensionQuickStart extension, QuickStartPanel qsp) {
        super(extension, qsp);

        this.setMode(Control.getSingleton().getMode());
    }

    @Override
    public String getTitleKey() {
        return "quickstart.attack.panel.title";
    }

    @Override
    public JPanel getDescriptionPanel() {
        JPanel panel = new QuickStartBackgroundPanel();
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.attack.panel.message1"),
                LayoutHelper.getGBC(0, 0, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.attack.panel.message2"),
                LayoutHelper.getGBC(0, 1, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                new JLabel(" "),
                LayoutHelper.getGBC(
                        0, 2, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer
        return panel;
    }

    @Override
    public JPanel getContentPanel() {
        if (contentPanel == null) {
            contentPanel = new QuickStartBackgroundPanel();
            int formPanelY = 0;

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.label.attackurl")),
                    LayoutHelper.getGBC(
                            1, formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            JPanel urlSelectPanel = new JPanel(new GridBagLayout());
            selectButton = new JButton(Constant.messages.getString("all.button.select"));
            selectButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    View.class.getResource("/resource/icon/16/094.png")))); // Globe
            // icon
            selectButton.addActionListener(
                    e -> {
                        NodeSelectDialog nsd =
                                new NodeSelectDialog(View.getSingleton().getMainFrame());
                        SiteNode node = null;
                        try {
                            node =
                                    Model.getSingleton()
                                            .getSession()
                                            .getSiteTree()
                                            .findNode(
                                                    new URI(
                                                            getUrlField()
                                                                    .getSelectedItem()
                                                                    .toString(),
                                                            false));
                        } catch (Exception e2) {
                            // Ignore
                        }
                        node = nsd.showDialog(node);
                        if (node != null && node.getHistoryReference() != null) {
                            try {
                                getUrlField()
                                        .setSelectedItem(
                                                node.getHistoryReference().getURI().toString());
                            } catch (Exception e1) {
                                // Ignore
                            }
                        }
                    });

            urlSelectPanel.add(this.getUrlField(), LayoutHelper.getGBC(0, 0, 1, 0.5D));
            urlSelectPanel.add(selectButton, LayoutHelper.getGBC(1, 0, 1, 0.0D));
            contentPanel.add(urlSelectPanel, LayoutHelper.getGBC(2, formPanelY, 3, 0.25D));

            traditionalSpiderY = ++formPanelY;
            plugableSpiderY = ++formPanelY;

            JPanel buttonPanel = QuickStartHelper.getHorizontalPanel();
            buttonPanel.add(this.getAttackButton());
            buttonPanel.add(this.getStopButton());
            buttonPanel.add(Box.createHorizontalGlue());
            contentPanel.add(buttonPanel, LayoutHelper.getGBC(2, ++formPanelY, 1, 1.0D));

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.label.progress")),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(getProgressLabel(), LayoutHelper.getGBC(2, formPanelY, 1, 1.0D));

            paddingY = ++formPanelY;
            this.replacePadding();
        }

        return contentPanel;
    }

    private JLabel getProgressLabel() {
        if (progressLabel == null) {
            progressLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "quickstart.progress."
                                            + AttackThread.Progress.notstarted.name()));
        }
        return progressLabel;
    }

    public void setTraditionalSpider(TraditionalSpider traditionalSpider) {
        if (traditionalSpider == null) {
            contentPanel.remove(traditionalSpiderLabel);
            traditionalSpiderLabel = null;
            contentPanel.remove(this.traditionalSpider.getComponent());
        } else {
            traditionalSpiderLabel = new JLabel(traditionalSpider.getLabel());
            contentPanel.add(
                    traditionalSpiderLabel,
                    LayoutHelper.getGBC(
                            1,
                            traditionalSpiderY,
                            1,
                            0.0D,
                            DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            contentPanel.add(
                    traditionalSpider.getComponent(),
                    LayoutHelper.getGBC(
                            2,
                            traditionalSpiderY,
                            1,
                            0.0D,
                            DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        }

        this.traditionalSpider = traditionalSpider;

        validate();
        repaint();
    }

    public void addPlugableSpider(PlugableSpider plugableSpider) {
        this.plugableSpider = plugableSpider;
        addAjaxSpiderGui();
    }

    public void removePlugableSpider(PlugableSpider plugableSpider) {
        if (contentPanel != null && plugableSpider != null) {
            contentPanel.remove(plugableSpiderLabel);
            contentPanel.remove(plugableSpider.getPanel());
            replacePadding();
        }
        this.plugableSpider = null;
    }

    private void addAjaxSpiderGui() {
        if (contentPanel != null && this.plugableSpider != null) {
            plugableSpiderLabel = new JLabel(this.plugableSpider.getLabel());
            contentPanel.add(
                    plugableSpiderLabel,
                    LayoutHelper.getGBC(
                            1, plugableSpiderY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(
                    this.plugableSpider.getPanel(),
                    LayoutHelper.getGBC(2, plugableSpiderY, 1, 1.0D));
            replacePadding();
        }
    }

    private void replacePadding() {
        if (contentPanel != null) {
            // this may or may not be present
            if (this.lowerPadding == null) {
                lowerPadding = new JLabel("");
            } else {
                contentPanel.remove(this.lowerPadding);
            }
            contentPanel.add(
                    lowerPadding,
                    LayoutHelper.getGBC(0, paddingY, 1, 0.0D, 1.0D)); // Padding at bottom
        }
    }

    protected void setMode(Mode mode) {
        switch (mode) {
            case safe:
            case protect:
                this.getUrlField().setEnabled(false);
                this.getUrlField()
                        .setSelectedItem(
                                Constant.messages.getString("quickstart.field.url.disabled.mode"));
                this.selectButton.setEnabled(false);
                this.getAttackButton().setEnabled(false);
                break;
            case standard:
            case attack:
                this.getUrlField().setEnabled(true);
                this.getUrlField().setSelectedItem(DEFAULT_VALUE_URL_FIELD);
                this.selectButton.setEnabled(true);
                this.getAttackButton().setEnabled(true);
                break;
        }
    }

    private JComboBox<String> getUrlField() {
        if (urlField == null) {
            urlField = new JComboBox<>();
            urlField.setEditable(true);
            urlField.setModel(getUrlModel());
            setRecentUrls();
        }
        return urlField;
    }

    protected DefaultComboBoxModel<String> getUrlModel() {
        if (urlModel == null) {
            urlModel = new DefaultComboBoxModel<>();
        }
        return urlModel;
    }

    private void setRecentUrls() {
        if (urlField != null) {
            QuickStartParam quickStartParam = this.getExtensionQuickStart().getQuickStartParam();
            Object currentUrl = urlField.getSelectedItem();
            DefaultComboBoxModel<String> model = getUrlModel();
            model.removeAllElements();
            List<Object> recentUrls = quickStartParam.getRecentUrls();
            for (Object url : recentUrls) {
                if (url != null) {
                    model.addElement(url.toString());
                }
            }
            if (currentUrl != null && currentUrl.toString().length() > 0) {
                urlField.setSelectedItem(currentUrl);
            } else {
                urlField.setSelectedItem(DEFAULT_VALUE_URL_FIELD);
            }
        }
    }

    private JButton getAttackButton() {
        if (attackButton == null) {
            attackButton = new JButton();
            attackButton.setText(Constant.messages.getString("quickstart.button.label.attack"));
            attackButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    SearchPanel.class.getResource(
                                            "/resource/icon/16/147.png")))); // 'lightning'
            // icon
            attackButton.setToolTipText(
                    Constant.messages.getString("quickstart.button.tooltip.attack"));

            attackButton.addActionListener(
                    e -> {
                        if ((traditionalSpider == null || !traditionalSpider.isSelected())
                                && (plugableSpider == null || !plugableSpider.isSelected())) {
                            getExtensionQuickStart()
                                    .getView()
                                    .showWarningDialog(
                                            Constant.messages.getString(
                                                    "quickstart.url.warning.nospider"));
                        } else {
                            attackUrl();
                        }
                    });
        }
        return attackButton;
    }

    private JButton getStopButton() {
        if (stopButton == null) {
            stopButton = new JButton();
            stopButton.setText(Constant.messages.getString("quickstart.button.label.stop"));
            stopButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    SearchPanel.class.getResource(
                                            "/resource/icon/16/142.png")))); // 'stop'
            // icon
            stopButton.setToolTipText(
                    Constant.messages.getString("quickstart.button.tooltip.stop"));
            stopButton.setEnabled(false);

            stopButton.addActionListener(e -> stopAttack());
        }
        return stopButton;
    }

    boolean attackUrl() {
        Object item = this.getUrlField().getSelectedItem();
        if (item == null || DEFAULT_VALUE_URL_FIELD.equals(item.toString())) {
            getExtensionQuickStart()
                    .getView()
                    .showWarningDialog(
                            Constant.messages.getString("quickstart.url.warning.invalid"));
            this.getUrlField().requestFocusInWindow();
            return false;
        }
        String urlStr = item.toString();
        URL url;
        try {
            url = new URL(urlStr);
            // Validate the actual request-uri of the HTTP message accessed.
            new URI(urlStr, true);
        } catch (Exception e) {
            getExtensionQuickStart()
                    .getView()
                    .showWarningDialog(
                            Constant.messages.getString("quickstart.url.warning.invalid"));
            this.getUrlField().requestFocusInWindow();
            return false;
        }
        this.getExtensionQuickStart().getQuickStartParam().addRecentUrl(urlStr);
        getAttackButton().setEnabled(false);
        getStopButton().setEnabled(true);

        getExtensionQuickStart()
                .attack(url, traditionalSpider != null && traditionalSpider.isSelected());
        setSpiderButtonsEnabled(false);
        return true;
    }

    void setAttackUrl(String url) {
        getUrlField().setSelectedItem(url);
    }

    private void stopAttack() {
        getExtensionQuickStart().stopAttack();

        stopButton.setEnabled(false);
    }

    private void setSpiderButtonsEnabled(boolean enabled) {
        if (traditionalSpider != null) {
            traditionalSpider.setEnabled(enabled);
        }
        if (plugableSpider != null) {
            plugableSpider.setEnabled(enabled);
        }
    }

    protected void notifyProgress(AttackThread.Progress progress) {
        this.notifyProgress(progress, null);
    }

    @SuppressWarnings("fallthrough")
    protected void notifyProgress(AttackThread.Progress progress, String msg) {
        if (msg == null) {
            msg = Constant.messages.getString("quickstart.progress." + progress.name());
        }
        getProgressLabel().setText(msg);
        getProgressLabel().setToolTipText(msg);

        switch (progress) {
            case complete:
                ExtensionAlert extAlert =
                        ((ExtensionAlert)
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionAlert.NAME));
                if (extAlert != null) {
                    extAlert.setAlertTabFocus();
                }
            case failed:
            case stopped:
                getAttackButton().setEnabled(true);
                getStopButton().setEnabled(false);
                setSpiderButtonsEnabled(true);
                break;
            default:
                break;
        }
    }

    public void optionsLoaded(QuickStartParam quickStartParam) {
        setRecentUrls();
    }

    public void optionsChanged(OptionsParam optionsParam) {
        setRecentUrls();
    }

    @Override
    public ImageIcon getIcon() {
        return ExtensionQuickStart.ZAP_ICON;
    }

    @Override
    public JPanel getFooterPanel() {
        return null;
    }
}
