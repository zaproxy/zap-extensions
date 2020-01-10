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

import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyParam;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.security.SslCertificateService;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.dynssl.DynSSLParam;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class DefaultExplorePanel extends QuickStartSubPanel {
    private static final long serialVersionUID = 1L;
    private static final String OWASP_ZAP_ROOT_CA_NAME = "owasp_zap_root_ca";
    private static final String OWASP_ZAP_ROOT_CA_FILE_EXT = ".cer";
    private static final String OWASP_ZAP_ROOT_CA_FILENAME =
            OWASP_ZAP_ROOT_CA_NAME + OWASP_ZAP_ROOT_CA_FILE_EXT;

    private JPanel contentPanel;
    private JButton saveButton;
    private ZapTextField hostPortField;
    private JButton copyButton;

    public DefaultExplorePanel(ExtensionQuickStart extension, QuickStartPanel qsp) {
        super(extension, qsp);
    }

    @Override
    public String getTitleKey() {
        return "quickstart.explore.panel.title";
    }

    @Override
    public JPanel getDescriptionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);

        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.launch.panel.default.message1"),
                LayoutHelper.getGBC(0, 0, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.launch.panel.default.message2"),
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
            contentPanel = new JPanel(new GridBagLayout());
            contentPanel.setBackground(Color.WHITE);
            int formPanelY = 0;

            JPanel savePanel = QuickStartHelper.getHorizontalPanel();

            savePanel.add(new JLabel(Constant.messages.getString("quickstart.explore.1.start")));
            savePanel.add(getSaveButton());
            savePanel.add(new JLabel(Constant.messages.getString("quickstart.explore.1.end")));
            contentPanel.add(
                    savePanel,
                    LayoutHelper.getGBC(
                            0, formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.explore.2")),
                    LayoutHelper.getGBC(
                            0, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            JPanel proxyPanel = QuickStartHelper.getHorizontalPanel();
            proxyPanel.add(new JLabel(Constant.messages.getString("quickstart.explore.3")));
            proxyPanel.add(getHostPortField());
            proxyPanel.add(getCopyButton());
            contentPanel.add(
                    proxyPanel,
                    LayoutHelper.getGBC(
                            0, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            contentPanel.add(
                    new JLabel(""),
                    LayoutHelper.getGBC(
                            0, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        }

        return contentPanel;
    }

    public JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = new JButton(Constant.messages.getString("menu.file.save"));
            saveButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(ZAP.class.getResource("/resource/icon/16/096.png"))));
            saveButton.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent arg0) {
                            final JFileChooser fc =
                                    new WritableFileChooser(
                                            new File(System.getProperty("user.home")));
                            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
                            fc.setMultiSelectionEnabled(false);
                            fc.setSelectedFile(new File(OWASP_ZAP_ROOT_CA_FILENAME));
                            if (fc.showSaveDialog(DefaultExplorePanel.this)
                                    == JFileChooser.APPROVE_OPTION) {
                                final File f = fc.getSelectedFile();
                                try {
                                    writePubCertificateToFile(f);
                                } catch (final Exception e) {
                                    View.getSingleton()
                                            .showWarningDialog(
                                                    DefaultExplorePanel.this,
                                                    Constant.messages.getString(
                                                            "quickstart.explore.warning.savefail",
                                                            e.getMessage()));
                                }
                            }
                        }
                    });
        }
        return saveButton;
    }

    private void writePubCertificateToFile(File f) throws IOException, KeyStoreException {
        OptionsParam options = Model.getSingleton().getOptionsParam();
        DynSSLParam param = options.getParamSet(DynSSLParam.class);
        KeyStore ks = param.getRootca();
        if (ks != null) {
            final Certificate cert = ks.getCertificate(SslCertificateService.ZAPROXY_JKS_ALIAS);
            try (final Writer w = Files.newBufferedWriter(f.toPath(), StandardCharsets.US_ASCII);
                    final PemWriter pw = new PemWriter(w)) {
                pw.writeObject(new JcaMiscPEMGenerator(cert));
                pw.flush();
            }
        }
    }

    private ZapTextField getHostPortField() {
        if (hostPortField == null) {
            hostPortField = new ZapTextField();
            hostPortField.setEditable(false);
            OptionsParam options = Model.getSingleton().getOptionsParam();
            hostPortField.setText(this.getProxyString(options.getProxyParam()));
        }
        return hostPortField;
    }

    private String getProxyString(ProxyParam params) {
        StringBuilder sb = new StringBuilder();
        sb.append("http://");
        sb.append(params.getProxyIp());
        sb.append(":");
        sb.append(params.getProxyPort());
        return sb.toString();
    }

    private JButton getCopyButton() {
        if (copyButton == null) {
            copyButton = new JButton();
            copyButton.setToolTipText(
                    Constant.messages.getString("quickstart.explore.button.clipboard"));
            copyButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    ExtensionQuickStart.class.getResource(
                                            ExtensionQuickStart.RESOURCES
                                                    + "/clipboard-sign.png"))));
            copyButton.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent arg0) {
                            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                            OptionsParam options = Model.getSingleton().getOptionsParam();
                            clipboard.setContents(
                                    new StringSelection(getProxyString(options.getProxyParam())),
                                    null);
                        }
                    });
        }
        return copyButton;
    }

    @Override
    public ImageIcon getIcon() {
        return ExtensionQuickStart.HUD_ICON;
    }

    @Override
    public JPanel getFooterPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.explore.panel.footer"),
                LayoutHelper.getGBC(0, 0, 1, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        return panel;
    }

    public void optionsChanged(OptionsParam optionsParam) {
        this.getHostPortField().setText(this.getProxyString(optionsParam.getProxyParam()));
    }
}
