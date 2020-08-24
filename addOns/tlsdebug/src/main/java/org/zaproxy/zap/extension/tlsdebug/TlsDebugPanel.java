/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.tlsdebug;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.border.EtchedBorder;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

public class TlsDebugPanel extends AbstractPanel implements Tab {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(TlsDebugPanel.class);

    private static final String RESOURCES = "/org/zaproxy/zap/extension/tlsdebug/resources";
    private static final ImageIcon TLSDEBUG_ICON =
            new ImageIcon(TlsDebugPanel.class.getResource(RESOURCES + "/tlsdebug.png"));

    private ExtensionTlsDebug extension;
    private JButton checkButton;
    private ZapTextField urlField;
    private JTextArea outputArea;
    private JPopupMenu outputAreaPopup;

    public TlsDebugPanel(ExtensionTlsDebug extension) {
        super();
        this.extension = extension;

        this.setIcon(TLSDEBUG_ICON);
        this.setDefaultAccelerator(
                this.extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_D, KeyEvent.ALT_DOWN_MASK, false));
        this.setLayout(new BorderLayout());

        JPanel panelContent = new JPanel(new GridBagLayout());
        this.add(panelContent, BorderLayout.NORTH);

        panelContent.setBackground(new Color(UIManager.getColor("TextField.background").getRGB()));
        panelContent.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));

        panelContent.add(
                new JLabel(Constant.messages.getString("tlsdebug.label.url")),
                LayoutHelper.getGBC(0, 0, 1, 0.0D, new Insets(5, 5, 5, 5)));

        JPanel urlSelectPanel = new JPanel(new GridBagLayout());
        JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
        selectButton.setIcon(
                DisplayUtils.getScaledIcon(
                        new ImageIcon(
                                View.class.getResource("/resource/icon/16/094.png")))); // Globe
        // icon
        selectButton.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        NodeSelectDialog nsd =
                                new NodeSelectDialog(View.getSingleton().getMainFrame());
                        SiteNode node = null;
                        try {
                            node =
                                    Model.getSingleton()
                                            .getSession()
                                            .getSiteTree()
                                            .findNode(new URI(getUrlField().getText(), false));
                        } catch (Exception e2) {
                            // Ignore
                        }
                        node = nsd.showDialog(node);
                        if (node != null && node.getHistoryReference() != null) {
                            try {
                                getUrlField()
                                        .setText(node.getHistoryReference().getURI().toString());
                            } catch (Exception e1) {
                                // Ignore
                            }
                        }
                    }
                });

        urlSelectPanel.add(this.getUrlField(), LayoutHelper.getGBC(0, 0, 1, 1.0D));
        urlSelectPanel.add(selectButton, LayoutHelper.getGBC(1, 0, 1, 0.0D));
        panelContent.add(urlSelectPanel, LayoutHelper.getGBC(1, 0, 3, 0.25D));

        panelContent.add(this.getCheckButton(), LayoutHelper.getGBC(0, 1, 1, 0.0D));

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.add(
                new JLabel(Constant.messages.getString("tlsdebug.label.console")),
                BorderLayout.NORTH);
        JScrollPane jScrollPane = new JScrollPane();
        jScrollPane.add(getOutputArea(), LayoutHelper.getGBC(0, 0, 4, 1.D, 1.0D)); // Padding
        // at
        // bottom
        jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
        jScrollPane.setHorizontalScrollBarPolicy(
                javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jScrollPane.setVerticalScrollBarPolicy(
                javax.swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        jScrollPane.setViewportView(getOutputArea());
        outputPanel.add(jScrollPane, BorderLayout.CENTER);

        this.add(outputPanel, BorderLayout.CENTER);
    }

    private ZapTextField getUrlField() {
        if (urlField == null) {
            urlField = new ZapTextField();
        }
        return urlField;
    }

    private JButton getCheckButton() {
        if (checkButton == null) {
            checkButton = new JButton();
            checkButton.setText(Constant.messages.getString("tlsdebug.button.label.check"));
            checkButton.setIcon(DisplayUtils.getScaledIcon(TLSDEBUG_ICON));
            // icon
            checkButton.setToolTipText(
                    Constant.messages.getString("tlsdebug.button.tooltip.check"));

            checkButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            try {
                                extension.launchDebug(new URL(getUrlField().getText()));
                            } catch (MalformedURLException mue) {
                                logger.warn(mue.getMessage(), mue);
                                View.getSingleton().showWarningDialog(mue.getMessage());
                            } catch (IOException ioe) {
                                logger.warn(ioe.getMessage(), ioe);
                                View.getSingleton().showWarningDialog(ioe.getMessage());
                            }
                        }
                    });
        }
        return checkButton;
    }

    protected JTextArea getOutputArea() {
        if (outputArea == null) {
            outputArea = new JTextArea();
            outputArea.setComponentPopupMenu(getOutputAreaPopupMenu());
        }

        return outputArea;
    }

    protected JPopupMenu getOutputAreaPopupMenu() {
        if (outputAreaPopup == null) {
            outputAreaPopup = new JPopupMenu();

            JMenuItem menuItem = new JMenuItem(Constant.messages.getString("tlsdebug.label.clear"));
            menuItem.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            outputArea.setText("");
                        }
                    });
            outputAreaPopup.add(menuItem);
        }

        return outputAreaPopup;
    }

    String getDebugProperty() {
        return "ssl";
    }

    void setCheckUrl(String url) {
        getUrlField().setText(url);
    }

    @Override
    public boolean isShowByDefault() {
        return true;
    }

    public void writeConsole(int b) {
        this.getOutputArea().append(String.valueOf((char) b));
        this.getOutputArea().setCaretPosition(outputArea.getDocument().getLength());
    }

    public void writeConsole(String s) {
        this.getOutputArea().append(s);
        this.getOutputArea().setCaretPosition(outputArea.getDocument().getLength());
    }
}
