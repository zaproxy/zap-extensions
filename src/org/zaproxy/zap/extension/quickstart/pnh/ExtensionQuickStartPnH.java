/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.quickstart.pnh;

import java.awt.Insets;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyParam;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.QuickStartPanel;
import org.zaproxy.zap.extension.quickstart.QuickStartPanelContentProvider;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

public class ExtensionQuickStartPnH extends ExtensionAdaptor implements
        OptionsChangedListener, QuickStartPanelContentProvider {

    public static final String NAME = "ExtensionQuickStartPnH";

    private Map<String, JLabel> idToLabel = new HashMap<String, JLabel>();
    private JButton confButton;
    private ZapTextField confField;

    private static final List<Class<?>> DEPENDENCIES;

    static {
        List<Class<?>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionQuickStart.class);
        dependencies.add(ExtensionPlugNHack.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionQuickStartPnH() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.addOptionsChangedListener(this);
            this.getExtQuickStart().addContentProvider(this);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            this.getExtQuickStart().removeContentProvider(this);
        }
    }

    @Override
    public List<Class<?>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.pnh.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader()
                .getExtension(ExtensionQuickStart.class);
    }

    private String getPlugNHackUrl() {
        ProxyParam proxyParam = Model.getSingleton().getOptionsParam()
                .getProxyParam();
        String protocol = "http://";
        if (Model.getSingleton().getOptionsParam().getApiParam().isSecureOnly()) {
            protocol = "https://";
        }
        return protocol + proxyParam.getProxyIp() + ":"
                + proxyParam.getProxyPort() + "/pnh/?" + API.API_NONCE_PARAM
                + "=" + API.getInstance().getLongLivedNonce("/pnh/");
    }

    private ZapTextField getConfField() {
        if (confField == null) {
            confField = new ZapTextField();
            confField.setEditable(false);
            updateConfField(Model.getSingleton().getOptionsParam()
                    .getApiParam().isEnabled());
        }
        return confField;
    }

    private void updateConfField(boolean apiState) {
        if (confField == null) {
            return;
        }
        // PnH URL Field has the same enable state as the API
        confField.setEnabled(apiState);
        if (apiState) {
            confField.setText(getPlugNHackUrl());
        } else {
            confField.setText(Constant.messages
                    .getString("quickstart.mitm.api.disabled"));
        }
    }

    private JButton getConfButton() {
        if (confButton == null) {
            confButton = new JButton();
            confButton.setText(Constant.messages
                    .getString("quickstart.button.label.mitm"));
            confButton.setToolTipText(Constant.messages
                    .getString("quickstart.button.tooltip.mitm"));
            confButton
                    .setIcon(DisplayUtils.getScaledIcon(new ImageIcon(
                            QuickStartPanel.class
                                    .getResource("/org/zaproxy/zap/extension/quickstart/resources/plug.png"))));

            updateConfButton(Model.getSingleton().getOptionsParam()
                    .getApiParam().isEnabled());

            confButton.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    DesktopUtils.openUrlInBrowser(getPlugNHackUrl());
                }
            });
        }
        return confButton;
    }

    private void updateConfButton(boolean apiState) {
        if (confButton == null) {
            return;
        }
        // PnH button has the same enable state as the API
        confButton.setEnabled(apiState);
        if (apiState) {
            confButton.setToolTipText(Constant.messages
                    .getString("quickstart.button.tooltip.mitm"));
        } else {
            confButton.setToolTipText(Constant.messages
                    .getString("quickstart.mitm.api.disabled"));
        }
    }

    public void updatePnhPanelElements(boolean apiState) {
        updateConfButton(apiState);
        updateConfField(apiState);
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        //PnH button has the same enable state as the API
        updatePnhPanelElements(optionsParam.getApiParam().isEnabled());
    }

    private JLabel getLabel(String id) {
        JLabel jlabel = this.idToLabel.get(id);
        if (jlabel == null) {
            jlabel = new JLabel(Constant.messages.getString(id));
            this.idToLabel.put(id, jlabel);
        }
        return jlabel;
    }

    @Override
    public int addToPanel(JPanel panel, int offset) {
        if (DesktopUtils.canOpenUrlInBrowser()) {
            panel.add(getLabel("quickstart.panel.pnhmsg"), LayoutHelper.getGBC(
                    0, ++offset, 5, 1.0D, new Insets(5, 5, 5, 5)));

            panel.add(getLabel("quickstart.label.mitm"), LayoutHelper.getGBC(0,
                    ++offset, 1, 0.0D, new Insets(5, 5, 5, 5)));

            panel.add(this.getConfButton(),
                    LayoutHelper.getGBC(1, offset, 1, 0.0D));

            panel.add(getLabel("quickstart.label.mitmalt"), LayoutHelper
                    .getGBC(0, ++offset, 1, 0.0D, new Insets(5, 5, 5, 5)));
        } else {
            panel.add(getLabel("quickstart.label.mitmurl"), LayoutHelper
                    .getGBC(0, ++offset, 1, 0.0D, new Insets(5, 5, 5, 5)));
        }
        panel.add(this.getConfField(), LayoutHelper.getGBC(1, offset, 3, 0.25D));
        return offset;
    }

    @Override
    public void removeFromPanel(JPanel panel) {
        if (DesktopUtils.canOpenUrlInBrowser()) {
            panel.remove(getLabel("quickstart.panel.pnhmsg"));
            panel.remove(getLabel("quickstart.label.mitm"));
            panel.remove(this.getConfButton());
            panel.remove(getLabel("quickstart.label.mitmalt"));
        } else {
            panel.remove(getLabel("quickstart.label.mitmurl"));
        }
    }


}
