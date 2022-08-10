/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramminer.gui;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.paramminer.ExtensionParamMiner;
import org.zaproxy.addon.paramminer.ParamMinerConfig;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ParamMinerDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String URL = "paramminer.dialog.url";
    private static final String CONTEXT = "paramminer.dialog.context";
    private static final String FCBZ_CACHE_BUSTER = "paramminer.dialog.fcbz_cache_buster";

    private static final String PREDEFINED = "paramminer.dialog.predefined.";
    private static final String CUSTOM = "paramminer.dialog.custom.";
    private static final String URL_WORDLIST = "url_wordlists";
    private static final String HEADER_WORDLIST = "header_wordlists";
    private static final String COOKIE_WORDLIST = "cookie_wordlists";

    private static final String SKIP_BORING_HEADERS = "paramminer.dialog.skip_boring_headers";
    private static final String THREADPOOL_SIZE = "paramminer.dialog.threadpool_size";

    private static final Logger logger = LogManager.getLogger(ParamMinerDialog.class);

    private ExtensionParamMiner extension;
    private HttpMessage target;
    private ParamMinerConfig config;
    private ZapTextField text;

    public ParamMinerDialog(ExtensionParamMiner extension, Frame owner, Dimension dim) {
        super(owner, "paramminer.panel.title", dim);
        this.extension = extension;
    }

    public void init(HttpMessage target) {
        if (target != null) {
            this.target = target;
        }
        logger.debug("init {}", this.target);
        if (config == null) {
            config = new ParamMinerConfig();
        }
        this.removeAllFields();
        this.addUriSelectField(URL, this.target, true);
        this.addComboField(CONTEXT, new String[] {}, "");
        this.addCheckBoxField(FCBZ_CACHE_BUSTER, false);
        this.addCheckBoxField(PREDEFINED + URL_WORDLIST, true);
        this.addCheckBoxField(PREDEFINED + HEADER_WORDLIST, false);
        this.addCheckBoxField(PREDEFINED + COOKIE_WORDLIST, false);

        this.addCheckBoxField(CUSTOM + URL_WORDLIST, false);
        this.addCheckBoxField(CUSTOM + HEADER_WORDLIST, false);
        this.addCheckBoxField(CUSTOM + COOKIE_WORDLIST, false);

        this.addCheckBoxField(SKIP_BORING_HEADERS, false);
        this.addTextField(THREADPOOL_SIZE, "8");
        this.addPadding();
        this.pack();
    }

    private void addUriSelectField(String fieldLabel, HttpMessage value, boolean editable) {
        text = new ZapTextField();
        if (value != null) {
            text.setText(value.getRequestHeader().getURI().toString());
        }

        JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
        selectButton.setIcon(
                new ImageIcon(View.class.getResource("/resource/icon/16/094.png"))); // Globe icon
        selectButton.addActionListener(
                e -> {
                    NodeSelectDialog nsd = new NodeSelectDialog(ParamMinerDialog.this);
                    SiteNode node =
                            nsd.showDialog(value != null ? value.getHistoryRef().getURI() : null);
                    if (node != null) {
                        text.setText(node.getHistoryReference().getURI().toString());
                    }
                });
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.add(
                text,
                LayoutHelper.getGBC(
                        0, 0, 1, 1.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.add(
                selectButton,
                LayoutHelper.getGBC(
                        1, 0, 1, 0.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));

        this.addCustomComponent(fieldLabel, panel);
    }

    @Override
    public void save() {
        config.setUrl(this.text.getText());
        config.setAddFcbzCacheBuster(this.getBoolValue(FCBZ_CACHE_BUSTER));

        config.setUsePredefinedUrlWordlists(this.getBoolValue(PREDEFINED + URL_WORDLIST));
        config.setUsePredefinedHeaderWordlists(this.getBoolValue(PREDEFINED + HEADER_WORDLIST));
        config.setUsePredefinedCookieWordlists(this.getBoolValue(PREDEFINED + COOKIE_WORDLIST));

        config.setUseCustomUrlWordlists(this.getBoolValue(CUSTOM + URL_WORDLIST));
        config.setUseCustomHeaderWordlists(this.getBoolValue(CUSTOM + HEADER_WORDLIST));
        config.setUseCustomCookieWordlists(this.getBoolValue(CUSTOM + COOKIE_WORDLIST));

        config.setSkipBoringHeaders(this.getBoolValue(SKIP_BORING_HEADERS));
        config.setThreadCount(this.getStringValue(THREADPOOL_SIZE));
        config.setContext(this.getStringValue(CONTEXT));
        logger.debug("config {}", this.config.getUrl());

        extension.startScan(config);
    }

    @Override
    public String validateFields() {
        if (this.text.getText() == null || this.text.getText().isEmpty()) {
            return Constant.messages.getString("paramminer.dialog.error.url");
        }
        return null;
    }
}
