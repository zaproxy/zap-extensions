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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.paramminer.ExtensionParamMiner;
import org.zaproxy.addon.paramminer.ParamMinerConfig;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ParamMinerDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String URL = "paramminer.dialog.url";
    private static final String CONTEXT = "paramminer.dialog.context";
    private static final String FCBZ_CACHE_BUSTER = "paramminer.dialog.fcbz_cache_buster";
    private static final String BASIC_WORDLISTS = "paramminer.dialog.basic_wordlists";
    private static final String CUSTOM_WORDLISTS = "paramminer.dialog.custom_wordlists";
    private static final String SKIP_BORING_HEADERS = "paramminer.dialog.skip_boring_headers";
    private static final String THREADPOOL_SIZE = "paramminer.dialog.threadpool_size";

    private static final Logger logger = LogManager.getLogger(ParamMinerDialog.class);

    private ExtensionParamMiner extension;
    private Target target;
    private ParamMinerConfig config;

    public ParamMinerDialog(ExtensionParamMiner extension, Frame owner, Dimension dim) {
        super(owner, "paramminer.panel.title", dim);
        this.extension = extension;
    }

    public void init(Target target) {
        if (target != null) {
            this.target = target;
        }
        logger.debug("init {}", this.target);
        if (config == null) {
            config = new ParamMinerConfig();
        }
        this.removeAllFields();
        this.addTargetSelectField(URL, this.target, true, false);
        this.addComboField(CONTEXT, new String[] {}, "");
        this.addCheckBoxField(FCBZ_CACHE_BUSTER, false);
        this.addCheckBoxField(BASIC_WORDLISTS, true);
        this.addCheckBoxField(CUSTOM_WORDLISTS, false);
        this.addCheckBoxField(SKIP_BORING_HEADERS, false);
        this.addTextField(THREADPOOL_SIZE, "4");
        this.addPadding();
        this.pack();
    }

    @Override
    public void save() {
        config.setUrl(this.getStringValue(URL));
        config.setAddFcbzCacheBuster(this.getBoolValue(FCBZ_CACHE_BUSTER));
        config.setUseBasicWordlists(this.getBoolValue(BASIC_WORDLISTS));
        config.setUseCustomWordlists(this.getBoolValue(CUSTOM_WORDLISTS));
        config.setSkipBoringHeaders(this.getBoolValue(SKIP_BORING_HEADERS));
        config.setThreadpoolSize(this.getStringValue(THREADPOOL_SIZE));
        config.setContext(this.getStringValue(CONTEXT));
        logger.debug("config {}", this.config.getUrl());

        extension.startScan(config);
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(URL) == null || this.getStringValue(URL).isEmpty()) {
            return Constant.messages.getString("paramminer.dialog.error.url");
        }
        return null;
    }
}
