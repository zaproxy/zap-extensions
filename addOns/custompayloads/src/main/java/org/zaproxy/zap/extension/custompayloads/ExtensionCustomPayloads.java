/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.AbstractParamPanel;

public class ExtensionCustomPayloads extends ExtensionAdaptor {

    private CustomPayloadsParam params;
    private CustomPayloadsOptionsPanel optionsPanel;

    public ExtensionCustomPayloads() {
        super();
        this.setI18nPrefix("custompayloads");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("custompayloads.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("custompayloads.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getParam());

        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
        }
    }

    private AbstractParamPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new CustomPayloadsOptionsPanel();
        }
        return optionsPanel;
    }

    protected CustomPayloadsParam getParam() {
        if (params == null) {
            params = new CustomPayloadsParam();
        }
        return params;
    }

    public void addPayloadCategory(PayloadCategory payloadCategory) {
        getParam().addPayloadCategory(payloadCategory);
    }

    public void removePayloadCategory(PayloadCategory payloadCategory) {
        getParam().removePayloadCategory(payloadCategory);
    }
}
