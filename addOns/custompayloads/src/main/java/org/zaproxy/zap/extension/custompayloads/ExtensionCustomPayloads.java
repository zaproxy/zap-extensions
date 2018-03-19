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

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionCustomPayloads extends ExtensionAdaptor {

    private CustomPayloadsParam params;
    private CustomPayloadsOptionsPanel optionsPanel;
    private ArrayList<CustomPayloadModel> defaultPayloads;

    public ExtensionCustomPayloads() {
        super();
        this.setI18nPrefix("custompayloads");
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
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

    public CustomPayloadsParam getParam() {
        if (params == null) {
            params = new CustomPayloadsParam(this);
        }
        return params;
    }

    public ArrayList<CustomPayloadModel> getDefaultPayloads() {
        if (defaultPayloads == null) {
            ArrayList<CustomPayloadModel> payloads = new ArrayList<>();
            PluginFactory factory = new PluginFactory();
            ZapXmlConfiguration conf = new ZapXmlConfiguration();
            factory.loadAllPlugin(conf);
            List<Plugin> scanners = factory.getAllPlugin();
            for (Plugin scanner : scanners) {
                if (scanner instanceof PluginWithConfigurablePayload) {
                    PluginWithConfigurablePayload scannerWithConfigurablePayload =
                            (PluginWithConfigurablePayload) scanner;
                    payloads.addAll(scannerWithConfigurablePayload.getDefaultPayloads());
                }
            }
            defaultPayloads = payloads;
        }
        return defaultPayloads;
    }

    public List<CustomPayloadModel> getPayloadsByCategory(String category) {
        return getParam().getPayloadsByCategory(category);
    }
}
