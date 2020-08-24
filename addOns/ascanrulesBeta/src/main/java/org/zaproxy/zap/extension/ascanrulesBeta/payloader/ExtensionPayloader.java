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
package org.zaproxy.zap.extension.ascanrulesBeta.payloader;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.ascanrulesBeta.UserAgentScanRule;
import org.zaproxy.zap.extension.custompayloads.ExtensionCustomPayloads;
import org.zaproxy.zap.extension.custompayloads.PayloadCategory;

public class ExtensionPayloader extends ExtensionAdaptor {

    public static final String NAME = "ExtensionPayloaderAscanRulesBeta";
    private static final List<Class<? extends Extension>> DEPENDENCIES;
    private static ExtensionCustomPayloads ecp;
    private PayloadCategory uaCategory;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionCustomPayloads.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionPayloader() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ecp =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionCustomPayloads.class);
        uaCategory =
                new PayloadCategory(
                        UserAgentScanRule.USER_AGENT_PAYLOAD_CATEGORY,
                        UserAgentScanRule.USER_AGENTS);
        ecp.addPayloadCategory(uaCategory);
        UserAgentScanRule.setPayloadProvider(() -> uaCategory.getPayloadsIterator());
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        UserAgentScanRule.setPayloadProvider(null);
        ecp.removePayloadCategory(uaCategory);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.payloader.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("ascanbeta.payloader.name");
    }
}
