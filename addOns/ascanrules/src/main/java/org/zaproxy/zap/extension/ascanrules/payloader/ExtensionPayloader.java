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
package org.zaproxy.zap.extension.ascanrules.payloader;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.ascanrules.HiddenFilesScanRule;
import org.zaproxy.zap.extension.ascanrules.UserAgentScanRule;
import org.zaproxy.zap.extension.ascanrules.XpathInjectionScanRule;
import org.zaproxy.zap.extension.custompayloads.ExtensionCustomPayloads;
import org.zaproxy.zap.extension.custompayloads.PayloadCategory;

public class ExtensionPayloader extends ExtensionAdaptor {

    public static final String NAME = "ExtensionPayloaderAscanRules";
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionCustomPayloads.class);
    private static ExtensionCustomPayloads ecp;
    private PayloadCategory uaCategory;
    private PayloadCategory hfCategory;
    private PayloadCategory xpathErrorCategory;

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
                        UserAgentScanRule.getUserAgents());
        ecp.addPayloadCategory(uaCategory);
        UserAgentScanRule.setPayloadProvider(uaCategory::getPayloadsIterator);

        hfCategory =
                new PayloadCategory(
                        HiddenFilesScanRule.HIDDEN_FILE_PAYLOAD_CATEGORY,
                        HiddenFilesScanRule.getHiddenFiles());
        ecp.addPayloadCategory(hfCategory);
        HiddenFilesScanRule.setPayloadProvider(hfCategory::getPayloadsIterator);

        xpathErrorCategory =
                new PayloadCategory(
                        List.of(),
                        XpathInjectionScanRule.DEFAULT_DISABLED_ERRORS,
                        XpathInjectionScanRule.ERRORS_PAYLOAD_CATEGORY);
        ecp.addPayloadCategory(xpathErrorCategory);
        XpathInjectionScanRule.setErrorProvider(xpathErrorCategory::getPayloadsIterator);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        UserAgentScanRule.setPayloadProvider(null);
        ecp.removePayloadCategory(uaCategory);
        HiddenFilesScanRule.setPayloadProvider(null);
        ecp.removePayloadCategory(hfCategory);
        XpathInjectionScanRule.setErrorProvider(null);
        ecp.removePayloadCategory(xpathErrorCategory);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanrules.payloader.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("ascanrules.payloader.name");
    }
}
