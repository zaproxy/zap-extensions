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
package org.zaproxy.zap.extension.pscanrules.payloader;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.custompayloads.ExtensionCustomPayloads;
import org.zaproxy.zap.extension.custompayloads.PayloadCategory;
import org.zaproxy.zap.extension.pscanrules.ApplicationErrorScanRule;
import org.zaproxy.zap.extension.pscanrules.UsernameIdorScanRule;

public class ExtensionPayloader extends ExtensionAdaptor {

    public static final String NAME = "ExtensionPayloaderPscanRulesRelease";
    private static final List<Class<? extends Extension>> DEPENDENCIES;
    private static ExtensionCustomPayloads ecp;
    private PayloadCategory idorCategory;
    private PayloadCategory errorCategory;

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
        idorCategory =
                new PayloadCategory(
                        UsernameIdorScanRule.USERNAME_IDOR_PAYLOAD_CATEGORY,
                        UsernameIdorScanRule.DEFAULT_USERNAMES);
        ecp.addPayloadCategory(idorCategory);
        UsernameIdorScanRule.setPayloadProvider(() -> idorCategory.getPayloadsIterator());

        errorCategory =
                new PayloadCategory(
                        ApplicationErrorScanRule.ERRORS_PAYLOAD_CATEGORY,
                        ApplicationErrorScanRule.DEFAULT_ERRORS);
        ecp.addPayloadCategory(errorCategory);
        ApplicationErrorScanRule.setPayloadProvider(() -> errorCategory.getPayloadsIterator());
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        UsernameIdorScanRule.setPayloadProvider(null);
        ecp.removePayloadCategory(idorCategory);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("pscanrules.payloader.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("pscanrules.payloader.name");
    }
}
