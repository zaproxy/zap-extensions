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
package org.zaproxy.zap.extension.ascanrulesBeta;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePlugin;

public class EnvFileScanRule extends AbstractAppFilePlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.envfiles.";
    private static final int PLUGIN_ID = 40034;

    public EnvFileScanRule() {
        super(".env", MESSAGE_PREFIX);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public boolean isFalsePositive(HttpMessage msg) {
        String responseBody = msg.getResponseBody().toString();
        // It likely is a FP if the response contains neither a comment nor assignment
        return !responseBody.contains("#") && !responseBody.contains("=");
    }
}
