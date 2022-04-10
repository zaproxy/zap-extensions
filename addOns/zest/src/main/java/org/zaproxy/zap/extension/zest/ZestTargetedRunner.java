/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import javax.script.ScriptException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.script.TargetedScript;

public class ZestTargetedRunner extends ZestZapRunner implements TargetedScript {

    private ExtensionZest extension = null;
    private ZestScriptWrapper script = null;

    public ZestTargetedRunner(
            ExtensionZest extension, ExtensionNetwork extensionNetwork, ZestScriptWrapper script) {
        super(extension, extensionNetwork, script);
        this.extension = extension;
        this.script = script;
    }

    @Override
    public void invokeWith(HttpMessage msg) throws ScriptException {
        try {
            this.extension.clearResults();
            this.run(
                    script.getZestScript(),
                    ZestZapUtils.toZestRequest(msg, false, true, extension.getParam()),
                    null);
        } catch (Exception e) {
            throw new ScriptException(e);
        }
    }
}
