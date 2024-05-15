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

import java.io.IOException;
import javax.script.ScriptException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.scripts.scanrules.ActiveScript;
import org.zaproxy.zap.extension.scripts.scanrules.ActiveScriptHelper;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;

public class ZestActiveRunner extends ZestZapRunner implements ActiveScript {

    private ZestScriptWrapper script = null;
    private ActiveScriptHelper scriptHelper = null;
    private HttpMessage msg = null;
    private String param = null;
    private ExtensionZest extension = null;

    private static final Logger LOGGER = LogManager.getLogger(ZestActiveRunner.class);

    public ZestActiveRunner(
            ExtensionZest extension, ExtensionNetwork extensionNetwork, ZestScriptWrapper script) {
        super(extension, extensionNetwork, script);
        this.extension = extension;
        this.script = script;
    }

    @Override
    public void scan(ActiveScriptHelper helper, HttpMessage msg, String param, String value)
            throws ScriptException {
        LOGGER.debug("Zest ActiveScan script: {}", this.script.getName());
        this.scriptHelper = helper;
        this.msg = msg;
        this.param = param;

        try {
            helper.setParam(msg, param, "{{target}}");
            this.run(
                    script.getZestScript(),
                    ZestZapUtils.toZestRequest(msg, false, true, extension.getParam()),
                    null);
        } catch (Exception e) {
            throw new ScriptException(e);
        }
    }

    @Override
    public ZestResponse send(ZestRequest request) throws IOException {
        HttpMessage msg = ZestZapUtils.toHttpMessage(request, null /*response*/);

        scriptHelper.sendAndReceive(msg, false /*isFollowRedirect*/);

        ZestResponse response = ZestZapUtils.toZestResponse(msg);
        return response;
    }

    @Override
    public void alertFound(Alert alert) {
        // Override this as we can put in more info from the script and message
        scriptHelper
                .newAlert()
                .setRisk(alert.getRisk())
                .setConfidence(alert.getConfidence())
                .setName(alert.getName())
                .setDescription(script.getDescription())
                .setParam(param)
                .setMessage(msg)
                .raise();
    }
}
