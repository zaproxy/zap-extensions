/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
import java.util.HashMap;
import java.util.Map;
import javax.script.ScriptException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.HttpSenderScript;
import org.zaproxy.zap.extension.script.HttpSenderScriptHelper;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;
import org.zaproxy.zest.core.v1.ZestVariables;

public class ZestHttpSenderRunner extends ZestZapRunner implements HttpSenderScript {

    public static final String ZAP_INITIATOR = "zap.initiator";

    private ZestScriptWrapper script = null;
    private HttpMessage msg = null;
    private ExtensionZest extension = null;
    private HttpSenderScriptHelper helper = null;

    private Logger logger = Logger.getLogger(ZestHttpSenderRunner.class);

    public ZestHttpSenderRunner(ExtensionZest extension, ZestScriptWrapper script) {
        super(extension, script);
        this.extension = extension;
        this.script = script;
    }

    @Override
    public void sendingRequest(HttpMessage msg, int initiator, HttpSenderScriptHelper helper)
            throws ScriptException {
        logger.debug("Zest sendingRequest script: " + this.script.getName());
        this.helper = helper;
        this.msg = msg;
        try {
            // Create the previous request so the script has something to run against
            ZestRequest req = ZestZapUtils.toZestRequest(msg, false, true, extension.getParam());

            // Set the response url to empty to give us a way to work out this is a request in the
            // script
            Map<String, String> params = new HashMap<String, String>();
            params.put(ZestVariables.RESPONSE_URL, "");
            params.put(ZAP_INITIATOR, Integer.toString(initiator));

            this.run(script.getZestScript(), req, params);

            // Recreate the request from the variables
            msg.setRequestHeader(
                    this.getVariable(ZestVariables.REQUEST_METHOD)
                            + " "
                            + this.getVariable(ZestVariables.REQUEST_URL)
                            + " "
                            + msg.getRequestHeader().getVersion()
                            + HttpHeader.CRLF
                            + getVariable(ZestVariables.REQUEST_HEADER));

            msg.setRequestBody(this.getVariable(ZestVariables.REQUEST_BODY));
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

        } catch (Exception e) {
            throw new ScriptException(e);
        }
    }

    @Override
    public void responseReceived(HttpMessage msg, int initiator, HttpSenderScriptHelper helper)
            throws ScriptException {
        logger.debug("Zest responseReceived script: " + this.script.getName());
        this.msg = msg;
        try {
            // Create the previous request so the script has something to run against
            ZestRequest req = ZestZapUtils.toZestRequest(msg, false, true, extension.getParam());
            req.setResponse(ZestZapUtils.toZestResponse(msg));

            Map<String, String> params = new HashMap<String, String>();
            params.put(ZAP_INITIATOR, Integer.toString(initiator));

            this.run(script.getZestScript(), req, params);

            msg.setResponseHeader(getVariable(ZestVariables.RESPONSE_HEADER));

            if (msg.getResponseHeader().isText()) {
                // Dont currently support changing binary response body
                msg.setResponseBody(this.getVariable(ZestVariables.RESPONSE_BODY));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return;
    }

    @Override
    public void alertFound(Alert alert) {
        // Override so we can set the message and URI
        alert.setMessage(msg);
        alert.setUri(msg.getRequestHeader().getURI().toString());
        super.alertFound(alert);
    }

    @Override
    public ZestResponse send(ZestRequest request) throws IOException {
        HttpMessage msg = ZestZapUtils.toHttpMessage(request, null);
        helper.getHttpSender().sendAndReceive(msg, request.isFollowRedirects());
        return ZestZapUtils.toZestResponse(msg);
    }
}
