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

import java.util.HashMap;
import java.util.Map;
import javax.script.ScriptException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ProxyScript;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestVariables;

public class ZestProxyRunner extends ZestZapRunner implements ProxyScript {

    private ZestScriptWrapper script = null;
    private HttpMessage msg = null;
    private ExtensionZest extension = null;

    private Logger logger = Logger.getLogger(ZestProxyRunner.class);

    public ZestProxyRunner(ExtensionZest extension, ZestScriptWrapper script) {
        super(extension, script);
        this.extension = extension;
        this.script = script;
    }

    @Override
    public boolean proxyRequest(HttpMessage msg) throws ScriptException {
        logger.debug("Zest proxyRequest script: " + this.script.getName());
        this.msg = msg;
        try {
            // Create the previous request so the script has something to run against
            ZestRequest req = ZestZapUtils.toZestRequest(msg, false, true, extension.getParam());

            // Set the response url to empty to give us a way to work out this is a request in the
            // script
            Map<String, String> params = new HashMap<String, String>();
            params.put(ZestVariables.RESPONSE_URL, "");

            this.run(script.getZestScript(), req, params);

            String reqHeader = this.getVariable(ZestVariables.REQUEST_HEADER);

            if (reqHeader == null || reqHeader.length() == 0) {
                // Its been cleared - drop the request
                if (View.isInitialised()) {
                    View.getSingleton()
                            .getOutputPanel()
                            .append(
                                    Constant.messages.getString(
                                            "zest.proxy.request.drop",
                                            msg.getRequestHeader().getURI()));
                }
                return false;
            }

            // Recreate the request from the variables
            msg.setRequestHeader(
                    this.getVariable(ZestVariables.REQUEST_METHOD)
                            + " "
                            + this.getVariable(ZestVariables.REQUEST_URL)
                            + " "
                            + msg.getRequestHeader().getVersion()
                            + HttpHeader.CRLF
                            + reqHeader);

            msg.setRequestBody(this.getVariable(ZestVariables.REQUEST_BODY));
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

            if (ZestScriptWrapper.ZAP_BREAK_VARIABLE_VALUE.equals(
                    script.getZestScript()
                            .getParameters()
                            .getVariable(ZestScriptWrapper.ZAP_BREAK_VARIABLE_NAME))) {
                // The intercept action was invoked
                msg.setForceIntercept(true);
            }

        } catch (Exception e) {
            throw new ScriptException(e);
        }
        return true;
    }

    @Override
    public boolean proxyResponse(HttpMessage msg) {
        logger.debug("Zest proxyResponse script: " + this.script.getName());
        this.msg = msg;
        try {
            // Create the previous request so the script has something to run against
            ZestRequest req = ZestZapUtils.toZestRequest(msg, false, true, extension.getParam());
            req.setResponse(ZestZapUtils.toZestResponse(msg));

            // Unset the 'break' flag (in case it was set in the request path
            msg.setForceIntercept(false);

            this.run(script.getZestScript(), req, null);

            String respHeader = this.getVariable(ZestVariables.RESPONSE_HEADER);

            if (respHeader == null || respHeader.length() == 0) {
                // Its been cleared - drop the request
                if (View.isInitialised()) {
                    View.getSingleton()
                            .getOutputPanel()
                            .append(
                                    Constant.messages.getString(
                                            "zest.proxy.response.drop",
                                            msg.getRequestHeader().getURI()));
                }
                return false;
            }
            msg.setResponseHeader(respHeader);

            if (msg.getResponseHeader().isText()) {
                // Dont currently support changing binary response body
                msg.setResponseBody(this.getVariable(ZestVariables.RESPONSE_BODY));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return true;
    }

    @Override
    public void alertFound(Alert alert) {
        // Override so we can set the message and URI
        alert.setMessage(msg);
        alert.setUri(msg.getRequestHeader().getURI().toString());
        super.alertFound(alert);
    }
}
