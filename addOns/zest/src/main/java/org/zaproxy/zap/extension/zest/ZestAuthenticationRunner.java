/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.script.ScriptException;
import org.apache.commons.httpclient.URI;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestVariables;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.AuthenticationScript;

public class ZestAuthenticationRunner extends ZestZapRunner implements AuthenticationScript {

    private static final String USERNAME = "Username";
    private static final String PASSWORD = "Password";

    private ZestScriptWrapper script = null;
    private AuthenticationHelper helper;

    public ZestAuthenticationRunner(ExtensionZest extension, ZestScriptWrapper script) {
        super(extension, script);
        this.script = script;
    }

    @Override
    public String[] getRequiredParamsNames() {
        List<String> requiredParameters = new ArrayList<>();
        for (String[] vars : script.getZestScript().getParameters().getVariables()) {
            String variableName = vars[0];
            if (!isCredentialParameter(variableName) && vars[1].length() == 0) {
                requiredParameters.add(variableName);
            }
        }
        return requiredParameters.toArray(new String[requiredParameters.size()]);
    }

    private static boolean isCredentialParameter(String variableName) {
        return USERNAME.equals(variableName) || PASSWORD.equals(variableName);
    }

    @Override
    public String[] getOptionalParamsNames() {
        List<String> optionalParameters = new ArrayList<>();
        for (String[] vars : script.getZestScript().getParameters().getVariables()) {
            String variableName = vars[0];
            if (!isCredentialParameter(variableName) && vars[1].length() != 0) {
                optionalParameters.add(variableName);
            }
        }
        return optionalParameters.toArray(new String[optionalParameters.size()]);
    }

    @Override
    public String[] getCredentialsParamsNames() {
        return new String[] {USERNAME, PASSWORD};
    }

    @Override
    public HttpMessage authenticate(
            AuthenticationHelper helper,
            Map<String, String> paramsValues,
            GenericAuthenticationCredentials credentials)
            throws ScriptException {

        this.helper = helper;

        try {
            paramsValues.put(USERNAME, credentials.getParam(USERNAME));
            paramsValues.put(PASSWORD, credentials.getParam(PASSWORD));

            this.run(script.getZestScript(), paramsValues);

            String respUrl = this.getVariable(ZestVariables.RESPONSE_URL);
            HttpMessage msg = new HttpMessage(new URI(respUrl, true));
            msg.setRequestHeader(
                    this.getVariable(ZestVariables.REQUEST_METHOD)
                            + " "
                            + this.getVariable(ZestVariables.REQUEST_URL)
                            + " "
                            + msg.getRequestHeader().getVersion()
                            + HttpHeader.CRLF
                            + this.getVariable(ZestVariables.REQUEST_HEADER));
            msg.setRequestBody(this.getVariable(ZestVariables.REQUEST_BODY));
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            msg.setResponseHeader(this.getVariable(ZestVariables.RESPONSE_HEADER));
            msg.setResponseBody(this.getVariable(ZestVariables.RESPONSE_BODY));
            // Make sure the proper requesting user is set on the returned message
            msg.setRequestingUser(helper.getRequestingUser());

            return msg;

        } catch (Exception e) {
            throw new ScriptException(e);
        }
    }

    @Override
    public ZestResponse send(ZestRequest request) throws IOException {
        HttpMessage msg = ZestZapUtils.toHttpMessage(request, null);
        msg.setRequestingUser(helper.getRequestingUser());
        helper.sendAndReceive(msg, request.isFollowRedirects());
        return ZestZapUtils.toZestResponse(msg);
    }
}
