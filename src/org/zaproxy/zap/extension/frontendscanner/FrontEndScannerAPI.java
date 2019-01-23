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
package org.zaproxy.zap.extension.frontendscanner;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HtmlParameter;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.model.StandardParameterParser;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;

public class FrontEndScannerAPI extends ApiImplementor {

    private static final String PREFIX = "frontendscanner";

    private StandardParameterParser parameterParser;

    public FrontEndScannerAPI() {
        this.parameterParser = new StandardParameterParser();
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public String handleCallBack(HttpMessage msg) throws ApiException {
        try {
            String query = msg.getRequestHeader().getURI().getQuery();

            if (query == null) {
                throw new ApiException (ApiException.Type.MISSING_PARAMETER, "action");
            }

            Map<String, String> parameters = parameterParser
                .getParams(msg, HtmlParameter.Type.url);

            String action = parameters.get("action");
            if (action == null) {
                throw new ApiException (ApiException.Type.MISSING_PARAMETER, "action");
            }

            LOGGER.debug("action = " + action);

            switch (action) {
                case "createAlert":
                    return createAlertFromMessage(msg);
                default:
                    throw new ApiException (ApiException.Type.ILLEGAL_PARAMETER, "action");
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw new ApiException (ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
    }

    private String createAlertFromMessage(HttpMessage msg) throws ApiException {
        try {
            int clientSidePassiveScriptPluginId = 50006;

            JSONObject alertParams = JSONObject.fromObject(
                msg.getRequestBody().toString()
            ).getJSONObject("alert");

            HistoryReference historyReference = new HistoryReference(
                alertParams.getInt("historyReferenceId")
            );

            Alert alert = new Alert(
                clientSidePassiveScriptPluginId,
                alertParams.getInt("risk"),
                alertParams.getInt("confidence"),
                alertParams.getString("name")
            );
            alert.setSource(Alert.Source.PASSIVE);
            alert.setDescription(alertParams.getString("description"));
            alert.setEvidence(alertParams.getString("evidence"));

            ExtensionAlert extAlert = Control
                .getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionAlert.class);

            extAlert.alertFound(alert, historyReference);

            return "";
        } catch (JSONException e) {
            throw new ApiException (ApiException.Type.MISSING_PARAMETER, e.getMessage());
        } catch (Exception e) {
            throw new ApiException (ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
    }
}
