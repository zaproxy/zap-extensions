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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.model.StandardParameterParser;

public class FrontEndScannerAPI extends ApiImplementor {

    private static final String DEFAULT_RESPONSE_HEADER =
            "HTTP/1.1 200 OK\r\n"
                    + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                    + "X-Content-Type-Options: nosniff\r\n"
                    + "Content-Type: application/javascript; charset=UTF-8\r\n";
    private static final String FRONT_END_SCANNER =
            Constant.getZapHome() + "/frontendscanner/front-end-scanner.js";
    private static final String PREFIX = "frontendscanner";
    private static final Logger LOGGER = LogManager.getLogger(ExtensionFrontEndScanner.class);

    private ExtensionFrontEndScanner extension;
    private StandardParameterParser parameterParser;

    public FrontEndScannerAPI(ExtensionFrontEndScanner extension) {
        this.extension = extension;
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
                throw new ApiException(ApiException.Type.MISSING_PARAMETER, "action");
            }

            List<NameValuePair> parameters =
                    parameterParser.getParameters(msg, HtmlParameter.Type.url);

            String action = getParamValue(parameters, "action");

            LOGGER.debug("action = {}", action);

            switch (action) {
                case "getFile":
                    return getFileFromParameters(msg, parameters);
                case "createAlert":
                    return createAlertFromMessage(msg);
                default:
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, "action");
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw new ApiException(
                    ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
    }

    private static String getParamValue(List<NameValuePair> parameters, String paramName)
            throws ApiException {
        Optional<NameValuePair> param =
                parameters.stream().filter(a -> a.getName().equals(paramName)).findFirst();
        String value = null;
        if (param.isPresent()) {
            value = param.get().getValue();
        }
        if (value != null) {
            return value;
        }
        throw new ApiException(ApiException.Type.MISSING_PARAMETER, paramName);
    }

    private String createAlertFromMessage(HttpMessage msg) throws ApiException {
        try {
            int clientSidePassiveScriptPluginId = 50006;

            JSONObject alertParams =
                    JSONObject.fromObject(msg.getRequestBody().toString()).getJSONObject("alert");

            HistoryReference historyReference =
                    new HistoryReference(alertParams.getInt("historyReferenceId"), true);

            Alert alert =
                    new Alert(
                            clientSidePassiveScriptPluginId,
                            alertParams.getInt("risk"),
                            alertParams.getInt("confidence"),
                            alertParams.getString("name"));
            alert.setSource(Alert.Source.PASSIVE);
            alert.setDescription(alertParams.getString("description"));
            alert.setEvidence(alertParams.getString("evidence"));
            alert.setUri(historyReference.getURI().toString());
            alert.setHistoryRef(historyReference);
            alert.setMessage(historyReference.getHttpMessage());
            historyReference.clearHttpMessage();

            ExtensionAlert extAlert =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);

            extAlert.alertFound(alert, historyReference);

            return "";
        } catch (JSONException e) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, e.getMessage());
        } catch (Exception e) {
            throw new ApiException(
                    ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
    }

    private String getFileFromParameters(HttpMessage msg, List<NameValuePair> parameters)
            throws ApiException, IOException {
        String fileName = getParamValue(parameters, "fileName");
        String historyReferenceId = getParamValue(parameters, "historyReferenceId");
        String host = msg.getRequestHeader().getHeader("host");

        try {
            // Prevent injection: it will fail if `historyReferenceId` is not an integer
            Integer.parseInt(historyReferenceId);
        } catch (NumberFormatException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, "historyReferenceId");
        }

        LOGGER.debug("fileName = {}", fileName);
        LOGGER.debug("historyReferenceId = {}", historyReferenceId);

        if (!fileName.equals("front-end-scanner.js")) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, "fileName");
        }

        String frontEndApiUrl = API.getInstance().getCallBackUrl(this, "https://" + host);

        // 65000 is an estimate, made by counting the characters in
        // files/frontendscanner/front-end-scanner.js
        StringBuilder injectedContentBuilder =
                new StringBuilder(65000).append("var frontEndScanner=(function() {");
        appendFrontEndScannerCodeTo(injectedContentBuilder);
        injectedContentBuilder.append("})();");

        String injectedContent =
                injectedContentBuilder
                        .toString()
                        .replace("<<HISTORY_REFERENCE_ID>>", historyReferenceId)
                        .replace(
                                "<<ZAP_CALLBACK_ENDPOINT>>",
                                frontEndApiUrl + "?action=createAlert");
        injectedContent = placeUserScriptsInto(injectedContent);

        msg.setResponseBody(injectedContent);
        msg.setResponseHeader(DEFAULT_RESPONSE_HEADER);
        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());

        return msg.getResponseBody().toString();
    }

    private void appendFrontEndScannerCodeTo(StringBuilder stringBuilder) {
        Path frontEndScannerPath = Paths.get(FRONT_END_SCANNER);
        stringBuilder.append(readFromFile(frontEndScannerPath));
    }

    private String readFromFile(Path file) throws UncheckedIOException {
        try {
            byte[] content = Files.readAllBytes(file);
            return new String(content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String placeUserScriptsInto(String string) throws IOException {
        try {
            String functions =
                    this.extension.getExtensionScript()
                            .getScripts(ExtensionFrontEndScanner.SCRIPT_TYPE_CLIENT_PASSIVE)
                            .stream()
                            .filter(ScriptWrapper::isEnabled)
                            .map(ScriptWrapper::getContents)
                            .map(code -> "function (frontEndScanner) { " + code + " }")
                            .collect(Collectors.joining(", "));

            return string.replace("'<<LIST_OF_PASSIVE_SCRIPTS>>'", '[' + functions + ']');
        } catch (UncheckedIOException e) {
            throw new IOException(e);
        }
    }
}
