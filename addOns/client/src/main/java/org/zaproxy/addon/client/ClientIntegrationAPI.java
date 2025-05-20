/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ReportedElement;
import org.zaproxy.addon.client.internal.ReportedEvent;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

public class ClientIntegrationAPI extends ApiImplementor {
    private static final String PREFIX = "client";

    private static final String ACTION_EXPORT_CLIENT_MAP = "exportClientMap";
    private static final String ACTION_REPORT_OBJECT = "reportObject";
    private static final String ACTION_REPORT_EVENT = "reportEvent";
    private static final String ACTION_REPORT_ZEST_STATEMENT = "reportZestStatement";
    private static final String ACTION_REPORT_ZEST_SCRIPT = "reportZestScript";

    private static final String PARAM_EXPORT_PATH = "pathYaml";
    private static final String PARAM_OBJECT_JSON = "objectJson";
    private static final String PARAM_EVENT_JSON = "eventJson";
    private static final String PARAM_STATEMENT_JSON = "statementJson";
    private static final String PARAM_SCRIPT_JSON = "scriptJson";

    private static final Logger LOGGER = LogManager.getLogger(ClientIntegrationAPI.class);

    private ExtensionClientIntegration extension;

    private String callbackUrl;

    public ClientIntegrationAPI(ExtensionClientIntegration extension) {
        this.extension = extension;

        this.addApiAction(new ApiAction(ACTION_REPORT_OBJECT, new String[] {PARAM_OBJECT_JSON}));
        this.addApiAction(new ApiAction(ACTION_REPORT_EVENT, new String[] {PARAM_EVENT_JSON}));
        this.addApiAction(
                new ApiAction(ACTION_REPORT_ZEST_STATEMENT, new String[] {PARAM_STATEMENT_JSON}));
        this.addApiAction(
                new ApiAction(ACTION_REPORT_ZEST_SCRIPT, new String[] {PARAM_SCRIPT_JSON}));

        this.addApiAction(
                new ApiAction(ACTION_EXPORT_CLIENT_MAP, new String[] {PARAM_EXPORT_PATH}));

        callbackUrl =
                API.getInstance().getCallBackUrl(this, HttpHeader.SCHEME_HTTPS + API.API_DOMAIN);
        LOGGER.debug("Client API callback URL: {}", callbackUrl);
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    protected String getCallbackUrl() {
        return callbackUrl;
    }

    private void handleReportObject(String jsonStr) {
        LOGGER.debug("Got object: {}", jsonStr);
        JSONObject json = JSONObject.fromObject(jsonStr);
        ReportedElement rnode = new ReportedElement(json);
        if (!"A".equals(rnode.getNodeName())) {
            // Dont add links - they flood the table
            this.extension.addReportedObject(rnode);
        }
        Object url = json.get("url");
        if (url instanceof String) {
            String urlStr = (String) url;
            if (!ExtensionClientIntegration.isApiUrl(urlStr)) {
                ClientNode node = this.extension.getOrAddClientNode(urlStr, false, false);
                ClientSideComponent component = new ClientSideComponent(json);
                extension.addComponentToNode(node, component);
                if (component.isStorageEvent()) {
                    String storageUrl = node.getSite() + component.getTypeForDisplay();
                    extension.addComponentToNode(
                            this.extension.getOrAddClientNode(storageUrl, false, true), component);
                }
            }
        } else {
            LOGGER.debug("Not got url:(: {}", url);
        }
        Object href = json.get("href");
        if (href instanceof String && ((String) href).toLowerCase(Locale.ROOT).startsWith("http")) {
            extension.getOrAddClientNode((String) href, false, false);
        }
    }

    private void handleReportEvent(String jsonStr) {
        LOGGER.debug("Got event: {}", jsonStr);
        JSONObject json = JSONObject.fromObject(jsonStr);
        ReportedEvent event = new ReportedEvent(json);
        if (event.getUrl() == null || !ExtensionClientIntegration.isApiUrl(event.getUrl())) {
            this.extension.addReportedObject(event);
            if (event.getUrl() != null) {
                extension.setVisited(event.getUrl());
            }
        }
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        try {
            switch (name) {
                case ACTION_REPORT_OBJECT ->
                        handleReportObject(this.getParam(params, PARAM_OBJECT_JSON, ""));

                case ACTION_REPORT_EVENT ->
                        handleReportEvent(this.getParam(params, PARAM_EVENT_JSON, ""));

                case ACTION_REPORT_ZEST_STATEMENT ->
                        this.extension.addZestStatement(
                                this.getParam(params, PARAM_STATEMENT_JSON, ""));
                case ACTION_REPORT_ZEST_SCRIPT ->
                        this.extension.addZestStatement(
                                this.getParam(params, PARAM_SCRIPT_JSON, ""));
                case ACTION_EXPORT_CLIENT_MAP -> {
                    String exportPath = this.getParam(params, PARAM_EXPORT_PATH, "");

                    validateExportPath(exportPath);

                    if (!this.extension.exportClientMap(exportPath, true)) {
                        throw new ApiException(
                                ApiException.Type.INTERNAL_ERROR,
                                "Failed to export client map: " + exportPath);
                    }
                }
                default -> throw new ApiException(ApiException.Type.BAD_ACTION);
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR);
        }

        return ApiResponseElement.OK;
    }

    static String decodeParamString(String body, String param) {
        // Should always start with 'param'=
        String str = body.substring(param.length() + 1);
        int apikeyIndex = str.indexOf("&apikey=");
        if (apikeyIndex > 0) {
            str = str.substring(0, apikeyIndex);
        }
        str = URLDecoder.decode(str, StandardCharsets.UTF_8);
        return str;
    }

    @Override
    public String handleCallBack(HttpMessage msg) throws ApiException {
        if (HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            String body = msg.getRequestBody().toString();

            if (body.startsWith(PARAM_OBJECT_JSON + "=")) {
                handleReportObject(decodeParamString(body, PARAM_OBJECT_JSON));
            } else if (body.startsWith(PARAM_EVENT_JSON)) {
                handleReportEvent(decodeParamString(body, PARAM_EVENT_JSON));
            } else if (body.startsWith(PARAM_STATEMENT_JSON)) {
                try {
                    this.extension.addZestStatement(decodeParamString(body, PARAM_STATEMENT_JSON));
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
            } else if (body.startsWith(PARAM_SCRIPT_JSON)) {
                try {
                    this.extension.addZestStatement(decodeParamString(body, PARAM_SCRIPT_JSON));
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
            }
        }
        // Will be accessed via a GET as part of the browser ext initiation
        return "";
    }

    private static void validateExportPath(String exportPath) throws ApiException {
        try {
            Path path = Paths.get(exportPath).toAbsolutePath().normalize();

            if (Files.exists(path)) {
                if (!Files.isRegularFile(path)) {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER,
                            "Export path is not a file: " + path);
                }

                if (!Files.isWritable(path)) {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER,
                            "Export file is not writable: " + path);
                }
                return;
            }

            Path parentDir = path.getParent();
            if (parentDir == null || Files.notExists(parentDir)) {
                throw new ApiException(
                        ApiException.Type.ILLEGAL_PARAMETER,
                        "Export directory does not exist: " + parentDir);
            }

            if (!Files.isWritable(parentDir)) {
                throw new ApiException(
                        ApiException.Type.ILLEGAL_PARAMETER,
                        "Export directory is not writable: " + parentDir);
            }

        } catch (InvalidPathException e) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER, "Invalid export path: " + exportPath);
        }
    }
}
