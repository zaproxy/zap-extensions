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
package org.zaproxy.addon.authhelper;

import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.HttpState;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.script.ScriptVars;
import org.zaproxy.zap.extension.sessions.ExtensionSessionManagement;
import org.zaproxy.zap.extension.sessions.SessionManagementAPI;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.AbstractSessionManagementMethodOptionsPanel;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethodType;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.EncodingUtils;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.view.LayoutHelper;

/**
 * The type corresponding to a {@link org.zaproxy.zap.session.SessionManagementMethod} for web
 * applications that use Header based Authentication.
 */
public class HeaderBasedSessionManagementMethodType extends SessionManagementMethodType {

    public static final String CONTEXT_CONFIG_SESSION_MGMT_HEADER =
            ExtensionSessionManagement.CONTEXT_CONFIG_SESSION + ".headers";

    private static final int METHOD_IDENTIFIER = 3;

    private static final String API_METHOD_NAME = "headerBasedSessionManagement";

    private static final Logger LOGGER =
            LogManager.getLogger(HeaderBasedSessionManagementMethodType.class);

    public static class HeaderBasedSessionManagementMethod implements SessionManagementMethod {

        private List<Pair<String, String>> headerConfigs = new ArrayList<>();
        private static Map<String, String> envVars = System.getenv();

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        public SessionManagementMethodType getType() {
            return new HeaderBasedSessionManagementMethodType();
        }

        protected static String replaceTokens(String text, Map<String, String> tokens) {
            Pattern pattern = Pattern.compile("\\{%(.+?)\\%}");
            Matcher matcher = pattern.matcher(text);
            StringBuilder builder = new StringBuilder();
            while (matcher.find()) {
                String replacement = tokens.get(matcher.group(1));
                if (replacement == null) {
                    // Put the token back so its more obvious what failed
                    replacement = matcher.group(0);
                }
                matcher.appendReplacement(builder, replacement);
            }
            matcher.appendTail(builder);
            return builder.toString();
        }

        /**
         * Only to be used for testing
         *
         * @param vars the environment variables to be replaced
         */
        protected static void replaceEnvVarsForTesting(Map<String, String> vars) {
            envVars = vars;
        }

        protected static Map<String, String> getAllTokens(HttpMessage msg) {
            Map<String, String> tokens = new HashMap<>();
            if (msg.getResponseHeader().isJson()) {
                // Extract json response data
                String responseData = msg.getResponseBody().toString();
                try {
                    extractJsonTokens(JSONObject.fromObject(responseData), "", tokens);
                } catch (JSONException e) {
                    String url = msg.getRequestHeader().getURI().toString();
                    LOGGER.error(
                            "Unable to parse authentication response body from {} as JSON: {} ",
                            url,
                            responseData,
                            e);
                    if (View.isInitialised()) {
                        View.getSingleton()
                                .getOutputPanel()
                                .append(
                                        Constant.messages.getString(
                                                "authhelper.session.method.header.error.json.parse",
                                                url,
                                                responseData));
                    }
                }
            }
            // Add response headers
            msg.getResponseHeader()
                    .getHeaders()
                    .forEach(h -> tokens.put("header:" + h.getName(), h.getValue()));
            // Add env vars
            envVars.forEach((k, v) -> tokens.put("env:" + k, v));
            // Add Global script vars
            ScriptVars.getGlobalVars().forEach((k, v) -> tokens.put("script:" + k, v));
            // Add URL params
            msg.getUrlParams().forEach(p -> tokens.put("url:" + p.getName(), p.getValue()));

            return tokens;
        }

        private static void extractJsonTokens(
                JSONObject jsonObject, String parent, Map<String, String> tokens) {
            for (Object key : jsonObject.keySet()) {
                Object obj = jsonObject.get(key);
                extractJsonTokens(obj, normalisedKey(parent, (String) key), tokens);
            }
        }

        private static void extractJsonTokens(
                Object obj, String parent, Map<String, String> tokens) {
            if (obj instanceof JSONObject) {
                extractJsonTokens((JSONObject) obj, parent, tokens);
            } else if (obj instanceof JSONArray) {
                JSONArray ja = (JSONArray) obj;
                Object[] oa = ja.toArray();
                for (int i = 0; i < oa.length; i++) {
                    extractJsonTokens(oa[i], parent + "[" + i + "]", tokens);
                }
            } else if (obj instanceof String) {
                tokens.put("json:" + parent, (String) obj);
            }
        }

        private static String normalisedKey(String parent, String key) {
            return parent.isEmpty() ? key : parent + "." + key;
        }

        @Override
        public HttpHeaderBasedSession extractWebSession(HttpMessage msg) {
            Map<String, String> tokens = getAllTokens(msg);

            List<Pair<String, String>> headers = new ArrayList<>();
            for (Pair<String, String> hc : this.headerConfigs) {
                headers.add(new Pair<>(hc.first, replaceTokens(hc.second, tokens)));
            }
            return new HttpHeaderBasedSession(headers);
        }

        @Override
        public WebSession createEmptyWebSession() {
            return new HttpHeaderBasedSession();
        }

        @Override
        public void clearWebSessionIdentifiers(HttpMessage msg) {
            headerConfigs.clear();
        }

        public List<Pair<String, String>> getHeaderConfigs() {
            return headerConfigs;
        }

        public void setHeaderConfigs(List<Pair<String, String>> headerConfigs) {
            this.headerConfigs = headerConfigs;
        }

        @Override
        public ApiResponse getApiResponseRepresentation() {
            return new ApiResponseElement("methodName", API_METHOD_NAME);
        }

        @Override
        public void processMessageToMatchSession(HttpMessage message, WebSession session)
                throws UnsupportedWebSessionException {
            if (session instanceof HttpHeaderBasedSession) {
                HttpHeaderBasedSession hbSession = (HttpHeaderBasedSession) session;
                for (Pair<String, String> header : hbSession.getHeaders()) {
                    message.getRequestHeader().setHeader(header.first, header.second);
                }
            }
        }

        @Override
        public SessionManagementMethod clone() {
            HeaderBasedSessionManagementMethod method = new HeaderBasedSessionManagementMethod();
            List<Pair<String, String>> hc = new ArrayList<>(headerConfigs.size());
            headerConfigs.stream().forEach(p -> hc.add(new Pair<>(p.first, p.second)));
            method.setHeaderConfigs(hc);
            return method;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) return false;
            if (getClass() != obj.getClass()) return false;
            return true;
        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }
    }

    public static class HttpHeaderBasedSession extends WebSession {

        private static int generatedNameIndex;

        private List<Pair<String, String>> headers = new ArrayList<>();

        public HttpHeaderBasedSession() {
            super("HTTP Header Based Session " + generatedNameIndex++, new HttpState());
        }

        public HttpHeaderBasedSession(List<Pair<String, String>> headers) {
            super("HTTP Header Based Session " + generatedNameIndex++, new HttpState());
            this.headers = headers;
        }

        public List<Pair<String, String>> getHeaders() {
            return headers;
        }
    }

    @Override
    public HeaderBasedSessionManagementMethod createSessionManagementMethod(int contextId) {
        return new HeaderBasedSessionManagementMethod();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.session.method.header.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractSessionManagementMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new HeaderBasedSessionManagementMethodOptionsPanel();
    }

    @Override
    public boolean hasOptionsPanel() {
        return true;
    }

    @Override
    public boolean isTypeForMethod(SessionManagementMethod method) {
        return method instanceof HeaderBasedSessionManagementMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        // Nothing to hook
    }

    private static Map<String, String> listToMap(List<Pair<String, String>> list) {
        Map<String, String> map = new HashMap<>(list.size());
        list.forEach(p -> map.put(p.first, p.second));
        return map;
    }

    private static List<Pair<String, String>> mapToList(Map<String, String> map) {
        List<Pair<String, String>> list = new ArrayList<>(map.size());
        map.forEach((k, v) -> list.add(new Pair<>(k, v)));
        return list;
    }

    @Override
    public SessionManagementMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        HeaderBasedSessionManagementMethod method = new HeaderBasedSessionManagementMethod();

        Map<String, String> map =
                EncodingUtils.stringToMap(
                        session.getContextDataString(
                                contextId, RecordContext.TYPE_SESSION_MANAGEMENT_FIELD_1, ""));

        method.setHeaderConfigs(mapToList(map));

        return method;
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, SessionManagementMethod method)
            throws UnsupportedSessionManagementMethodException, DatabaseException {

        if (!(method instanceof HeaderBasedSessionManagementMethod)) {
            throw new UnsupportedSessionManagementMethodException(
                    "Header based session management type only supports: "
                            + HeaderBasedSessionManagementMethod.class.getName());
        }
        HeaderBasedSessionManagementMethod sessionMethod =
                (HeaderBasedSessionManagementMethod) method;

        session.setContextData(
                contextId,
                RecordContext.TYPE_SESSION_MANAGEMENT_FIELD_1,
                EncodingUtils.mapToString(listToMap(sessionMethod.getHeaderConfigs())));
    }

    @Override
    public void exportData(Configuration config, SessionManagementMethod sessionMethod) {
        if (!(sessionMethod instanceof HeaderBasedSessionManagementMethod)) {
            throw new UnsupportedSessionManagementMethodException(
                    "Header based session management type only supports: "
                            + HeaderBasedSessionManagementMethod.class.getName());
        }
        HeaderBasedSessionManagementMethod method =
                (HeaderBasedSessionManagementMethod) sessionMethod;

        List<String> list = new ArrayList<>();
        for (Pair<String, String> pair : method.headerConfigs) {
            list.add(
                    Base64.encodeBase64String(pair.first.getBytes())
                            + ":"
                            + (pair.second == null
                                    ? ""
                                    : Base64.encodeBase64String(pair.second.getBytes())));
        }
        config.setProperty(CONTEXT_CONFIG_SESSION_MGMT_HEADER, list);
    }

    @Override
    public void importData(Configuration config, SessionManagementMethod sessionMethod)
            throws ConfigurationException {
        if (!(sessionMethod instanceof HeaderBasedSessionManagementMethod)) {
            throw new UnsupportedSessionManagementMethodException(
                    "Header based session management type only supports: "
                            + HeaderBasedSessionManagementMethod.class.getName());
        }
        HeaderBasedSessionManagementMethod method =
                (HeaderBasedSessionManagementMethod) sessionMethod;

        List<Pair<String, String>> headerConfigs = new ArrayList<>();
        for (Object entry : config.getList(CONTEXT_CONFIG_SESSION_MGMT_HEADER)) {
            String str = entry.toString();
            int cIndex = str.indexOf(":");
            if (cIndex > 0) {
                headerConfigs.add(
                        new Pair<>(
                                new String(Base64.decodeBase64(str.substring(0, cIndex))),
                                new String(Base64.decodeBase64(str.substring(cIndex + 1)))));
            }
        }
        method.setHeaderConfigs(headerConfigs);
    }

    /* API related constant. */
    private static final String PARAM_HEADERS = "headers";

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        return new ApiDynamicActionImplementor(
                API_METHOD_NAME, new String[] {PARAM_HEADERS}, null) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context =
                        ApiUtils.getContextByParamId(params, SessionManagementAPI.PARAM_CONTEXT_ID);
                HeaderBasedSessionManagementMethod smm =
                        createSessionManagementMethod(context.getId());
                List<Pair<String, String>> headers = new ArrayList<>();
                // Headers are newline separated key: value pairs
                String[] headerArray = params.getString(PARAM_HEADERS).split("\n");
                for (String kv : headerArray) {
                    int colonIndex = kv.indexOf(":");
                    if (colonIndex < 0) {
                        throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_HEADERS);
                    }
                    headers.add(
                            new Pair<>(
                                    kv.substring(0, colonIndex - 1).strip(),
                                    kv.substring(colonIndex).strip()));
                }

                smm.setHeaderConfigs(headers);
                context.setSessionManagementMethod(smm);
            }
        };
    }

    @SuppressWarnings("serial")
    public static class HeaderBasedSessionManagementMethodOptionsPanel
            extends AbstractSessionManagementMethodOptionsPanel {

        private HeaderBasedSessionManagementPanel panel = new HeaderBasedSessionManagementPanel();
        private HeaderBasedSessionManagementMethod method;

        public HeaderBasedSessionManagementMethodOptionsPanel() {
            super();
            this.setLayout(new GridBagLayout());
            this.add(panel, LayoutHelper.getGBC(0, 0, 1, 1.0));
        }

        @Override
        public void bindMethod(SessionManagementMethod method)
                throws UnsupportedSessionManagementMethodException {
            this.method = (HeaderBasedSessionManagementMethod) method;
            this.panel.setHeaders(this.method.getHeaderConfigs());
        }

        @Override
        public void validateFields() throws IllegalStateException {
            List<Pair<String, String>> headers = panel.getHeaders();
            for (Pair<String, String> header : headers) {
                if (header.first.isBlank() || header.second.isBlank()) {
                    throw new IllegalStateException(
                            Constant.messages.getString(
                                    "authhelper.session.method.header.error.value"));
                }
            }
            if (headers.isEmpty()) {
                throw new IllegalStateException(
                        Constant.messages.getString(
                                "authhelper.session.method.header.error.headers"));
            }
        }

        @Override
        public void saveMethod() {
            method.setHeaderConfigs(panel.getHeaders());
        }

        @Override
        public SessionManagementMethod getMethod() {
            return this.method;
        }
    }
}
