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

import net.sf.json.JSONObject;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.HttpState;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.sessions.SessionManagementAPI;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.AbstractSessionManagementMethodOptionsPanel;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethodType;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.utils.ApiUtils;

/**
 * The type corresponding to a {@link org.zaproxy.zap.session.SessionManagementMethod} used to
 * indicate that ZAP should attempt to automatically detect the session management method required.
 * If ZAP succeeds in doing so then the method will be changed to the detected type.
 */
public class AutoDetectSessionManagementMethodType extends SessionManagementMethodType {

    private static final int METHOD_IDENTIFIER = 4;

    private static final String API_METHOD_NAME = "autoDetectSessionManagement";

    public static class AutoDetectSessionManagementMethod implements SessionManagementMethod {

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        public SessionManagementMethodType getType() {
            return new AutoDetectSessionManagementMethodType();
        }

        @Override
        public HttpHeaderBasedSession extractWebSession(HttpMessage msg) {
            return null;
        }

        @Override
        public WebSession createEmptyWebSession() {
            return new HttpHeaderBasedSession();
        }

        @Override
        public void clearWebSessionIdentifiers(HttpMessage msg) {}

        @Override
        public ApiResponse getApiResponseRepresentation() {
            return new ApiResponseElement("methodName", API_METHOD_NAME);
        }

        @Override
        public void processMessageToMatchSession(HttpMessage message, WebSession session)
                throws UnsupportedWebSessionException {}

        @Override
        public SessionManagementMethod clone() {
            return new AutoDetectSessionManagementMethod();
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

        public HttpHeaderBasedSession() {
            super("Auto-Detect Session " + generatedNameIndex++, new HttpState());
        }
    }

    @Override
    public AutoDetectSessionManagementMethod createSessionManagementMethod(int contextId) {
        return new AutoDetectSessionManagementMethod();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.session.method.auto.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractSessionManagementMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return null;
    }

    @Override
    public boolean hasOptionsPanel() {
        return false;
    }

    @Override
    public boolean isTypeForMethod(SessionManagementMethod method) {
        return method instanceof AutoDetectSessionManagementMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        // Nothing to hook
    }

    @Override
    public SessionManagementMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        return new AutoDetectSessionManagementMethod();
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, SessionManagementMethod method)
            throws UnsupportedSessionManagementMethodException, DatabaseException {}

    @Override
    public void exportData(Configuration config, SessionManagementMethod sessionMethod) {}

    @Override
    public void importData(Configuration config, SessionManagementMethod sessionMethod)
            throws ConfigurationException {}

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        return new ApiDynamicActionImplementor(API_METHOD_NAME, null, null) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context =
                        ApiUtils.getContextByParamId(params, SessionManagementAPI.PARAM_CONTEXT_ID);
                context.setSessionManagementMethod(createSessionManagementMethod(context.getId()));
            }
        };
    }
}
