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

import java.util.HashMap;
import java.util.Map;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AbstractCredentialsOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.authentication.AuthenticationAPI;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;

public class AutoDetectAuthenticationMethodType extends AuthenticationMethodType {

    private static final int METHOD_IDENTIFIER = 7;

    private static final String API_METHOD_NAME = "autoDetectAuthentication";

    public AutoDetectAuthenticationMethodType() {}

    public class AutoDetectAuthenticationMethod extends AuthenticationMethod {

        public AutoDetectAuthenticationMethod() {}

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        protected AuthenticationMethod duplicate() {
            return new AutoDetectAuthenticationMethod();
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return new UsernamePasswordAuthenticationCredentials();
        }

        @Override
        public AuthenticationMethodType getType() {
            return new AutoDetectAuthenticationMethodType();
        }

        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials credentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {
            return null;
        }

        @Override
        public ApiResponse getApiResponseRepresentation() {
            return new AuthMethodApiResponseRepresentation<>(new HashMap<>());
        }

        @Override
        public void replaceUserDataInPollRequest(HttpMessage msg, User user) {}
    }

    @Override
    public AutoDetectAuthenticationMethod createAuthenticationMethod(int contextId) {
        return new AutoDetectAuthenticationMethod();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth.method.autodetect.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return null;
    }

    @Override
    public boolean hasOptionsPanel() {
        return false;
    }

    @Override
    public AbstractCredentialsOptionsPanel<? extends AuthenticationCredentials>
            buildCredentialsOptionsPanel(
                    AuthenticationCredentials credentials, Context uiSharedContext) {
        return null;
    }

    @Override
    public boolean hasCredentialsOptionsPanel() {
        return false;
    }

    @Override
    public boolean isTypeForMethod(AuthenticationMethod method) {
        return method instanceof AutoDetectAuthenticationMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {}

    @Override
    public AuthenticationMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        return createAuthenticationMethod(contextId);
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, AuthenticationMethod authMethod)
            throws DatabaseException {
        if (!(authMethod instanceof AutoDetectAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Auto-Detect authentication type only supports: "
                            + AutoDetectAuthenticationMethod.class);
        }
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        if (!(authMethod instanceof AutoDetectAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Auto-Detect authentication type only supports: "
                            + AutoDetectAuthenticationMethod.class);
        }
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        if (!(authMethod instanceof AutoDetectAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Auto-Detect authentication type only supports: "
                            + AutoDetectAuthenticationMethod.class);
        }
    }

    @Override
    public UsernamePasswordAuthenticationCredentials createAuthenticationCredentials() {
        return new UsernamePasswordAuthenticationCredentials();
    }

    @Override
    public Class<UsernamePasswordAuthenticationCredentials> getAuthenticationCredentialsType() {
        return UsernamePasswordAuthenticationCredentials.class;
    }

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        String[] mandatoryParamNames = new String[] {};
        String[] optionalParamNames = new String[] {};
        return new ApiDynamicActionImplementor(
                API_METHOD_NAME, mandatoryParamNames, optionalParamNames) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context =
                        ApiUtils.getContextByParamId(params, AuthenticationAPI.PARAM_CONTEXT_ID);

                context.setAuthenticationMethod(createAuthenticationMethod(context.getId()));
            }
        };
    }

    @Override
    public ApiDynamicActionImplementor getSetCredentialsForUserApiAction() {
        return UsernamePasswordAuthenticationCredentials.getSetCredentialsForUserApiAction(this);
    }

    /*
     * Copied from org.zaproxy.zap.authentication.AuthenticationMethod
     */
    static class AuthMethodApiResponseRepresentation<T> extends ApiResponseSet<T> {

        public AuthMethodApiResponseRepresentation(Map<String, T> values) {
            super("method", values);
        }

        @Override
        public JSON toJSON() {
            JSONObject response = new JSONObject();
            response.put(getName(), super.toJSON());
            return response;
        }
    }
}
