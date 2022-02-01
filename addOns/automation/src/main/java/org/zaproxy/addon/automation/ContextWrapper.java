/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType.JsonBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class ContextWrapper {

    private Context context;

    private Data data;

    private ExtensionUserManagement extUserMgmt;

    private static final String MANUAL_AUTH_CREDS_CANONICAL_NAME =
            "org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationCredentials";

    private static final Logger LOG = LogManager.getLogger(ContextWrapper.class);

    public ContextWrapper(Data data) {
        this.data = data;
    }

    /**
     * Create a ContextWrapper from an existing Context
     *
     * @param context the existing context
     */
    public ContextWrapper(Context context) {
        this.context = context;
        this.data = new Data();
        this.data.setName(context.getName());
        this.data.setIncludePaths(context.getIncludeInContextRegexs());
        this.data.setExcludePaths(context.getExcludeFromContextRegexs());
        // Contexts dont actually define the starting URL, but we need at least one
        for (String url : context.getIncludeInContextRegexs()) {
            if (url.endsWith(".*")) {
                this.addUrl(url.substring(0, url.length() - 2));
            }
        }

        this.data.setSessionManagement(new SessionManagementData(context));
        this.data.setAuthentication(new AuthenticationData(context));

        if (getExtUserMgmt() != null) {
            ArrayList<UserData> users = new ArrayList<>();
            for (User user : extUserMgmt.getContextUserAuthManager(context.getId()).getUsers()) {
                if (user.getAuthenticationCredentials()
                        instanceof UsernamePasswordAuthenticationCredentials) {
                    UsernamePasswordAuthenticationCredentials upCreds =
                            (UsernamePasswordAuthenticationCredentials)
                                    user.getAuthenticationCredentials();
                    users.add(
                            new UserData(
                                    user.getName(), upCreds.getUsername(), upCreds.getPassword()));
                } else if (user.getAuthenticationCredentials()
                        instanceof GenericAuthenticationCredentials) {
                    GenericAuthenticationCredentials genCreds =
                            (GenericAuthenticationCredentials) user.getAuthenticationCredentials();
                    @SuppressWarnings("unchecked")
                    Map<String, String> paramValues =
                            (Map<String, String>) JobUtils.getPrivateField(genCreds, "paramValues");
                    UserData ud = new UserData(user.getName());
                    ud.setCredentials(paramValues);
                    users.add(ud);
                } else if (MANUAL_AUTH_CREDS_CANONICAL_NAME.equals(
                        user.getAuthenticationCredentials().getClass().getCanonicalName())) {
                    // Cannot use instanceof as its a private class :/
                    users.add(new UserData(user.getName()));
                } else {
                    LOG.debug(
                            "Auth credentials {} not yet supported",
                            user.getAuthenticationCredentials().getClass().getCanonicalName());
                }
            }
            if (!users.isEmpty()) {
                this.getData().setUsers(users);
            }
        }
    }

    public ContextWrapper(
            Map<?, ?> contextData, AutomationEnvironment env, AutomationProgress progress) {
        this.data = new Data();
        for (Entry<?, ?> cdata : contextData.entrySet()) {
            Object value = cdata.getValue();
            if (value == null) {
                continue;
            }
            switch (cdata.getKey().toString()) {
                case "name":
                    data.setName(value.toString());
                    break;
                case "urls":
                    if (!(value instanceof ArrayList)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badurlslist", value));

                    } else {
                        ArrayList<?> urlList = (ArrayList<?>) value;
                        for (Object urlObj : urlList) {
                            String url = urlObj.toString();
                            data.getUrls().add(url);
                            validateUrl(url, progress);
                        }
                    }
                    break;
                case "url":
                    // For backwards compatibility
                    String url = value.toString();
                    data.getUrls().add(url);
                    validateUrl(url, progress);
                    progress.warn(
                            Constant.messages.getString("automation.error.context.url.deprecated"));
                    break;
                case "includePaths":
                    data.setIncludePaths(verifyRegexes(value, "badincludelist", progress));
                    break;
                case "excludePaths":
                    data.setExcludePaths(verifyRegexes(value, "badexcludelist", progress));
                    break;
                case "authentication":
                    data.setAuthentication(new AuthenticationData(value, progress));
                    break;
                case "sessionManagement":
                    data.setSessionManagement(new SessionManagementData(value, progress));
                    break;
                case "users":
                    if (!(value instanceof ArrayList)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.baduserslist", value));
                    } else {
                        List<UserData> users = new ArrayList<>();
                        ArrayList<?> userList = (ArrayList<?>) value;
                        for (Object userObj : userList) {
                            if (!(userObj instanceof LinkedHashMap)) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.context.baduser", userObj));
                            } else {
                                UserData ud = new UserData();
                                JobUtils.applyParamsToObject(
                                        (LinkedHashMap<?, ?>) userObj, ud, "users", null, progress);
                                if (env.getUser(ud.getName()) != null) {
                                    progress.error(
                                            Constant.messages.getString(
                                                    "automation.error.context.dupuser",
                                                    data.getName(),
                                                    ud.getCredential(
                                                            UserData.USERNAME_CREDENTIAL)));
                                } else {
                                    users.add(ud);
                                }
                            }
                        }
                        data.setUsers(users);
                    }
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown",
                                    AutomationEnvironment.AUTOMATION_CONTEXT_NAME,
                                    cdata.getKey().toString()));
            }
        }
        if (StringUtils.isEmpty(data.getName())) {
            progress.error(
                    Constant.messages.getString("automation.error.context.noname", contextData));
        }
        if (data.getUrls().isEmpty()) {
            progress.error(
                    Constant.messages.getString("automation.error.context.nourl", contextData));
        }
    }

    private void validateUrl(String url, AutomationProgress progress) {
        try {
            if (!url.contains("${")) {
                // Cannot validate urls containing envvars
                new URI(url, true);
            }
        } catch (URIException e) {
            progress.error(Constant.messages.getString("automation.error.context.badurl", url));
        }
    }

    private List<String> verifyRegexes(Object value, String key, AutomationProgress progress) {
        if (!(value instanceof ArrayList<?>)) {
            progress.error(Constant.messages.getString("automation.error.context." + key, value));
            return Collections.emptyList();
        }
        ArrayList<String> regexes = new ArrayList<>();
        for (Object regex : (ArrayList<?>) value) {
            String regexStr = regex.toString();
            regexes.add(regexStr);
            try {
                if (!regexStr.contains("${")) {
                    // Only validate the regex if it doesnt contain vars
                    Pattern.compile(regexStr);
                }
            } catch (PatternSyntaxException e) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.badregex",
                                regex.toString(),
                                e.getMessage()));
            }
        }
        return regexes;
    }

    public Context getContext() {
        return this.context;
    }

    public void addUrl(String url) {
        this.data.getUrls().add(url);
    }

    public List<String> getUrls() {
        return this.data.getUrls();
    }

    public Data getData() {
        return data;
    }

    public void setData(Data data) {
        this.data = data;
    }

    public void createContext(
            Session session, AutomationEnvironment env, AutomationProgress progress) {
        String contextName = env.replaceVars((getData().getName()));
        Context oldContext = session.getContext(contextName);
        if (oldContext != null) {
            session.deleteContext(oldContext);
        }
        this.context = session.getNewContext(contextName);
        for (String url : getData().getUrls()) {
            try {
                String urlWithEnvs = env.replaceVars(url);
                new URI(urlWithEnvs, true);
                this.context.addIncludeInContextRegex(urlWithEnvs + ".*");
            } catch (Exception e) {
                progress.error(Constant.messages.getString("automation.error.context.badurl", url));
            }
        }
        List<String> includePaths = getData().getIncludePaths();
        if (includePaths != null) {
            for (String path : includePaths) {
                String incRegex = env.replaceVars(path);
                if (!this.context.getIncludeInContextRegexs().contains(incRegex)) {
                    // The inc regex could have been included above, so no point duplicating it
                    this.context.addIncludeInContextRegex(incRegex);
                }
            }
        }
        List<String> excludePaths = getData().getExcludePaths();
        if (excludePaths != null) {
            for (String path : excludePaths) {
                this.context.addExcludeFromContextRegex(env.replaceVars(path));
            }
        }
        if (getData().getSessionManagement() != null) {
            getData().getSessionManagement().initContextSessionManagement(context, progress, env);
        }
        if (getData().getAuthentication() != null) {
            getData().getAuthentication().initContextAuthentication(context, progress, env);
        }
        if (getData().getUsers() != null) {
            initContextUsers(context, env);
        }
    }

    private void initContextUsers(Context context, AutomationEnvironment env) {
        if (getExtUserMgmt() != null) {
            for (UserData ud : getData().getUsers()) {
                User user = new User(context.getId(), env.replaceVars(ud.getName()));
                AuthenticationMethod authMethod = context.getAuthenticationMethod();
                if (authMethod instanceof HttpAuthenticationMethod
                        || authMethod instanceof FormBasedAuthenticationMethod
                        || authMethod instanceof JsonBasedAuthenticationMethod) {
                    UsernamePasswordAuthenticationCredentials upCreds =
                            new UsernamePasswordAuthenticationCredentials(
                                    env.replaceVars(ud.getCredential(UserData.USERNAME_CREDENTIAL)),
                                    env.replaceVars(
                                            ud.getCredential(UserData.PASSWORD_CREDENTIAL)));
                    user.setAuthenticationCredentials(upCreds);
                } else if (authMethod instanceof ManualAuthenticationMethod) {
                    user.setAuthenticationCredentials(
                            authMethod.getType().createAuthenticationCredentials());
                } else if (authMethod instanceof ScriptBasedAuthenticationMethod) {
                    ScriptBasedAuthenticationMethod scriptMethod =
                            (ScriptBasedAuthenticationMethod) authMethod;
                    String[] credName =
                            (String[])
                                    JobUtils.getPrivateField(scriptMethod, "credentialsParamNames");
                    GenericAuthenticationCredentials genCreds =
                            new GenericAuthenticationCredentials(credName);
                    for (Entry<String, String> cred : ud.getCredentials().entrySet()) {
                        genCreds.setParam(cred.getKey(), env.replaceVars(cred.getValue()));
                    }
                    user.setAuthenticationCredentials(genCreds);
                } else {
                    LOG.error(
                            "Users not supported for {}", authMethod.getClass().getCanonicalName());
                }
                user.setEnabled(true);
                extUserMgmt.getContextUserAuthManager(context.getId()).addUser(user);
            }
        }
    }

    public List<String> getUserNames() {
        List<String> userNames = new ArrayList<>();
        if (this.getData().getUsers() != null) {
            this.getData().getUsers().stream().forEach(u -> userNames.add(u.getName()));
        }
        return userNames;
    }

    public User getUser(String name) {
        if (getExtUserMgmt() != null) {
            for (User user : extUserMgmt.getContextUserAuthManager(context.getId()).getUsers()) {
                if (user.getName().equals(name)) {
                    LOG.debug("User {} found in context {}", name, context.getName());
                    return user;
                }
            }
        }
        LOG.debug("User {} not found in context {}", name, context.getName());
        return null;
    }

    private ExtensionUserManagement getExtUserMgmt() {
        if (extUserMgmt == null
                && Control.getSingleton() != null
                && Control.getSingleton().getExtensionLoader() != null) {
            extUserMgmt =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionUserManagement.class);
        }
        return extUserMgmt;
    }

    public static class Data extends AutomationData {
        private String name;
        private List<String> urls = new ArrayList<>();
        private List<String> includePaths;
        private List<String> excludePaths;
        private AuthenticationData authentication;
        private SessionManagementData sessionManagement;
        private List<UserData> users;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls = urls;
        }

        public List<String> getIncludePaths() {
            return includePaths;
        }

        public void setIncludePaths(List<String> includePaths) {
            this.includePaths = includePaths;
        }

        public List<String> getExcludePaths() {
            return excludePaths;
        }

        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }

        public AuthenticationData getAuthentication() {
            return authentication;
        }

        public void setAuthentication(AuthenticationData authentication) {
            this.authentication = authentication;
        }

        public SessionManagementData getSessionManagement() {
            return sessionManagement;
        }

        public void setSessionManagement(SessionManagementData sessionManagement) {
            this.sessionManagement = sessionManagement;
        }

        public List<UserData> getUsers() {
            return users;
        }

        public void setUsers(List<UserData> users) {
            this.users = users;
        }
    }

    public static class UserData extends AutomationData {

        public static final String USERNAME_CREDENTIAL = "username";
        public static final String PASSWORD_CREDENTIAL = "password";

        private String name;
        private Map<String, String> credentials = new HashMap<>();

        public UserData() {}

        public UserData(String name) {
            this.name = name;
        }

        public UserData(String name, String username, String password) {
            this.name = name;
            this.credentials.put(USERNAME_CREDENTIAL, username);
            this.credentials.put(PASSWORD_CREDENTIAL, password);
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setUsername(String username) {
            // Required for backwards compatibility
            this.credentials.put(USERNAME_CREDENTIAL, username);
        }

        public void setPassword(String password) {
            // Required for backwards compatibility
            this.credentials.put(PASSWORD_CREDENTIAL, password);
        }

        public Map<String, String> getCredentials() {
            return credentials;
        }

        public String getCredential(String key) {
            return this.credentials.get(key);
        }

        public void setCredentials(Map<String, String> credentials) {
            this.credentials = credentials;
        }
    }
}
