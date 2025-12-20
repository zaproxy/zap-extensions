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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
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
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zap.model.StructuralNodeModifier;
import org.zaproxy.zap.users.User;

public class ContextWrapper {

    private Context context;

    private Data data;

    private ExtensionUserManagement extUserMgmt;

    private static final String MANUAL_AUTH_CREDS_CANONICAL_NAME =
            "org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationCredentials";

    private static final Logger LOGGER = LogManager.getLogger(ContextWrapper.class);

    public ContextWrapper(Data data) {
        this.data = data;
    }

    /**
     * Create a ContextWrapper from an existing Context
     *
     * @param context the existing context
     * @param env the environment
     */
    public ContextWrapper(Context context, AutomationEnvironment env) {
        this.context = context;
        this.data = new Data();
        this.data.setName(context.getName());
        this.data.setIncludePaths(context.getIncludeInContextRegexs());
        this.data.setExcludePaths(context.getExcludeFromContextRegexs());
        // Contexts dont actually define the starting URL, but we need at least one
        for (String url : context.getIncludeInContextRegexs()) {
            if (url.endsWith(".*")) {
                String urlStr = env.replaceVars(url.substring(0, url.length() - 2));
                try {
                    new URI(urlStr, true);
                    this.addUrl(urlStr);
                } catch (Exception e) {
                    // Ignore - could well be a more complex regex
                }
            }
        }

        this.data.setSessionManagement(new SessionManagementData(context));
        this.data.setTechnology(new TechnologyData(context));
        this.data.setStructure(new StructureData(context));

        if (getExtUserMgmt() != null) {
            ArrayList<UserData> users = new ArrayList<>();
            for (User user : extUserMgmt.getContextUserAuthManager(context.getId()).getUsers()) {
                if (user.getAuthenticationCredentials()
                        instanceof UsernamePasswordAuthenticationCredentials) {
                    UsernamePasswordAuthenticationCredentials upCreds =
                            (UsernamePasswordAuthenticationCredentials)
                                    user.getAuthenticationCredentials();
                    UserData ud =
                            new UserData(
                                    user.getName(), upCreds.getUsername(), upCreds.getPassword());
                    setTotpData(upCreds, ud);
                    users.add(ud);
                } else if (user.getAuthenticationCredentials()
                        instanceof GenericAuthenticationCredentials) {
                    GenericAuthenticationCredentials genCreds =
                            (GenericAuthenticationCredentials) user.getAuthenticationCredentials();
                    @SuppressWarnings("unchecked")
                    Map<String, String> paramValues =
                            (Map<String, String>) JobUtils.getPrivateField(genCreds, "paramValues");
                    UserData ud = new UserData(user.getName());
                    ud.setCredentials(paramValues);
                    setTotpData(genCreds, ud);
                    ud.getInternalCredentials().setTotp(null);
                    users.add(ud);
                } else if (MANUAL_AUTH_CREDS_CANONICAL_NAME.equals(
                        user.getAuthenticationCredentials().getClass().getCanonicalName())) {
                    // Cannot use instanceof as its a private class :/
                    users.add(new UserData(user.getName()));
                } else {
                    LOGGER.debug(
                            "Auth credentials {} not yet supported",
                            user.getAuthenticationCredentials().getClass().getCanonicalName());
                }
            }
            if (!users.isEmpty()) {
                this.getData().setUsers(users);
            }
        }
        this.data.setAuthentication(new AuthenticationData(context, getData().getUsers()));
    }

    private static void setTotpData(AuthenticationCredentials credentials, UserData ud) {
        TotpSupport.TotpData coreData = TotpSupport.getTotpData(credentials);
        if (coreData == null) {
            return;
        }

        UserData.TotpData totpData = new UserData.TotpData();
        totpData.setSecret(coreData.secret());
        totpData.setPeriod(String.valueOf(coreData.period()));
        totpData.setDigits(String.valueOf(coreData.digits()));
        totpData.setAlgorithm(coreData.algorithm());
        ud.getInternalCredentials().setTotp(totpData);
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
                    data.setIncludePaths(
                            JobUtils.verifyRegexes(value, cdata.getKey().toString(), progress));
                    break;
                case "excludePaths":
                    data.setExcludePaths(
                            JobUtils.verifyRegexes(value, cdata.getKey().toString(), progress));
                    break;
                case "authentication":
                    data.setAuthentication(new AuthenticationData(value, progress));
                    break;
                case "sessionManagement":
                    data.setSessionManagement(new SessionManagementData(value, progress, env));
                    break;
                case "technology":
                    data.setTechnology(new TechnologyData(value, env, progress));
                    break;
                case "structure":
                    data.setStructure(new StructureData(value, progress));
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
                                readTotpData(ud, userObj);
                                forceCredentialsStringType(userObj);
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

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void readTotpData(UserData ud, Object userObj) {
        Object credentials = ((LinkedHashMap) userObj).get("credentials");
        if (!(credentials instanceof LinkedHashMap map)) {
            return;
        }

        Object data = map.remove("totp");
        if (!(data instanceof LinkedHashMap)) {
            return;
        }

        try {
            ud.getInternalCredentials()
                    .setTotp(
                            JsonMapper.builder()
                                    .build()
                                    .convertValue(data, UserData.TotpData.class));
        } catch (Exception e) {
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void forceCredentialsStringType(Object userObj) {
        Object credentials = ((LinkedHashMap) userObj).get("credentials");
        if (credentials instanceof LinkedHashMap) {
            ((LinkedHashMap) credentials)
                    .replaceAll(
                            (k, v) -> {
                                if (v instanceof Number) {
                                    return v.toString();
                                }
                                return v;
                            });
        }
    }

    private void validateUrl(String url, AutomationProgress progress) {
        try {
            if (!JobUtils.containsVars(url)) {
                // Cannot validate urls containing envvars
                new URI(url, true);
            }
        } catch (URIException e) {
            progress.error(Constant.messages.getString("automation.error.context.badurl", url));
        }
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
            getData()
                    .getAuthentication()
                    .initContextAuthentication(context, progress, env, getData().getUsers());
        }
        if (getData().getTechnology() != null) {
            getData().getTechnology().initContextTechnology(context, progress);
        }
        if (getData().getStructure() != null) {
            getData().getStructure().initContext(context, env, progress);
        }
        if (getData().getUsers() != null) {
            initContextUsers(context, env);
        }
        session.saveContext(context);
    }

    private void initContextUsers(Context context, AutomationEnvironment env) {
        if (getExtUserMgmt() != null) {
            for (UserData ud : getData().getUsers()) {
                User user = new User(context.getId(), env.replaceVars(ud.getName()));
                AuthenticationMethod authMethod = context.getAuthenticationMethod();
                if (authMethod instanceof HttpAuthenticationMethod
                        || authMethod instanceof FormBasedAuthenticationMethod
                        || authMethod instanceof JsonBasedAuthenticationMethod
                        || authMethod
                                .getClass()
                                .getCanonicalName()
                                .equals(AuthenticationData.BROWSER_BASED_AUTH_METHOD_CLASSNAME)) {
                    UsernamePasswordAuthenticationCredentials upCreds =
                            TotpSupport.createUsernamePasswordAuthenticationCredentials(
                                    authMethod,
                                    env.replaceVars(ud.getCredential(UserData.USERNAME_CREDENTIAL)),
                                    env.replaceVars(
                                            ud.getCredential(UserData.PASSWORD_CREDENTIAL)));

                    setTotpData(ud, upCreds, env);
                    user.setAuthenticationCredentials(upCreds);
                } else if (authMethod instanceof ManualAuthenticationMethod) {
                    user.setAuthenticationCredentials(
                            authMethod.getType().createAuthenticationCredentials());
                } else if (authMethod instanceof ScriptBasedAuthenticationMethod) {
                    GenericAuthenticationCredentials genCreds =
                            (GenericAuthenticationCredentials)
                                    authMethod.createAuthenticationCredentials();
                    for (Entry<String, String> cred : ud.getCredentials().entrySet()) {
                        genCreds.setParam(cred.getKey(), env.replaceVars(cred.getValue()));
                    }
                    setTotpData(ud, genCreds, env);
                    user.setAuthenticationCredentials(genCreds);
                } else {
                    LOGGER.error(
                            "Users not supported for {}", authMethod.getClass().getCanonicalName());
                }
                user.setEnabled(true);
                extUserMgmt.getContextUserAuthManager(context.getId()).addUser(user);
            }
        }
    }

    private static void setTotpData(
            UserData ud, AuthenticationCredentials credentials, AutomationEnvironment env) {
        if (ud.getInternalCredentials().getTotp() == null) {
            return;
        }

        String algorithm = env.replaceVars(ud.getInternalCredentials().getTotp().getAlgorithm());
        TotpSupport.TotpData totpData =
                new TotpSupport.TotpData(
                        env.replaceVars(ud.getInternalCredentials().getTotp().getSecret()),
                        getInt(
                                env.replaceVars(ud.getInternalCredentials().getTotp().getPeriod()),
                                30),
                        getInt(
                                env.replaceVars(ud.getInternalCredentials().getTotp().getDigits()),
                                6),
                        algorithm == null ? "SHA1" : algorithm);
        TotpSupport.setTotpData(totpData, credentials);
    }

    private static int getInt(String value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            LOGGER.warn("An error occurred while parsing: {}", value, e);
        }
        return defaultValue;
    }

    public List<String> getUserNames() {
        List<String> userNames = new ArrayList<>();
        if (this.getData().getUsers() != null) {
            this.getData().getUsers().stream().forEach(u -> userNames.add(u.getName()));
        }
        return userNames;
    }

    public User getUser(String name) {
        if (getExtUserMgmt() != null && context != null) {
            for (User user : extUserMgmt.getContextUserAuthManager(context.getId()).getUsers()) {
                if (user.getName().equals(name)) {
                    LOGGER.debug("User {} found in context {}", name, context.getName());
                    return user;
                }
            }
        }
        LOGGER.debug("User {} not found in context {}", name, data.getName());
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

    @Getter
    @Setter
    public static class Data extends AutomationData {
        private String name;
        private List<String> urls = new ArrayList<>();
        private List<String> includePaths = new ArrayList<>();
        private List<String> excludePaths = new ArrayList<>();
        private AuthenticationData authentication;
        private SessionManagementData sessionManagement;
        private TechnologyData technology;
        private StructureData structure;
        private List<UserData> users = new ArrayList<>();
    }

    public static class UserData extends AutomationData {

        public static final String USERNAME_CREDENTIAL = "username";
        public static final String PASSWORD_CREDENTIAL = "password";

        private String name;
        private Credentials credentials = new Credentials();

        public UserData() {}

        public UserData(String name) {
            this.name = name;
        }

        public UserData(String name, String username, String password) {
            this.name = name;
            this.credentials.getParameters().put(USERNAME_CREDENTIAL, username);
            this.credentials.getParameters().put(PASSWORD_CREDENTIAL, password);
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setUsername(String username) {
            // Required for backwards compatibility
            this.credentials.getParameters().put(USERNAME_CREDENTIAL, username);
        }

        public void setPassword(String password) {
            // Required for backwards compatibility
            this.credentials.getParameters().put(PASSWORD_CREDENTIAL, password);
        }

        @JsonIgnore
        public Map<String, String> getCredentials() {
            return credentials.getParameters();
        }

        public String getCredential(String key) {
            return this.credentials.getParameters().get(key);
        }

        public void setCredentials(Map<String, String> credentials) {
            this.credentials.setParameters(credentials);
        }

        @JsonGetter("credentials")
        public Credentials getInternalCredentials() {
            return credentials;
        }

        @Getter
        @Setter
        public static class Credentials {

            @JsonAnyGetter private Map<String, String> parameters = new HashMap<>();

            private TotpData totp;

            @JsonIgnore
            public Map<String, String> getParameters() {
                return parameters;
            }
        }

        @Getter
        @Setter
        public static class TotpData {

            private String secret;
            private String period;
            private String digits;
            private String algorithm;
        }
    }

    @Getter
    @Setter
    public static class StructureData {

        private List<String> structuralParameters;
        private List<DataDrivenNodeData> dataDrivenNodes;

        public StructureData() {
            structuralParameters = new ArrayList<>();
            dataDrivenNodes = new ArrayList<>();
        }

        StructureData(Context context) {
            this();

            var urlParamParser = context.getUrlParamParser();
            if (urlParamParser instanceof StandardParameterParser) {
                var spp = (StandardParameterParser) urlParamParser;
                structuralParameters = new ArrayList<>(spp.getStructuralParameters());
            }
            context.getDataDrivenNodes()
                    .forEach(
                            ddn ->
                                    dataDrivenNodes.add(
                                            new DataDrivenNodeData(
                                                    ddn.getName(), ddn.getPattern().toString())));
        }

        StructureData(Object data, AutomationProgress progress) {
            this();

            if (!(data instanceof Map)) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.badstructure",
                                data.getClass().getSimpleName()));
                return;
            }

            Map<?, ?> dataMap = (Map<?, ?>) data;
            for (Entry<?, ?> cdata : dataMap.entrySet()) {
                if ("structuralParameters".equals(cdata.getKey().toString())) {
                    Object value = cdata.getValue();
                    if (!(value instanceof List)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badstructuralparameterslist",
                                        value));

                    } else {
                        ((List<?>) value)
                                .stream().map(Object::toString).forEach(structuralParameters::add);
                    }
                } else if ("dataDrivenNodes".equals(cdata.getKey().toString())) {
                    Object value = cdata.getValue();
                    if (!(value instanceof List)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badddnlist", value));

                    } else {
                        List<DataDrivenNodeData> ddnList = new ArrayList<>();
                        for (Object ddn : (List<?>) value) {
                            if (!(ddn instanceof LinkedHashMap)) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.env.ddn.bad", ddn));
                                continue;
                            }
                            LinkedHashMap<?, ?> ddnMap = (LinkedHashMap<?, ?>) ddn;
                            Object nameObj = ddnMap.get("name");
                            Object regexObj = ddnMap.get("regex");
                            if (ddnMap.size() != 2
                                    || !(nameObj instanceof String)
                                    || !(regexObj instanceof String)) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.env.ddn.bad", ddn));
                                continue;
                            }
                            String regex = (String) regexObj;
                            try {
                                Pattern.compile(regex);
                            } catch (Exception e) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.env.ddn.regex.bad", regex));
                                continue;
                            }
                            if (!regex.matches(".*\\(.*\\).*\\(.*\\).*")) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.env.ddn.regex.format", regex));
                                continue;
                            }
                            ddnList.add(new DataDrivenNodeData((String) nameObj, regex));
                        }
                        if (!ddnList.isEmpty()) {
                            this.setDataDrivenNodes(ddnList);
                        }
                    }
                } else {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown",
                                    AutomationEnvironment.AUTOMATION_CONTEXT_NAME,
                                    cdata.getKey().toString()));
                }
            }
        }

        void initContext(Context context, AutomationEnvironment env, AutomationProgress progress) {
            var urlParamParser = new StandardParameterParser();
            urlParamParser.setStructuralParameters(
                    structuralParameters.stream()
                            .map(env::replaceVars)
                            .filter(
                                    e -> {
                                        if (e.matches("\\w+")) {
                                            return true;
                                        }

                                        progress.error(
                                                Constant.messages.getString(
                                                        "automation.error.context.badstructuralparametername",
                                                        e));
                                        return false;
                                    })
                            .collect(Collectors.toList()));

            context.setUrlParamParser(urlParamParser);
            urlParamParser.setContext(context);

            context.setDataDrivenNodes(
                    dataDrivenNodes.stream()
                            .map(
                                    ddn ->
                                            new StructuralNodeModifier(
                                                    StructuralNodeModifier.Type.DataDrivenNode,
                                                    Pattern.compile(ddn.getRegex()),
                                                    ddn.getName()))
                            .toList());
        }

        @Getter
        @Setter
        @AllArgsConstructor
        public static class DataDrivenNodeData {
            private String name;
            private String regex;
        }
    }
}
