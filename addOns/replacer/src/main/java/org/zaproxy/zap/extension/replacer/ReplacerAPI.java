/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.ConfigurationException;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;

public class ReplacerAPI extends ApiImplementor {

    private static final String PREFIX = "replacer";
    private static final String VIEW_RULES = "rules";
    private static final String ACTION_ADD_RULE = "addRule";
    private static final String ACTION_REMOVE_RULE = "removeRule";
    private static final String ACTION_SET_ENABLED = "setEnabled";

    private static final String DESC = "description";

    private static final String ENABLED = "enabled";
    private static final String MATCH_TYPE = "matchType";
    private static final String MATCH_REGEX = "matchRegex";
    private static final String MATCH_STRING = "matchString";
    private static final String REPLACEMENT = "replacement";
    private static final String INITIATORS = "initiators";
    private static final String PARAM_BOOL = "bool";

    private ExtensionReplacer extension = null;

    /** Provided only for API client generator usage. */
    public ReplacerAPI() {
        this(null);
    }

    public ReplacerAPI(ExtensionReplacer ext) {
        extension = ext;

        this.addApiView(new ApiView(VIEW_RULES));

        this.addApiAction(
                new ApiAction(
                        ACTION_ADD_RULE,
                        new String[] {DESC, ENABLED, MATCH_TYPE, MATCH_REGEX, MATCH_STRING},
                        new String[] {REPLACEMENT, INITIATORS}));

        this.addApiAction(new ApiAction(ACTION_REMOVE_RULE, new String[] {DESC}));
        this.addApiAction(new ApiAction(ACTION_SET_ENABLED, new String[] {DESC, PARAM_BOOL}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        if (VIEW_RULES.equals(name)) {
            ApiResponseList rules = new ApiResponseList(name);
            for (ReplacerParamRule rule : extension.getParams().getRules()) {
                rules.addItem(this.ruleToResponse(rule));
            }
            return rules;
        }
        throw new ApiException(ApiException.Type.BAD_VIEW);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        ApiResponse response = ApiResponseElement.OK;
        if (ACTION_SET_ENABLED.equals(name)) {
            if (!extension
                    .getParams()
                    .setEnabled(params.getString(DESC), this.getParam(params, PARAM_BOOL, false))) {
                throw new ApiException(ApiException.Type.DOES_NOT_EXIST, DESC);
            }
            try {
                this.extension.getParams().getConfig().save();
            } catch (ConfigurationException e) {
                throw new ApiException(ApiException.Type.INTERNAL_ERROR);
            }
        } else if (ACTION_ADD_RULE.equals(name)) {
            String desc = params.getString(DESC);
            if (this.extension.getParams().getRule(desc) != null) {
                throw new ApiException(ApiException.Type.ALREADY_EXISTS, DESC);
            }

            MatchType type;
            try {
                type = MatchType.valueOf(params.getString(MATCH_TYPE));
            } catch (IllegalArgumentException e1) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, MATCH_TYPE, e1);
            }
            String matchString = params.getString(MATCH_STRING);
            boolean matchRegex;
            try {
                matchRegex = params.getBoolean(MATCH_REGEX);
            } catch (JSONException e) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, MATCH_REGEX, e);
            }
            if (matchRegex) {
                try {
                    Pattern.compile(matchString);
                } catch (PatternSyntaxException e) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, MATCH_STRING, e);
                }
            }
            List<Integer> initiators = null;
            String initString = this.getParam(params, INITIATORS, "");
            if (initString.length() > 0) {
                initiators = new ArrayList<>();
                try {
                    for (String str : initString.split(",")) {
                        initiators.add(Integer.parseInt(str.trim()));
                    }
                } catch (NumberFormatException e) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, INITIATORS, e);
                }
            }
            boolean enabled;
            try {
                enabled = params.getBoolean(ENABLED);
            } catch (JSONException e) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, ENABLED, e);
            }

            this.extension
                    .getParams()
                    .addRule(
                            new ReplacerParamRule(
                                    desc,
                                    type,
                                    matchString,
                                    matchRegex,
                                    getParam(params, REPLACEMENT, ""),
                                    initiators,
                                    enabled));

            try {
                this.extension.getParams().getConfig().save();
            } catch (ConfigurationException e) {
                throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
            }

        } else if (ACTION_REMOVE_RULE.equals(name)) {
            if (!extension.getParams().removeRule(params.getString(DESC))) {
                throw new ApiException(ApiException.Type.DOES_NOT_EXIST, DESC);
            }
            try {
                this.extension.getParams().getConfig().save();
            } catch (ConfigurationException e) {
                throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
            }
        } else {
            throw new ApiException(ApiException.Type.BAD_ACTION);
        }
        return response;
    }

    private ApiResponse ruleToResponse(ReplacerParamRule rule) {
        Map<String, String> map = new HashMap<>();
        map.put(DESC, rule.getDescription());
        map.put(ENABLED, Boolean.toString(rule.isEnabled()));
        map.put(MATCH_TYPE, rule.getMatchType().name());
        map.put(MATCH_REGEX, Boolean.toString(rule.isMatchRegex()));
        map.put(MATCH_STRING, rule.getMatchString());
        map.put(REPLACEMENT, rule.getReplacement());
        StringBuilder sb = new StringBuilder();
        if (rule.getInitiators() != null) {
            for (Integer init : rule.getInitiators()) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(init);
            }
        }
        map.put(INITIATORS, sb.toString());
        return new ApiResponseSet<>("rule", map);
    }
}
