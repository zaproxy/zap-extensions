/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class GraphQlParam extends VersionedAbstractParam {

    /** The base configuration key for all GraphQL configurations. */
    private static final String PARAM_BASE_KEY = "graphql";

    private static final String PARAM_QUERY_GENERATOR_ENABLED = PARAM_BASE_KEY + ".queryGenEnabled";
    private static final String PARAM_MAX_QUERY_DEPTH = PARAM_BASE_KEY + ".maxQueryDepth";
    private static final String PARAM_LENIENT_MAX_QUERY_DEPTH =
            PARAM_BASE_KEY + ".lenientMaxQueryDepth";
    private static final String PARAM_MAX_ADDITIONAL_QUERY_DEPTH =
            PARAM_BASE_KEY + ".maxAdditionalQueryDepth";
    private static final String PARAM_MAX_ARGS_DEPTH = PARAM_BASE_KEY + ".maxArgsDepth";
    private static final String PARAM_OPTIONAL_ARGS = PARAM_BASE_KEY + ".optionalArgs";
    private static final String PARAM_ARGS_TYPE = PARAM_BASE_KEY + ".argsType";
    private static final String PARAM_QUERY_SPLIT_TYPE = PARAM_BASE_KEY + ".querySplitType";
    private static final String PARAM_REQUEST_METHOD = PARAM_BASE_KEY + ".requestMethod";
    private static final String PARAM_CYCLE_DETECTION_MODE = PARAM_BASE_KEY + ".cycleDetectionMode";
    private static final String PARAM_CYCLE_DETECTION_MAX_ALERTS =
            PARAM_BASE_KEY + ".cycleDetectionMaxAlerts";

    public static final boolean DEFAULT_QUERY_GEN_ENABLED = true;
    public static final int DEFAULT_MAX_QUERY_DEPTH = 5;
    public static final boolean DEFAULT_LENIENT_MAX_QUERY_DEPTH = true;
    public static final int DEFAULT_MAX_ADDITIONAL_QUERY_DEPTH = 5;
    public static final int DEFAULT_MAX_ARGS_DEPTH = 5;
    public static final boolean DEFAULT_OPTIONAL_ARGS = true;
    public static final ArgsTypeOption DEFAULT_ARGS_TYPE = ArgsTypeOption.BOTH;
    public static final QuerySplitOption DEFAULT_QUERY_SPLIT_TYPE = QuerySplitOption.LEAF;
    public static final RequestMethodOption DEFAULT_REQUEST_METHOD = RequestMethodOption.POST_JSON;
    public static final CycleDetectionModeOption DEFAULT_CYCLE_DETECTION_MODE =
            CycleDetectionModeOption.QUICK;
    public static final int DEFAULT_MAX_CYCLE_DETECTION_ALERTS = 100;

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     */
    private static final int PARAM_CURRENT_VERSION = 2;

    private static final Logger LOGGER = LogManager.getLogger(GraphQlParam.class);

    public GraphQlParam() {}

    /** For unit tests. */
    public GraphQlParam(
            boolean queryGenEnabled,
            int maxQueryDepth,
            boolean lenientMaxQueryDepthEnabled,
            int maxAdditionalQueryDepth,
            int maxArgsDepth,
            boolean optionalArgsEnabled,
            ArgsTypeOption argsType,
            QuerySplitOption querySplitType,
            RequestMethodOption requestMethod,
            CycleDetectionModeOption cycleDetectionMode,
            int maxCycleDetectionAlerts) {
        this.queryGenEnabled = queryGenEnabled;
        this.maxQueryDepth = maxQueryDepth;
        this.lenientMaxQueryDepthEnabled = lenientMaxQueryDepthEnabled;
        this.maxAdditionalQueryDepth = maxAdditionalQueryDepth;
        this.maxArgsDepth = maxArgsDepth;
        this.optionalArgsEnabled = optionalArgsEnabled;
        this.argsType = argsType;
        this.querySplitType = querySplitType;
        this.requestMethod = requestMethod;
        this.cycleDetectionMode = cycleDetectionMode;
        this.maxCycleDetectionAlerts = maxCycleDetectionAlerts;
    }

    /** This option is used to specify how field arguments should be included. */
    public enum ArgsTypeOption {
        /** Arguments are added in-line. */
        INLINE,
        /** Arguments are added using variables. */
        VARIABLES,
        /** Each request is sent twice - once with in-line arguments and once using variables. */
        BOTH;

        @Override
        public String toString() {
            return switch (this) {
                case INLINE -> Constant.messages.getString("graphql.options.value.args.inline");
                case VARIABLES ->
                        Constant.messages.getString("graphql.options.value.args.variables");
                case BOTH -> Constant.messages.getString("graphql.options.value.args.both");
            };
        }
    };

    /** This option is used to specify how the queries should be generated and sent. */
    public enum QuerySplitOption {
        /** A request is sent for each leaf field (scalars or enums). */
        LEAF,
        /** A request is sent for each field immediately under a Root type. */
        ROOT_FIELD,
        /** A single large request is sent. */
        OPERATION;

        @Override
        public String toString() {
            return switch (this) {
                case LEAF -> Constant.messages.getString("graphql.options.value.split.leaf");
                case ROOT_FIELD ->
                        Constant.messages.getString("graphql.options.value.split.rootField");
                case OPERATION ->
                        Constant.messages.getString("graphql.options.value.split.operation");
            };
        }
    };

    /** This option is used to specify how the requests should be made. */
    public enum RequestMethodOption {
        /** The method is POST and the Content-type is application/json. */
        POST_JSON,
        /** The method is POST and the Content-type is application/graphql. */
        POST_GRAPHQL,
        /** The method is GET and the query is appended to the endpoint URL in a query string. */
        GET;

        @Override
        public String toString() {
            return switch (this) {
                case POST_JSON ->
                        Constant.messages.getString("graphql.options.value.request.postJson");
                case POST_GRAPHQL ->
                        Constant.messages.getString("graphql.options.value.split.postGraphql");
                case GET -> Constant.messages.getString("graphql.options.value.split.get");
            };
        }
    }

    public enum CycleDetectionModeOption {
        DISABLED,
        QUICK,
        EXHAUSTIVE;

        @Override
        public String toString() {
            return switch (this) {
                case DISABLED ->
                        Constant.messages.getString(
                                "graphql.options.value.cycleDetection.disabled");
                case QUICK ->
                        Constant.messages.getString("graphql.options.value.cycleDetection.quick");
                case EXHAUSTIVE ->
                        Constant.messages.getString(
                                "graphql.options.value.cycleDetection.exhaustive");
            };
        }
    }

    private boolean queryGenEnabled;
    private int maxQueryDepth;
    private boolean lenientMaxQueryDepthEnabled;
    private int maxAdditionalQueryDepth;
    private int maxArgsDepth;
    private boolean optionalArgsEnabled;
    private ArgsTypeOption argsType;
    private QuerySplitOption querySplitType;
    private RequestMethodOption requestMethod;
    private CycleDetectionModeOption cycleDetectionMode;
    private int maxCycleDetectionAlerts;

    public int getMaxQueryDepth() {
        return maxQueryDepth;
    }

    public void setMaxQueryDepth(int maxQueryDepth) {
        this.maxQueryDepth = maxQueryDepth;
        getConfig().setProperty(PARAM_MAX_QUERY_DEPTH, maxQueryDepth);
    }

    public boolean getLenientMaxQueryDepthEnabled() {
        return lenientMaxQueryDepthEnabled;
    }

    public void setLenientMaxQueryDepthEnabled(boolean lenientMaxQueryDepthEnabled) {
        this.lenientMaxQueryDepthEnabled = lenientMaxQueryDepthEnabled;
        getConfig().setProperty(PARAM_LENIENT_MAX_QUERY_DEPTH, lenientMaxQueryDepthEnabled);
    }

    public int getMaxAdditionalQueryDepth() {
        return maxAdditionalQueryDepth;
    }

    public void setMaxAdditionalQueryDepth(int maxAdditionalQueryDepth) {
        this.maxAdditionalQueryDepth = maxAdditionalQueryDepth;
        getConfig().setProperty(PARAM_MAX_ADDITIONAL_QUERY_DEPTH, maxAdditionalQueryDepth);
    }

    public int getMaxArgsDepth() {
        return maxArgsDepth;
    }

    public void setMaxArgsDepth(int maxArgsDepth) {
        this.maxArgsDepth = maxArgsDepth;
        getConfig().setProperty(PARAM_MAX_ARGS_DEPTH, maxArgsDepth);
    }

    public boolean getOptionalArgsEnabled() {
        return optionalArgsEnabled;
    }

    public void setOptionalArgsEnabled(boolean optionalArgsEnabled) {
        this.optionalArgsEnabled = optionalArgsEnabled;
        getConfig().setProperty(PARAM_OPTIONAL_ARGS, optionalArgsEnabled);
    }

    @ZapApiIgnore
    public ArgsTypeOption getArgsType() {
        return argsType;
    }

    // For generating an API action.
    public void setArgsType(String argsType) throws ApiException {
        try {
            setArgsType(ArgsTypeOption.valueOf(argsType.toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            LOGGER.debug("'{}' is not a valid Arguments Specification Type.", argsType);
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }

    public void setArgsType(ArgsTypeOption argsType) {
        this.argsType = argsType;
        getConfig().setProperty(PARAM_ARGS_TYPE, argsType.name());
    }

    @ZapApiIgnore
    public QuerySplitOption getQuerySplitType() {
        return querySplitType;
    }

    // For generating an API action.
    public void setQuerySplitType(String querySplitType) throws ApiException {
        try {
            setQuerySplitType(QuerySplitOption.valueOf(querySplitType.toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            LOGGER.debug("'{}' is not a valid Query Split Type.", querySplitType);
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }

    public void setQuerySplitType(QuerySplitOption querySplitType) {
        this.querySplitType = querySplitType;
        getConfig().setProperty(PARAM_QUERY_SPLIT_TYPE, querySplitType.name());
    }

    @ZapApiIgnore
    public RequestMethodOption getRequestMethod() {
        return requestMethod;
    }

    // For generating an API action.
    public void setRequestMethod(String requestMethod) throws ApiException {
        try {
            setRequestMethod(RequestMethodOption.valueOf(requestMethod.toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            LOGGER.debug("'{}' is not a valid Request Method Option.", requestMethod);
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }

    public void setRequestMethod(RequestMethodOption requestMethod) {
        this.requestMethod = requestMethod;
        getConfig().setProperty(PARAM_REQUEST_METHOD, requestMethod.name());
    }

    public boolean getQueryGenEnabled() {
        return queryGenEnabled;
    }

    public void setQueryGenEnabled(boolean queryGenEnabled) {
        this.queryGenEnabled = queryGenEnabled;
        getConfig().setProperty(PARAM_QUERY_GENERATOR_ENABLED, queryGenEnabled);
    }

    @ZapApiIgnore
    public CycleDetectionModeOption getCycleDetectionMode() {
        return cycleDetectionMode;
    }

    public void setCycleDetectionMode(CycleDetectionModeOption cycleDetectionMode) {
        this.cycleDetectionMode = cycleDetectionMode;
        getConfig().setProperty(PARAM_CYCLE_DETECTION_MODE, cycleDetectionMode.name());
    }

    // For generating an API action.
    public void setCycleDetectionMode(String cycleDetectionMode) throws ApiException {
        try {
            setCycleDetectionMode(
                    CycleDetectionModeOption.valueOf(cycleDetectionMode.toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            LOGGER.debug("'{}' is not a valid Cycle Detection Mode.", cycleDetectionMode);
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }

    public int getMaxCycleDetectionAlerts() {
        return maxCycleDetectionAlerts;
    }

    public void setMaxCycleDetectionAlerts(int maxCycleDetectionAlerts) {
        this.maxCycleDetectionAlerts = maxCycleDetectionAlerts;
        getConfig().setProperty(PARAM_CYCLE_DETECTION_MAX_ALERTS, maxCycleDetectionAlerts);
    }

    @Override
    protected String getConfigVersionKey() {
        return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void parseImpl() {
        queryGenEnabled = getBoolean(PARAM_QUERY_GENERATOR_ENABLED, DEFAULT_QUERY_GEN_ENABLED);
        maxQueryDepth = getInt(PARAM_MAX_QUERY_DEPTH, DEFAULT_MAX_QUERY_DEPTH);
        lenientMaxQueryDepthEnabled =
                getBoolean(PARAM_LENIENT_MAX_QUERY_DEPTH, DEFAULT_LENIENT_MAX_QUERY_DEPTH);
        maxAdditionalQueryDepth =
                getInt(PARAM_MAX_ADDITIONAL_QUERY_DEPTH, DEFAULT_MAX_ADDITIONAL_QUERY_DEPTH);
        maxArgsDepth = getInt(PARAM_MAX_ARGS_DEPTH, DEFAULT_MAX_ARGS_DEPTH);
        optionalArgsEnabled = getBoolean(PARAM_OPTIONAL_ARGS, DEFAULT_OPTIONAL_ARGS);
        argsType = getEnum(PARAM_ARGS_TYPE, DEFAULT_ARGS_TYPE);
        querySplitType = getEnum(PARAM_QUERY_SPLIT_TYPE, DEFAULT_QUERY_SPLIT_TYPE);
        requestMethod = getEnum(PARAM_REQUEST_METHOD, DEFAULT_REQUEST_METHOD);
        cycleDetectionMode = getEnum(PARAM_CYCLE_DETECTION_MODE, DEFAULT_CYCLE_DETECTION_MODE);
        maxCycleDetectionAlerts =
                getInt(PARAM_CYCLE_DETECTION_MAX_ALERTS, DEFAULT_MAX_CYCLE_DETECTION_ALERTS);
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}
}
