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

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class GraphQlParam extends VersionedAbstractParam {

    /** The base configuration key for all GraphQL configurations. */
    private static final String PARAM_BASE_KEY = "graphql";

    private static final String PARAM_MAX_QUERY_DEPTH = PARAM_BASE_KEY + ".maxQueryDepth";
    private static final String PARAM_MAX_ARGS_DEPTH = PARAM_BASE_KEY + ".maxArgsDepth";
    private static final String PARAM_OPTIONAL_ARGS = PARAM_BASE_KEY + ".optionalArgs";
    private static final String PARAM_ARGS_TYPE = PARAM_BASE_KEY + ".argsType";
    private static final String PARAM_QUERY_SPLIT_TYPE = PARAM_BASE_KEY + ".querySplitType";
    private static final String PARAM_REQUEST_METHOD = PARAM_BASE_KEY + ".requestMethod";

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    private static final Logger LOG = Logger.getLogger(GraphQlParam.class);

    public GraphQlParam() {}

    /** For unit tests. */
    public GraphQlParam(
            int maxQueryDepth,
            int maxArgsDepth,
            boolean optionalArgsEnabled,
            ArgsTypeOption argsType,
            QuerySplitOption querySplitType,
            RequestMethodOption requestMethod) {
        this.maxQueryDepth = maxQueryDepth;
        this.maxArgsDepth = maxArgsDepth;
        this.optionalArgsEnabled = optionalArgsEnabled;
        this.argsType = argsType;
        this.querySplitType = querySplitType;
        this.requestMethod = requestMethod;
    }

    /** This option is used to specify how field arguments should be included. */
    public enum ArgsTypeOption {
        /** Arguments are added in-line. */
        INLINE,
        /** Arguments are added using variables. */
        VARIABLES,
        /** Each request is sent twice - once with in-line arguments and once using variables. */
        BOTH;

        public String getName() {
            switch (this) {
                case INLINE:
                    return Constant.messages.getString("graphql.options.value.args.inline");
                case VARIABLES:
                    return Constant.messages.getString("graphql.options.value.args.variables");
                case BOTH:
                    return Constant.messages.getString("graphql.options.value.args.both");
                default:
                    return null;
            }
        }
    };

    /** This option is used to specify how the queries should be generated and sent. */
    public enum QuerySplitOption {
        /** A request is sent for each leaf field (scalars or enums). */
        LEAF,
        /** A request is sent for each field immediately under a Root type. */
        ROOT_FIELD,
        /** A single large request is sent. */
        DO_NOT_SPLIT;

        public String getName() {
            switch (this) {
                case LEAF:
                    return Constant.messages.getString("graphql.options.value.split.leaf");
                case ROOT_FIELD:
                    return Constant.messages.getString("graphql.options.value.split.rootField");
                case DO_NOT_SPLIT:
                    return Constant.messages.getString("graphql.options.value.split.doNotSplit");
                default:
                    return null;
            }
        }
    };

    /** This option is used to specify how the requests should be made. */
    public enum RequestMethodOption {
        /** The method is POST and the Content-type is application/json. */
        POST_JSON,
        /** The method is POST and the Content-type is application/graphql. */
        POST_GRAPHQL,
        /**
         * The method is GET and the the query is appended to the endpoint URL in a query string.
         */
        GET;

        public String getName() {
            switch (this) {
                case POST_JSON:
                    return Constant.messages.getString("graphql.options.value.request.postJson");
                case POST_GRAPHQL:
                    return Constant.messages.getString("graphql.options.value.split.postGraphql");
                case GET:
                    return Constant.messages.getString("graphql.options.value.split.get");
                default:
                    return null;
            }
        }
    };

    private int maxQueryDepth;
    private int maxArgsDepth;
    private boolean optionalArgsEnabled;
    private ArgsTypeOption argsType;
    private QuerySplitOption querySplitType;
    private RequestMethodOption requestMethod;

    public int getMaxQueryDepth() {
        return maxQueryDepth;
    }

    public void setMaxQueryDepth(int maxQueryDepth) {
        this.maxQueryDepth = maxQueryDepth;
        getConfig().setProperty(PARAM_MAX_QUERY_DEPTH, maxQueryDepth);
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

    public ArgsTypeOption getArgsType() {
        return argsType;
    }

    public void setArgsType(ArgsTypeOption argsType) {
        this.argsType = argsType;
        getConfig().setProperty(PARAM_ARGS_TYPE, argsType.toString());
    }

    public QuerySplitOption getQuerySplitType() {
        return querySplitType;
    }

    public void setSplitQueryType(QuerySplitOption querySplitType) {
        this.querySplitType = querySplitType;
        getConfig().setProperty(PARAM_QUERY_SPLIT_TYPE, querySplitType.toString());
    }

    public RequestMethodOption getRequestMethod() {
        return requestMethod;
    }

    public void setRequestMethod(RequestMethodOption requestMethod) {
        this.requestMethod = requestMethod;
        getConfig().setProperty(PARAM_REQUEST_METHOD, requestMethod.toString());
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
        maxQueryDepth = getInt(PARAM_MAX_QUERY_DEPTH, 5);
        maxArgsDepth = getInt(PARAM_MAX_ARGS_DEPTH, 5);
        optionalArgsEnabled = getBoolean(PARAM_OPTIONAL_ARGS, false);
        argsType =
                ArgsTypeOption.valueOf(getString(PARAM_ARGS_TYPE, ArgsTypeOption.BOTH.toString()));
        querySplitType =
                QuerySplitOption.valueOf(
                        getString(PARAM_QUERY_SPLIT_TYPE, QuerySplitOption.LEAF.toString()));
        requestMethod =
                RequestMethodOption.valueOf(
                        getString(PARAM_REQUEST_METHOD, RequestMethodOption.POST_JSON.toString()));
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}
}
