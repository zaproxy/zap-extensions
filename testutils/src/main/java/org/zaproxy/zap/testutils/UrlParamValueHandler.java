/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.testutils;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;

import fi.iki.elonen.NanoHTTPD;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.collections.MapUtils;

/**
 * Simplifies simulation of server responses for use cases, where the attack is based on an URL
 * parameter value.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * nano.addHandler(UrlParamValueHandler.builder()
 *             .targetParam("topic")
 *             .whenParamValueIs("cats' --").thenReturnHtml("A, B")
 *             .whenParamValueIs("cats' AND '1'='1' --").thenReturnHtml("A, B")
 *             .whenParamValueIs("cats' AND '1'='2' --").thenReturnHtml("")
 *             .build()
 *     );
 * }</pre>
 *
 * <p>If not overridden by corresponding builder functions, the following defaults apply:
 *
 * <ul>
 *   <li>Handler "listens" for "/" URL path
 *   <li>Handler returns an empty default response for all non-specified parameter values
 * </ul>
 */
public class UrlParamValueHandler extends NanoServerHandler {
    private static final String DEFAULT_RESPONSE = "";
    private final String targetParam;
    private final Map<String, String> paramValueToResponseMap;
    private final String fallbackResponse;
    private final List<String> actualParamValues;

    private UrlParamValueHandler(
            String targetPath,
            String targetParam,
            Map<String, String> paramValueToResponseMap,
            String fallbackResponse) {
        super(targetPath);
        this.targetParam = targetParam;
        this.paramValueToResponseMap = paramValueToResponseMap;
        this.fallbackResponse = fallbackResponse;
        this.actualParamValues = new ArrayList<>();
    }

    @Override
    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
        String actualParamValue = getFirstParamValue(session, targetParam);
        actualParamValues.add(actualParamValue);

        // safe cast, since both paramValueToResponseMap-values and fallbackResponse are of type
        // String
        String targetBody =
                (String)
                        MapUtils.getObject(
                                paramValueToResponseMap, actualParamValue, fallbackResponse);
        return newFixedLengthResponse(targetBody);
    }

    /**
     * Creates a builder for creating a {@link UrlParamValueHandler}
     *
     * @return a new Builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Gets all parameter values which have been processed by this handler
     *
     * @return a list of all actual parameter values
     */
    public List<String> getActualParamValues() {
        return new ArrayList<>(actualParamValues);
    }

    /**
     * Gets all parameter values for which a response have been prepared by calling {@link
     * Builder#whenParamValueIs(String)}
     *
     * @return a set of all expected parameter values
     */
    public Set<String> getExpectedParamValues() {
        return paramValueToResponseMap.keySet();
    }

    public static class Builder {
        private final String targetPath;

        private final String targetParam;

        private final Map<String, String> paramValueToResponseMap;

        private final String fallbackResponse;

        private Builder() {
            this("/", null, new HashMap<>(), DEFAULT_RESPONSE);
        }

        private Builder(
                String targetPath,
                String targetParam,
                Map<String, String> paramValueToResponseMap,
                String fallbackResponse) {
            this.targetPath = targetPath;
            this.targetParam = targetParam;
            this.paramValueToResponseMap = paramValueToResponseMap;
            this.fallbackResponse = fallbackResponse;
        }

        /**
         * Overrides the default URL path for which the created handler is to return responses
         * (default: "/").
         *
         * @param targetPath the URL path
         * @return a Builder
         */
        public Builder targetPath(String targetPath) {
            Objects.requireNonNull(targetPath, "targetPath must not be null");
            return new Builder(
                    targetPath,
                    this.targetParam,
                    this.paramValueToResponseMap,
                    this.fallbackResponse);
        }

        /**
         * Sets the name of the param which will hold the attack payload.
         *
         * @param targetParam the param name
         * @return a Builder
         */
        public Builder targetParam(String targetParam) {
            Objects.requireNonNull(targetParam, "targetParam must not be null");
            return new Builder(
                    this.targetPath,
                    targetParam,
                    this.paramValueToResponseMap,
                    this.fallbackResponse);
        }

        /**
         * Defines a parameter value for which a specific response should be returned.
         *
         * @param paramValue the param value
         * @return a ResponseBuilder for building the actual response
         */
        public ResponseBuilder whenParamValueIs(String paramValue) {
            Objects.requireNonNull(paramValue, "paramValue must not be null");
            return new ResponseBuilder(this, paramValue);
        }

        /**
         * Overrides the default content of the fallback response message which is returned for all
         * parameter values which are not specified via {@link #whenParamValueIs(String)} (default:
         * "").
         *
         * @param content the content in fallback response
         * @return a Builder
         */
        public Builder fallbackHtmlResponse(String content) {
            Objects.requireNonNull(content, "content must not be null");
            return new Builder(
                    this.targetPath, this.targetParam, this.paramValueToResponseMap, content);
        }

        /**
         * Creates a {@link UrlParamValueHandler}
         *
         * @return an new handler
         */
        public UrlParamValueHandler build() {
            Objects.requireNonNull(
                    targetParam, "you must specify a targetParam by calling #targetParam()");
            return new UrlParamValueHandler(
                    targetPath, targetParam, paramValueToResponseMap, fallbackResponse);
        }
    }

    public static class ResponseBuilder {
        private final Builder builder;

        private final String paramValue;

        private ResponseBuilder(Builder builder, String paramValue) {
            this.builder = builder;
            this.paramValue = paramValue;
        }

        /**
         * Sets the content of the response to be returned for the parameter value specified in
         * previous {@link Builder#whenParamValueIs(String)}.
         *
         * <p>The response to be returned will have HTTP status OK and MIME type "text/html"
         *
         * @param htmlContent the content in response
         * @return a Builder
         * @see NanoHTTPD#newFixedLengthResponse(String)
         */
        public Builder thenReturnHtml(String htmlContent) {
            Map<String, String> newResponseMap = new HashMap<>(builder.paramValueToResponseMap);
            newResponseMap.put(paramValue, htmlContent);

            return new Builder(
                    builder.targetPath,
                    builder.targetParam,
                    newResponseMap,
                    builder.fallbackResponse);
        }
    }
}
