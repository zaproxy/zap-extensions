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
package org.zaproxy.addon.graphql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.zaproxy.addon.graphql.GraphQlParam.ArgsTypeOption;
import org.zaproxy.addon.graphql.GraphQlParam.QuerySplitOption;
import org.zaproxy.addon.graphql.GraphQlParam.RequestMethodOption;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link GraphQlParam}. */
class GraphQlParamUnitTest {

    private static final String PARAM_ARGS_TYPE = "graphql.argsType";
    private static final String PARAM_QUERY_SPLIT_TYPE = "graphql.querySplitType";
    private static final String PARAM_REQUEST_METHOD = "graphql.requestMethod";

    private ZapXmlConfiguration config;
    private GraphQlParam options;

    @BeforeEach
    void setUp() {
        options = new GraphQlParam();
        config = new ZapXmlConfiguration();
        options.load(config);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(options.getConfigVersionKey(), is(equalTo("graphql[@version]")));
    }

    @ParameterizedTest
    @EnumSource(ArgsTypeOption.class)
    void shouldLoadConfigWithArgsTypeOption(ArgsTypeOption value) {
        // Given
        options = new GraphQlParam();
        config.setProperty(PARAM_ARGS_TYPE, value.toString());
        // When
        options.load(config);
        // Then
        assertThat(options.getArgsType(), is(equalTo(value)));
    }

    @Test
    void shouldUseDefaultWithInvalidArgsTypeOption() {
        // Given
        options = new GraphQlParam();
        config.setProperty(PARAM_ARGS_TYPE, "Not Valid");
        // When
        options.load(config);
        // Then
        assertThat(options.getArgsType(), is(equalTo(ArgsTypeOption.BOTH)));
    }

    @ParameterizedTest
    @EnumSource(QuerySplitOption.class)
    void shouldLoadConfigWithQuerySplitOption(QuerySplitOption value) {
        // Given
        options = new GraphQlParam();
        config.setProperty(PARAM_QUERY_SPLIT_TYPE, value.toString());
        // When
        options.load(config);
        // Then
        assertThat(options.getQuerySplitType(), is(equalTo(value)));
    }

    @Test
    void shouldUseDefaultWithInvalidQuerySplitOption() {
        // Given
        options = new GraphQlParam();
        config.setProperty(PARAM_QUERY_SPLIT_TYPE, "Not Valid");
        // When
        options.load(config);
        // Then
        assertThat(options.getQuerySplitType(), is(equalTo(QuerySplitOption.LEAF)));
    }

    @ParameterizedTest
    @EnumSource(RequestMethodOption.class)
    void shouldLoadConfigWithRequestMethodOption(RequestMethodOption value) {
        // Given
        options = new GraphQlParam();
        config.setProperty(PARAM_REQUEST_METHOD, value.toString());
        // When
        options.load(config);
        // Then
        assertThat(options.getRequestMethod(), is(equalTo(value)));
    }

    @Test
    void shouldUseDefaultWithInvalidRequestMethodOption() {
        // Given
        options = new GraphQlParam();
        config.setProperty(PARAM_REQUEST_METHOD, "Not Valid");
        // When
        options.load(config);
        // Then
        assertThat(options.getRequestMethod(), is(equalTo(RequestMethodOption.POST_JSON)));
    }
}
