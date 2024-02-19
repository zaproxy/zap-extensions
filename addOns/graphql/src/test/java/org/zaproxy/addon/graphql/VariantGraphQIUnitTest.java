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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.filter.BurstFilter;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

class VariantGraphQlUnitTest {
    private VariantGraphQl variant;
    private static List<String> logMessages;

    private static final String APPENDER_NAME = "ZAP-TestAppender";
    private static Level originalLevel;

    @BeforeAll
    static void initAppender() {
        LoggerConfig rootLogger = LoggerContext.getContext().getConfiguration().getRootLogger();
        rootLogger.addAppender(new TestAppender(VariantGraphQlUnitTest::handleError), null, null);
        originalLevel = rootLogger.getLevel();
        Configurator.setRootLevel(Level.ALL);
    }

    @AfterAll
    static void removeAppender() {
        LoggerContext.getContext().getConfiguration().getRootLogger().removeAppender(APPENDER_NAME);
        Configurator.setRootLevel(originalLevel);
    }

    @BeforeEach
    void setup() {
        variant = new VariantGraphQl();
        logMessages = new ArrayList<>();
    }

    @Test
    void shouldFailToExtractParametersFromNullMessage() {
        // Given
        HttpMessage msg = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> variant.setMessage(msg));
    }

    @Test
    void shouldNotExtractParametersForPostIfBodyIsEmptyAndNoContentTypeIsSet()
            throws HttpMalformedHeaderException {
        // Given
        HttpRequestHeader httpReqHeader = new HttpRequestHeader();
        httpReqHeader.setMessage("POST /abc/xyz HTTP/1.1");
        HttpMessage msg = new HttpMessage(httpReqHeader);
        // When
        variant.setMessage(msg);
        // Then
        assertThat(variant.getParamList(), is(empty()));
    }

    @Test
    void shouldNotLogErrorsOnJsonArray() throws HttpMalformedHeaderException {
        // Given
        HttpRequestHeader httpReqHeader = new HttpRequestHeader();
        httpReqHeader.setMessage("POST /abc/xyz HTTP/1.1");
        httpReqHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
        HttpMessage msg = new HttpMessage(httpReqHeader);
        msg.getRequestBody().setBody("[]");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

        // When
        variant.setMessage(msg);
        // Then
        assertThat(logMessages, is(empty()));
    }

    @Test
    void shouldLogWarnOnInvalidJson() throws HttpMalformedHeaderException {
        // Given
        HttpRequestHeader httpReqHeader = new HttpRequestHeader();
        httpReqHeader.setMessage("POST /abc/xyz HTTP/1.1");
        httpReqHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");
        HttpMessage msg = new HttpMessage(httpReqHeader);
        msg.getRequestBody().setBody("{[");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

        // When
        variant.setMessage(msg);
        // Then
        assertThat(logMessages.size(), is(1));
    }

    @Test
    void shouldSetGraphqlQueryParametersCorrectlyOnTheUrl()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpRequestHeader httpReqHeader = new HttpRequestHeader();
        httpReqHeader.setMessage(
                "GET /graphql/?x=1&query=%7BsqlInjection(expression:%20%221%22)%7D&y=2 HTTP/1.1");
        HttpMessage msg = new HttpMessage(httpReqHeader);

        // When
        variant.setMessage(msg);
        NameValuePair param = variant.getParamList().get(0);
        String sqliPayload = "\"or 1=1--";
        variant.setParameter(msg, param, param.getName(), sqliPayload);
        // Then
        assertThat(
                msg.getRequestHeader()
                        .getURI()
                        .getQuery()
                        .contains("query={sqlInjection(expression:\"\\\"or 1=1--\")}"),
                is(true));
    }

    private static void handleError(String message) {
        logMessages.add(message);
    }

    static class TestAppender extends AbstractAppender {

        private static final Property[] NO_PROPERTIES = {};

        private final Consumer<String> logConsumer;

        TestAppender(Consumer<String> logConsumer) {
            super(
                    APPENDER_NAME,
                    BurstFilter.newBuilder().setMaxBurst(100).setLevel(Level.WARN).build(),
                    PatternLayout.newBuilder()
                            .withDisableAnsi(true)
                            .withCharset(StandardCharsets.UTF_8)
                            .withPattern("%m%n")
                            .build(),
                    true,
                    NO_PROPERTIES);
            this.logConsumer = logConsumer;
            start();
        }

        @Override
        public void append(LogEvent event) {
            logConsumer.accept(((StringLayout) getLayout()).toSerializable(event));
        }
    }
}
