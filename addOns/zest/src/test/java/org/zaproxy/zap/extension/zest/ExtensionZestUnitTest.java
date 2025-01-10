/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionZest}. */
class ExtensionZestUnitTest {

    private ExtensionZest extension;

    @BeforeEach
    void setup() {
        extension = new ExtensionZest();
    }

    @Test
    void shouldHandleScriptAddedWithNoEngineName() {
        // Given
        ScriptWrapper sw = mock(ScriptWrapper.class);
        given(sw.getEngineName()).willReturn(null);
        // When/ Then
        assertDoesNotThrow(() -> extension.scriptAdded(sw, false));
    }

    @Nested
    class ScriptCreation {

        private String name;
        private ScriptType type;
        private CreateScriptOptions options;
        private ExtensionScript extensionScript;

        @BeforeEach
        void setup() {
            name = "Script Name";
            type = mock(ScriptType.class);
            options = mock(CreateScriptOptions.class);
            includeResponsesAs(CreateScriptOptions.IncludeResponses.GLOBAL_OPTION);
            extensionScript = mock(ExtensionScript.class);

            var extLoader = mock(ExtensionLoader.class);
            Control.initSingletonForTesting(mock(Model.class), extLoader);

            given(extLoader.getExtension(ExtensionScript.NAME)).willReturn(extensionScript);
            given(extLoader.getExtension(ExtensionZest.NAME)).willReturn(extension);
        }

        private void includeResponsesAs(CreateScriptOptions.IncludeResponses value) {
            given(options.getIncludeResponses()).willReturn(value);
        }

        @ParameterizedTest
        @NullAndEmptySource
        void shouldThrowForNullAndEmptyMessages(List<HttpMessage> messages) {
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> extension.createScript(name, type, messages, options));
            assertThat(e.getMessage(), is(equalTo("The messages should not be null nor empty.")));
        }

        @Test
        void shouldThrowForNullMessage() {
            // Given
            List<HttpMessage> messages = new ArrayList<>();
            messages.add(null);
            // When / Then
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> extension.createScript(name, type, messages, options));
            assertThat(e.getMessage(), is(equalTo("A message should not be null.")));
        }

        @Test
        void shouldThrowForMessageWithoutUri() {
            // Given
            List<HttpMessage> messages = new ArrayList<>();
            messages.add(new HttpMessage());
            // When / Then
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> extension.createScript(name, type, messages, options));
            assertThat(
                    e.getMessage(),
                    is(
                            equalTo(
                                    "Failed to convert message to ZestRequest: The request header does not have a URI.")));
        }

        @Test
        void shouldAddScript() throws Exception {
            // Given
            List<HttpMessage> messages = new ArrayList<>();
            messages.add(new HttpMessage(new URI("http://example.com", true)));
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(
                    sw.getContents(),
                    allOf(
                            containsString("\"url\": \"http://example.com\","),
                            containsString("\"elementType\": \"ZestRequest\""),
                            not(containsString("ZestExpressionStatusCode")),
                            not(containsString("ZestExpressionLength"))));
            var argCaptor = ArgumentCaptor.forClass(ScriptWrapper.class);
            verify(extensionScript).addScript(argCaptor.capture(), eq(false));
            assertThat(sw, is(sameInstance(argCaptor.getValue())));
            assertThat(sw.getName(), is(equalTo(name)));
            assertThat(sw.getType(), is(sameInstance(type)));
            assertThat(sw.getEngine(), is(sameInstance(extension.getZestEngineWrapper())));
        }

        @Test
        void shouldAddStatusAssertion() throws Exception {
            // Given
            List<HttpMessage> messages = new ArrayList<>();
            messages.add(new HttpMessage(new URI("http://example.com", true)));
            given(options.isAddStatusAssertion()).willReturn(true);
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(
                    sw.getContents(),
                    allOf(
                            containsString("ZestExpressionStatusCode"),
                            not(containsString("ZestExpressionLength"))));
        }

        @Test
        void shouldAddLengthAssertion() throws Exception {
            // Given
            List<HttpMessage> messages = new ArrayList<>();
            messages.add(new HttpMessage(new URI("http://example.com", true)));
            given(options.isAddLengthAssertion()).willReturn(true);
            given(options.getLengthApprox()).willReturn(42);
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(
                    sw.getContents(),
                    allOf(
                            not(containsString("ZestExpressionStatusCode")),
                            containsString("ZestExpressionLength"),
                            containsString("\"approx\": 42,")));
        }

        @Test
        void shouldThrowIfAddScriptThrows() throws Exception {
            // Given
            List<HttpMessage> messages = new ArrayList<>();
            messages.add(new HttpMessage(new URI("http://example.com", true)));
            Exception cause = new InvalidParameterException("Some Reason");
            given(extensionScript.addScript(any(), anyBoolean())).willThrow(cause);
            // When / Then
            IllegalStateException e =
                    assertThrows(
                            IllegalStateException.class,
                            () -> extension.createScript(name, type, messages, options));
            assertThat(e.getMessage(), is(equalTo("Failed to add the script: Some Reason")));
            assertThat(e.getCause(), is(sameInstance(cause)));
        }

        @Test
        void shouldIncludeResponsesWithIncludeResponsesAlways() throws Exception {
            // Given
            includeResponsesAs(CreateScriptOptions.IncludeResponses.ALWAYS);
            List<HttpMessage> messages = List.of(messageWithResponse());
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(sw.getContents(), containsString("HTTP/1.1 200 OK"));
        }

        @Test
        void shouldNotIncludeResponsesWithIncludeResponsesNever() throws Exception {
            // Given
            includeResponsesAs(CreateScriptOptions.IncludeResponses.NEVER);
            List<HttpMessage> messages = List.of(messageWithResponse());
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(sw.getContents(), not(containsString("HTTP/1.1 200 OK")));
        }

        @Test
        void shouldIncludeResponsesWithIncludeResponsesGlobalOptionIfGlobalIncludes()
                throws Exception {
            // Given
            includeResponsesAs(CreateScriptOptions.IncludeResponses.GLOBAL_OPTION);
            globalOptionIncludeResponsesAs(true);
            List<HttpMessage> messages = List.of(messageWithResponse());
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(sw.getContents(), containsString("HTTP/1.1 200 OK"));
        }

        @Test
        void shouldNotIncludeResponsesWithIncludeResponsesGlobalOptionIfGlobalDoesNotInclude()
                throws Exception {
            // Given
            includeResponsesAs(CreateScriptOptions.IncludeResponses.GLOBAL_OPTION);
            globalOptionIncludeResponsesAs(false);
            List<HttpMessage> messages = List.of(messageWithResponse());
            // When
            var sw = extension.createScript(name, type, messages, options);
            // Then
            assertThat(sw.getContents(), not(containsString("HTTP/1.1 200 OK")));
        }

        private HttpMessage messageWithResponse()
                throws HttpMalformedHeaderException, URIException {
            HttpMessage msg = new HttpMessage(new URI("http://example.com", true));
            msg.setResponseHeader("HTTP/1.1 200 OK");
            return msg;
        }

        private void globalOptionIncludeResponsesAs(boolean value) {
            extension.getParam().load(new ZapXmlConfiguration());
            extension.getParam().setIncludeResponses(value);
        }
    }
}
