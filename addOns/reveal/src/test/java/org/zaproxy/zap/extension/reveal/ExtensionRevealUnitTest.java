/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.reveal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Locale;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link ExtensionReveal}. */
class ExtensionRevealUnitTest {

    private static final String DEFAULT_BODY =
            "<html><head></head><body><H1>Some Heading</H1></body></html>";
    private ExtensionReveal extension;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extension = new ExtensionReveal();
        extension.init();
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldAddProxyListenerAndApiImplementorOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<ExtensionReveal> plArg = ArgumentCaptor.forClass(ExtensionReveal.class);
        verify(extensionHook).addProxyListener(plArg.capture());
        assertThat(plArg.getValue(), is(notNullValue()));

        ArgumentCaptor<RevealAPI> apiArg = ArgumentCaptor.forClass(RevealAPI.class);
        verify(extensionHook).addApiImplementor(apiArg.capture());
        assertThat(apiArg.getValue(), is(notNullValue()));
    }

    @Test
    void shouldBeUnloadable() {
        // Given / When
        boolean canUnload = extension.canUnload();
        // Then
        assertThat(canUnload, is(equalTo(true)));
    }

    @Test
    void shouldHaveSameContentLengthOnUnmodifiedMessage() {
        // Given
        HttpMessage msg = createMessage();
        // When
        extension.revealFields(msg);
        // Then
        assertThat(msg.getResponseBody().length(), is(equalTo(60)));
    }

    @ParameterizedTest
    @CsvSource({
        "<input type=\"hidden\" value=\"notShown\">, 144",
        "<input type=\"text\" value=\"notEditable\" disabled>, 159",
        "<input type=\"text\" value=\"notEditable\" readonly>, 159"
    })
    void shouldHaveExpectedContentLengthIfElementsRevealed(String inputElement, int after) {
        // Given
        HttpMessage msg =
                createMessage(
                        """
                        <html>
                        <head></head>
                        <body>
                        <H1>Some Heading</H1>
                        <form action="/doStuff">
                        %s
                        <input type="text">
                        </form>
                        </body>
                        </html>"""
                                .formatted(inputElement));
        // When
        extension.revealFields(msg);
        // Then
        assertThat(msg.getResponseBody().length(), is(equalTo(after)));
    }

    private static HttpMessage createMessage() {
        return createMessage(DEFAULT_BODY);
    }

    private static HttpMessage createMessage(String body) {
        HttpMessage msg = new HttpMessage();
        msg.setResponseBody(body);

        try {
            msg.setResponseHeader(
                    """
                    HTTP/1.1 200 OK\r
                    content-type: text/html\r
                    content-length: %s"""
                            .formatted(msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            // Nothing to do
        }
        return msg;
    }
}
