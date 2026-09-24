/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.llm;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import io.github.bonigarcia.seljup.BrowsersTemplate.Browser;
import io.github.bonigarcia.seljup.SeleniumJupiter;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.authhelper.llm.AiAssistedAuthenticationMethodType.AiAssistedAuthenticationMethod;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

/**
 * Exercises {@link AiAuthScriptGenerator#PAGE_ELEMENTS_JS} against a real browser DOM, since it's a
 * JavaScript snippet that a mocked {@link WebDriver} can't verify. Kept separate from {@link
 * AiAuthScriptGeneratorUnitTest} so the real WebDriver session doesn't interfere with its
 * Mockito-based tests.
 */
class AiAuthScriptGeneratorPageElementsUnitTest extends TestUtils {

    @RegisterExtension static SeleniumJupiter seleniumJupiter = new SeleniumJupiter();

    private AiAuthScriptGenerator generator;
    private String url;
    private Supplier<String> pageContent = () -> "";

    @BeforeAll
    static void setup() {
        seleniumJupiter.addBrowsers(
                new Browser(
                        "firefox",
                        null,
                        null,
                        new String[] {"-headless"},
                        new String[] {"remote.active-protocols=1"},
                        Map.of("webSocketUrl", true)));
    }

    @BeforeEach
    void setupEach() throws IOException {
        AiAssistedAuthenticationMethod config =
                new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
        config.setLoginPageUrl("http://localhost/login");
        generator = new AiAuthScriptGenerator(config, mock(LlmCommunicationService.class), null);

        startServer();

        String path = "/test";
        url = "http://localhost:" + nano.getListeningPort() + path;
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(pageContent.get());
                    }
                });
    }

    @AfterEach
    void cleanupEach() {
        stopServer();
    }

    @TestTemplate
    void shouldExcludeHiddenTypeInput(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                        <input type="text" id="visible" name="visible" />
                        <input type="hidden" id="csrf" name="csrf" value="token123" />
                        """;
        wd.get(url);
        // When
        List<AiAuthInputElement> elements = generator.extractPageElements(wd);
        // Then
        assertThat(elements.size(), is(equalTo(1)));
        assertThat(elements.get(0).id(), is(equalTo("visible")));
    }

    @TestTemplate
    void shouldExcludeElementWithHiddenAttribute(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                        <input type="text" id="visible" name="visible" />
                        <input type="text" id="hiddenAttr" name="hiddenAttr" hidden />
                        """;
        wd.get(url);
        // When
        List<AiAuthInputElement> elements = generator.extractPageElements(wd);
        // Then
        assertThat(elements.size(), is(equalTo(1)));
        assertThat(elements.get(0).id(), is(equalTo("visible")));
    }

    @TestTemplate
    void shouldExcludeElementHiddenViaCssDisplayNone(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                        <input type="text" id="visible" name="visible" />
                        <input type="text" id="cssHidden" name="cssHidden" style="display:none" />
                        """;
        wd.get(url);
        // When
        List<AiAuthInputElement> elements = generator.extractPageElements(wd);
        // Then
        assertThat(elements.size(), is(equalTo(1)));
        assertThat(elements.get(0).id(), is(equalTo("visible")));
    }

    @TestTemplate
    void shouldExcludeAncestorHiddenElement(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                        <input type="text" id="visible" name="visible" />
                        <div style="display:none">
                          <input type="text" id="insideHidden" name="insideHidden" />
                        </div>
                        """;
        wd.get(url);
        // When
        List<AiAuthInputElement> elements = generator.extractPageElements(wd);
        // Then
        assertThat(elements.size(), is(equalTo(1)));
        assertThat(elements.get(0).id(), is(equalTo("visible")));
    }

    @TestTemplate
    void shouldIncludeAllVisibleElements(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                        <input type="text" id="username" name="username" />
                        <input type="password" id="password" name="password" />
                        <button id="submit">Log in</button>
                        """;
        wd.get(url);
        // When
        List<AiAuthInputElement> elements = generator.extractPageElements(wd);
        // Then
        assertThat(elements.size(), is(equalTo(3)));
        assertThat(elements.stream().allMatch(AiAuthInputElement::visible), is(true));
    }
}
