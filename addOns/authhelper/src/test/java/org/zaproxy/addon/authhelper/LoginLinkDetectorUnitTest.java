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
package org.zaproxy.addon.authhelper;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import io.github.bonigarcia.seljup.BrowsersTemplate.Browser;
import io.github.bonigarcia.seljup.SeleniumJupiter;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

class LoginLinkDetectorUnitTest extends TestUtils {

    @RegisterExtension static SeleniumJupiter seleniumJupiter = new SeleniumJupiter();

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
    void shouldReturnNoWdLinks(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <input type="text" name="randomA" />
                            <form>
                            <input type="text" name="randomB">
                            <input type="password" name="passw">
                            </form>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(0)));
    }

    @Test
    void shouldReturnNoSrcLinks() {
        // Given
        String html =
                """
                            <input type="text" name="randomA" />
                            <form>
                            <input type="text" name="randomB">
                            <input type="password" name="passw">
                            </form>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(0)));
    }

    @TestTemplate
    void shouldReturnSimpleWdLink(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#login">Log in</a>
                            <a href="#link3">Link 3</a>
                            <button>Sign in</button>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getDomProperty("href"), is(equalTo(url + "#login")));
    }

    @Test
    void shouldReturnSimpleSrcLink() {
        // Given
        String html =
                """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#login">Log in</a>
                            <a href="#link3">Link 3</a>
                            <button>Sign in</button>
                            <div/>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getAttributeValue("href"), is(equalTo("#login")));
    }

    @TestTemplate
    void shouldReturnMultipleSimpleWdLinks(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#login">Log in</a>
                            <a href="#link2">Link 2</a>
                            <a href="#signin"> SignIn </a>
                            <a href="#link3">Link 3</a>
                            <button>Sign in</button>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getDomProperty("href"), is(equalTo(url + "#login")));
        assertThat(loginLinks.get(1).getDomProperty("href"), is(equalTo(url + "#signin")));
    }

    @Test
    void shouldReturnMultipleSimpleSrcLinks() {
        // Given
        String html =
                """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#login">Log in</a>
                            <a href="#link2">Link 2</a>
                            <a href="#signin"> SignIn </a>
                            <a href="#link3">Link 3</a>
                            <button>Sign in</button>
                            <div/>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getAttributeValue("href"), is(equalTo("#login")));
        assertThat(loginLinks.get(1).getAttributeValue("href"), is(equalTo("#signin")));
    }

    @TestTemplate
    void shouldReturnLinkWithDeeperWdText(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#login"><div><div></div><div><div>Log in</div></div></a>
                            <a href="#link3">Link 3</a>
                            <button>Sign in</button>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getDomProperty("href"), is(equalTo(url + "#login")));
    }

    @Test
    void shouldReturnLinkWithDeeperSrcText() {
        // Given
        String html =
                """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#login"><div><div></div><div><div>Log in</div></div></a>
                            <a href="#link3">Link 3</a>
                            <button>Sign in</button>
                            <div/>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getAttributeValue("href"), is(equalTo("#login")));
    }

    @TestTemplate
    void shouldReturnSimpleWdButton(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#link3">Link 3</a>
                            <button custom="test">Sign in</button>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getDomAttribute("custom"), is(equalTo("test")));
    }

    @Test
    void shouldReturnSimpleWdButton() {
        // Given
        String html =
                """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#link3">Link 3</a>
                            <button custom="test">Sign in</button>
                            <div/>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getAttributeValue("custom"), is(equalTo("test")));
    }

    @TestTemplate
    void shouldReturnMultipleSimpleWdButtons(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <button custom="test1">Sign in</button>
                            <a href="#link2">Link 2</a>
                            <button custom="test2">Log In</button>
                            <a href="#link3">Link 3</a>
                            <button custom="test3">Log Out</button>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getDomAttribute("custom"), is(equalTo("test1")));
        assertThat(loginLinks.get(1).getDomAttribute("custom"), is(equalTo("test2")));
    }

    @Test
    void shouldReturnMultipleSimpleSrcButtons() {
        // Given
        String html =
                """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <button custom="test1">Sign in</button>
                            <a href="#link2">Link 2</a>
                            <button custom="test2">Log In</button>
                            <a href="#link3">Link 3</a>
                            <button custom="test3">Log Out</button>
                            <div/>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getAttributeValue("custom"), is(equalTo("test1")));
        assertThat(loginLinks.get(1).getAttributeValue("custom"), is(equalTo("test2")));
    }

    @TestTemplate
    void shouldReturnButtonWithDeeperWdText(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <button custom="test"><div><div></div><div><div>Log in</div></div></button>
                            <a href="#link3">Link 3</a>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getDomAttribute("custom"), is(equalTo("test")));
    }

    @Test
    void shouldReturnButtonWithDeeperSrcText() {
        // Given
        String html =
                """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <button custom="test"><div><div></div><div><div>Log in</div></div></button>
                            <a href="#link3">Link 3</a>
                            <div/>
                         """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getAttributeValue("custom"), is(equalTo("test")));
    }

    @TestTemplate
    void shouldReturnSimpleWdRoleButton(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <a href="#link3">Link 3</a>
                            <div role="button" custom="test">Sign in</div>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getDomAttribute("custom"), is(equalTo("test")));
    }

    @Test
    void shouldReturnSimpleWdRoleButton() {
        // Given
        String html =
                """
                   <h1>Heading</h1>
                   <a href="#link1">Link 1</a>
                   <a href="#link2">Link 2</a>
                   <a href="#link3">Link 3</a>
                   <div role="button" custom="test">Sign in</div>
                   <div/>
                """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getAttributeValue("custom"), is(equalTo("test")));
    }

    @TestTemplate
    void shouldReturnMultipleSimpleWdRoleButtons(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <div role="button" custom="test1">Sign in</div>
                            <a href="#link2">Link 2</a>
                            <div role="button" custom="test2">Log In</div>
                            <a href="#link3">Link 3</a>
                            <div role="button" custom="test3">Log Out</div>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getDomAttribute("custom"), is(equalTo("test1")));
        assertThat(loginLinks.get(1).getDomAttribute("custom"), is(equalTo("test2")));
    }

    @Test
    void shouldReturnMultipleSimpleSrcRoleButtons() {
        // Given
        String html =
                """
                   <h1>Heading</h1>
                   <a href="#link1">Link 1</a>
                   <div role="button" custom="test1">Sign in</div>
                   <a href="#link2">Link 2</a>
                   <div role="button" custom="test2">Log In</div>
                   <a href="#link3">Link 3</a>
                   <div role="button" custom="test3">Log Out</div>
                   <div/>
                """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getAttributeValue("custom"), is(equalTo("test1")));
        assertThat(loginLinks.get(1).getAttributeValue("custom"), is(equalTo("test2")));
    }

    @TestTemplate
    void shouldReturnRoleButtonWithDeeperWdText(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                            <h1>Heading</h1>
                            <a href="#link1">Link 1</a>
                            <a href="#link2">Link 2</a>
                            <div role="button" custom="test"><div><div></div><div><div>Log in</div></div></div>
                            <a href="#link3">Link 3</a>
                            <div/>
                         """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getDomAttribute("custom"), is(equalTo("test")));
    }

    @Test
    void shouldReturnRoleButtonWithDeeperSrcText() {
        // Given
        String html =
                """
                   <h1>Heading</h1>
                   <a href="#link1">Link 1</a>
                   <a href="#link2">Link 2</a>
                   <div role="button" custom="test"><div><div></div><div><div>Log in</div></div></div></div>
                   <a href="#link3">Link 3</a>
                   <div/>
                """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(1)));
        assertThat(loginLinks.get(0).getAttributeValue("custom"), is(equalTo("test")));
    }

    @TestTemplate
    void shouldReturnDivsWithPointerStyleAndLoginTextWithWd(WebDriver wd) {
        // Given
        pageContent =
                () ->
                        """
                           <div id="div1">Login but no pointer</div>
                           <div id="div2">
                             <div id="div3" style="cursor: pointer">
                               <div id="div4"></div>
                               <div id="div5">Log in</div>
                             </div>
                           </div>
                        """;
        wd.get(url);
        // When
        List<WebElement> loginLinks =
                LoginLinkDetector.getLoginLinks(wd, AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(2)));
        assertThat(loginLinks.get(0).getDomAttribute("id"), is(equalTo("div3")));
        assertThat(loginLinks.get(1).getDomAttribute("id"), is(equalTo("div5")));
    }

    @Test
    void shouldReturnDivsWithLoginTextWithSrc() {
        // Given
        String html =
                """
                   <div id="div1">Login but no pointer</div>
                   <div id="div2">
                     <div id="div3" style="cursor: pointer">
                       <div id="div4"></div>
                       <div id="div5">Log in</div>
                     </div>
                   </div>
                """;
        // When
        List<Element> loginLinks =
                LoginLinkDetector.getLoginLinks(new Source(html), AuthUtils.LOGIN_LABELS_P1);

        // Then
        assertThat(loginLinks.size(), is(equalTo(4)));
        assertThat(loginLinks.get(0).getAttributeValue("id"), is(equalTo("div1")));
        assertThat(loginLinks.get(1).getAttributeValue("id"), is(equalTo("div2")));
        assertThat(loginLinks.get(2).getAttributeValue("id"), is(equalTo("div3")));
        assertThat(loginLinks.get(3).getAttributeValue("id"), is(equalTo("div5")));
    }
}
