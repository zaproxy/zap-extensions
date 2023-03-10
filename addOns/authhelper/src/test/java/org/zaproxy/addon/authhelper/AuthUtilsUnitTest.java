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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.Point;
import org.openqa.selenium.Rectangle;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.testutils.TestUtils;

class AuthUtilsUnitTest extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionAuthhelper());
    }

    @Test
    void shouldReturnUserTextField() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "text"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(inputElements);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("text")));
    }

    @Test
    void shouldReturnUserEmailField() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(inputElements);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("email")));
    }

    @Test
    void shouldReturnNoUserField() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "hidden"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(inputElements);

        // Then
        assertThat(field, is(nullValue()));
    }

    @Test
    void shouldReturnPasswordField() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "checkbox"));
        inputElements.add(new TestWebElement("input", "password"));

        // When
        WebElement field = AuthUtils.getPasswordField(inputElements);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("password")));
    }

    @Test
    void shouldReturnNoPasswordField() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "hidden"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getPasswordField(inputElements);

        // Then
        assertThat(field, is(nullValue()));
    }

    @Test
    void shouldReturnNoSessionTokens() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));

        // When
        List<String> tokenLabels = AuthUtils.getSessionTokenLabels(msg);

        // Then
        assertThat(tokenLabels.size(), is(equalTo(0)));
    }

    @Test
    void shouldExtractHeaderSessionTokens() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader("CustomHeader", "example-session-token");
        msg.getResponseHeader().addHeader(HttpHeader.AUTHORIZATION, "example-session-token");

        // When
        List<String> tokenLabels = AuthUtils.getSessionTokenLabels(msg);

        // Then
        assertThat(tokenLabels.size(), is(equalTo(1)));
        assertThat(
                tokenLabels.get(0), is(equalTo(AuthUtils.HEADER_TOKEN + HttpHeader.AUTHORIZATION)));
    }

    @Test
    void shouldExtractJsonSessionTokens() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "blah-blah-json");
        msg.getResponseBody()
                .setBody("{'auth': {'test': '123', accessToken: 'example-session-token'}}");

        // When
        List<String> tokenLabels = AuthUtils.getSessionTokenLabels(msg);

        // Then
        assertThat(tokenLabels.size(), is(equalTo(1)));
        assertThat(tokenLabels.get(0), is(equalTo("json:auth.accessToken")));
    }

    @Test
    void shouldDefaultToNoTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, String> tokens = AuthUtils.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(0)));
    }

    @Test
    void shouldExtractHeaderTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, String> tokens = AuthUtils.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("header:Header1"), is(equalTo("Value1")));
        assertThat(tokens.get("header:Header2"), is(equalTo("Value2")));
    }

    @Test
    void shouldExtractUrlParams() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, String> tokens = AuthUtils.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("url:att1"), is(equalTo("val1")));
        assertThat(tokens.get("url:att2"), is(equalTo("val2")));
    }

    @Test
    void shouldExtractJsonTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json"),
                        new HttpResponseBody(
                                "{'wrapper1': {\n"
                                        + "  'att1': 'val1',\n"
                                        + "  'att2': 'val2',\n"
                                        + "  'wrapper2': {\n"
                                        + "    'att1': 'val3',\n"
                                        + "    'array': [\n"
                                        + "      {'att1': 'val4', 'att2': 'val5'},\n"
                                        + "      {'att3': 'val6', 'att4': 'val7'}\n"
                                        + "    ]\n"
                                        + "  }\n"
                                        + "}}"));
        // When
        Map<String, String> tokens = AuthUtils.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(8)));
        assertThat(tokens.get("json:wrapper1.att1"), is(equalTo("val1")));
        assertThat(tokens.get("json:wrapper1.att2"), is(equalTo("val2")));
        assertThat(tokens.get("json:wrapper1.wrapper2.att1"), is(equalTo("val3")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[0].att1"), is(equalTo("val4")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[0].att2"), is(equalTo("val5")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[1].att3"), is(equalTo("val6")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[1].att4"), is(equalTo("val7")));
        assertThat(tokens.get("header:Content-Type"), is(equalTo("application/json")));
    }

    class TestWebElement implements WebElement {

        private String tag;
        private String type;

        TestWebElement(String tag, String type) {
            this.tag = tag;
            this.type = type;
        }

        @Override
        public <X> X getScreenshotAs(OutputType<X> target) throws WebDriverException {
            return null;
        }

        @Override
        public void click() {}

        @Override
        public void submit() {}

        @Override
        public void sendKeys(CharSequence... keysToSend) {}

        @Override
        public void clear() {}

        @Override
        public String getTagName() {
            return tag;
        }

        @Override
        public String getAttribute(String name) {
            if ("type".equalsIgnoreCase(name)) {
                return type;
            }
            return null;
        }

        @Override
        public boolean isSelected() {
            return false;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public String getText() {
            return null;
        }

        @Override
        public List<WebElement> findElements(By by) {
            return null;
        }

        @Override
        public WebElement findElement(By by) {
            return null;
        }

        @Override
        public boolean isDisplayed() {
            return false;
        }

        @Override
        public Point getLocation() {
            return null;
        }

        @Override
        public Dimension getSize() {
            return null;
        }

        @Override
        public Rectangle getRect() {
            return null;
        }

        @Override
        public String getCssValue(String propertyName) {
            return null;
        }
    }
}
