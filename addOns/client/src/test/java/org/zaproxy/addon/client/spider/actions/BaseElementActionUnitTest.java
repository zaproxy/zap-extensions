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
package org.zaproxy.addon.client.spider.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.Point;
import org.openqa.selenium.Rectangle;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.spider.ActionWaitStrategy;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;
import org.zaproxy.addon.client.spider.TaskContext;
import org.zaproxy.addon.commonlib.ValueProvider;

/** Unit test for {@link BaseElementAction}. */
class BaseElementActionUnitTest {

    private ValueProvider valueProvider;
    private URI uri;
    private BaseElementAction action;

    @BeforeEach
    void setupEach() throws IOException {
        valueProvider = mock(ValueProvider.class);
        uri = new URI("http://localhost:1234/test", true);
        ClientSideComponent component = mock();

        action =
                new BaseElementAction(uri, component) {

                    @Override
                    protected boolean run(
                            TaskContext context, WebElement element, String statsPrefix) {
                        return true;
                    }

                    @Override
                    protected String getStatsPrefix() {
                        return "prefix";
                    }
                };
    }

    @ParameterizedTest
    @CsvSource({
        "'', text",
        "something, text",
        "email, text",
        "text, text",
        "password, password",
        "file, file"
    })
    void shouldCallValueProviderWithExpectedValues(String type, String controlType) {
        // Given
        String name = "input-name";
        String value = "input-value";
        TaskContext context = context(List.of(new TestWebElement("input", type, name, value)));
        String formAction = "formaction";

        // When
        action.fillComponents(context, formAction, "statsprefix");

        // Then
        verify(valueProvider)
                .getValue(
                        uri,
                        formAction,
                        name,
                        value,
                        List.of(),
                        Map.of(),
                        Map.of("Control Type", controlType, "type", type));
    }

    @ParameterizedTest
    @CsvSource({"textarea-name, textarea-value"})
    void shouldCallValueProviderWithExpectedValuesForTextArea(String name, String value) {
        // Given
        TaskContext context = context(List.of(new TestWebElement("textarea", null, name, value)));
        String formAction = "formaction";

        // When
        action.fillComponents(context, formAction, "statsprefix");

        // Then
        verify(valueProvider)
                .getValue(
                        uri,
                        formAction,
                        name,
                        value,
                        List.of(),
                        Map.of(),
                        Map.of("Control Type", "text", "type", "textarea"));
    }

    @Test
    void shouldWaitAfterAction() throws IOException {
        // Given
        ActionWaitStrategy waitStrategy = mock();
        given(waitStrategy.waitAfterAction()).willReturn(true);
        String url = "http://localhost:1234/test";
        TaskContext context = runContext(waitStrategy, url, url, true);

        // When
        boolean result = action.run(context);

        // Then
        assertThat(result, is(equalTo(true)));
        verify(waitStrategy).waitAfterAction();
        verify(waitStrategy, never()).waitAfterPageLoad(url);
    }

    @Test
    void shouldWaitAfterPageLoadWhenUrlChanges() throws IOException {
        // Given
        ActionWaitStrategy waitStrategy = mock();
        given(waitStrategy.waitAfterAction()).willReturn(true);
        given(waitStrategy.waitAfterPageLoad("http://localhost:1234/other")).willReturn(true);
        TaskContext context =
                runContext(
                        waitStrategy,
                        "http://localhost:1234/test",
                        "http://localhost:1234/other",
                        true);

        // When
        boolean result = action.run(context);

        // Then
        assertThat(result, is(equalTo(true)));
        verify(waitStrategy).waitAfterAction();
        verify(waitStrategy).waitAfterPageLoad("http://localhost:1234/other");
    }

    @Test
    void shouldNotWaitAfterPageLoadWhenUrlUnchanged() throws IOException {
        // Given
        ActionWaitStrategy waitStrategy = mock();
        given(waitStrategy.waitAfterAction()).willReturn(true);
        String url = "http://localhost:1234/test";
        TaskContext context = runContext(waitStrategy, url, url, true);

        // When
        action.run(context);

        // Then
        verify(waitStrategy, never()).waitAfterPageLoad(url);
    }

    @Test
    void shouldNotWaitWhenActionReturnsFalse() throws IOException {
        // Given
        ActionWaitStrategy waitStrategy = mock();
        TaskContext context =
                runContext(
                        waitStrategy,
                        "http://localhost:1234/test",
                        "http://localhost:1234/test",
                        false);

        // When
        boolean result = action.run(context);

        // Then
        assertThat(result, is(equalTo(false)));
        verify(waitStrategy, never()).waitAfterAction();
        verify(waitStrategy, never()).waitAfterPageLoad(any());
    }

    @Test
    void shouldReturnFalseWhenWaitAfterActionInterrupted() throws IOException {
        // Given
        ActionWaitStrategy waitStrategy = mock();
        given(waitStrategy.waitAfterAction()).willReturn(false);
        String url = "http://localhost:1234/test";
        TaskContext context = runContext(waitStrategy, url, url, true);

        // When
        boolean result = action.run(context);

        // Then
        assertThat(result, is(equalTo(false)));
        verify(waitStrategy).waitAfterAction();
        verify(waitStrategy, never()).waitAfterPageLoad(url);
    }

    private TaskContext runContext(
            ActionWaitStrategy waitStrategy,
            String urlBefore,
            String urlAfter,
            boolean actionResult)
            throws IOException {
        URI actionUri = new URI("http://localhost:1234/test", true);
        ClientSideComponent component = mock();
        given(component.getBy()).willReturn(By.id("elem"));

        BaseElementAction runAction =
                new BaseElementAction(actionUri, component) {
                    @Override
                    protected boolean run(
                            TaskContext context, WebElement element, String statsPrefix) {
                        return actionResult;
                    }

                    @Override
                    protected String getStatsPrefix() {
                        return "run.prefix";
                    }
                };

        WebDriverProcess wdp = mock(WebDriverProcess.class);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = mock(WebElement.class);
        given(element.isDisplayed()).willReturn(true);
        given(wd.findElement(By.id("elem"))).willReturn(element);
        given(wd.getCurrentUrl()).willReturn(urlBefore, urlAfter);
        given(wdp.getWebDriver()).willReturn(wd);
        given(wdp.getWaitStrategy()).willReturn(waitStrategy);

        action = runAction;

        return new TaskContext(wdp, valueProvider, null);
    }

    private TaskContext context(List<WebElement> elements) {
        WebDriverProcess wdp = mock(WebDriverProcess.class);
        WebDriver wd = mock(WebDriver.class);
        given(wd.findElements(By.xpath("//input | //textarea"))).willReturn(elements);
        given(wdp.getWebDriver()).willReturn(wd);
        return new TaskContext(wdp, valueProvider, null);
    }

    class TestWebElement implements WebElement {

        private String tag;
        private String type;
        private String name;
        private String value;

        TestWebElement(String tag, String type, String name, String value) {
            this.tag = tag;
            this.type = type;
            this.name = name;
            this.value = value;
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
        public String getDomAttribute(String name) {
            switch (name) {
                case "name":
                    return this.name;
                case "type":
                    return type;
                case "value":
                    return value;
                default:
                    return null;
            }
        }

        @Override
        @Deprecated
        public String getAttribute(String name) {
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
            return true;
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
