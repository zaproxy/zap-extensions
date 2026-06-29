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
package org.zaproxy.addon.client.spider.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideComponent.Type;
import org.zaproxy.addon.client.internal.ElementLocator;
import org.zaproxy.addon.client.spider.ActionWaitStrategy;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link ClickElement}. */
class ClickElementUnitTest {

    private ValueProvider valueProvider;
    private URI uri;
    private ActionWaitStrategy waitStrategy;
    private InMemoryStats stats;

    @BeforeEach
    void setUp() throws IOException {
        valueProvider = mock(ValueProvider.class);
        waitStrategy = mock();
        uri = new URI("http://example.com/test", true);
        stats = new InMemoryStats();
        Stats.addListener(stats);
    }

    @AfterEach
    void tearDown() {
        Stats.removeListener(stats);
    }

    @Test
    void shouldThrowIfComponentIsNull() {
        assertThrows(
                NullPointerException.class,
                () -> new ClickElement(valueProvider, uri, null, false));
    }

    @Test
    void shouldClickElementOnRun() {
        // Given
        ClientSideComponent component = componentWithLocator("A", "id", "btn");
        ClickElement action = new ClickElement(valueProvider, uri, component, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(By.id("btn"))).willReturn(element);
        given(wd.findElements(any(By.class))).willReturn(List.of());

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        verify(element).click();
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A.clicked"), is(1L));
    }

    @Test
    void shouldFillInputsAndTextAreasBeforeClicking() {
        // Given
        ClientSideComponent component = componentWithLocator("A", "id", "btn");
        ClickElement action = new ClickElement(valueProvider, uri, component, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);
        WebElement input1 = visibleInput("inputA", "text");
        WebElement input2 = visibleInput("inputB", "text");
        WebElement textarea = visibleTextArea("textareaA");
        given(wd.findElements(any(By.class))).willReturn(List.of(input1, input2, textarea));
        given(valueProvider.getValue(any(), any(), eq("inputA"), any(), any(), any(), any()))
                .willReturn("value1");
        given(valueProvider.getValue(any(), any(), eq("inputB"), any(), any(), any(), any()))
                .willReturn("value2");
        given(valueProvider.getValue(any(), any(), eq("textareaA"), any(), any(), any(), any()))
                .willReturn("value3");

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        InOrder inOrder = inOrder(input1, input2, textarea);
        inOrder.verify(input1).clear();
        inOrder.verify(input1).sendKeys("value1");
        inOrder.verify(input2).clear();
        inOrder.verify(input2).sendKeys("value2");
        inOrder.verify(textarea).clear();
        inOrder.verify(textarea).sendKeys("value3");
    }

    @Test
    void shouldNotFillInputsBeforeClickingWhenPassive() {
        // Given
        ClientSideComponent component = componentWithLocator("A", "id", "btn");
        ClickElement action = new ClickElement(valueProvider, uri, component, true);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);
        WebElement input1 = visibleInput("inputA", "text");
        WebElement input2 = visibleInput("inputB", "text");
        WebElement textarea = visibleTextArea("textareaA");
        given(wd.findElements(any(By.class))).willReturn(List.of(input1, input2, textarea));

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        verifyNoInteractions(input1);
        verifyNoInteractions(input2);
        verifyNoInteractions(textarea);
    }

    @Test
    void shouldHandleClickExceptionGracefully() {
        // Given
        ClientSideComponent component = componentWithLocator("A", "id", "btn");
        ClickElement action = new ClickElement(valueProvider, uri, component, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);
        given(wd.findElements(any(By.class))).willReturn(List.of());
        willThrow(RuntimeException.class).given(element).click();

        // When / Then
        boolean result = assertDoesNotThrow(() -> action.run(waitStrategy, wd));
        assertThat(result, is(equalTo(false)));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A.exception"), is(1L));
    }

    @Test
    void shouldIncrementStatsWhenElementNotFound() {
        // Given
        ClientSideComponent component = componentWithLocator("A", "id", "btn");
        ClickElement action = new ClickElement(valueProvider, uri, component, false);
        WebDriver wd = mock(WebDriver.class);
        given(wd.findElement(any(By.class))).willThrow(RuntimeException.class);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A.notfound"), is(1L));
    }

    @Test
    void shouldIncrementStatsWhenElementNotDisplayed() {
        // Given
        ClientSideComponent component = componentWithLocator("A", "id", "btn");
        ClickElement action = new ClickElement(valueProvider, uri, component, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = mock(WebElement.class);
        given(wd.findElement(any(By.class))).willReturn(element);
        given(element.isDisplayed()).willReturn(false);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A.notdisplayed"), is(1L));
    }

    @Test
    void shouldYieldNoByWhenNoElementLocator() {
        // Given
        ClientSideComponent component = component("A", null);
        ClickElement action = new ClickElement(valueProvider, uri, component, false);
        WebDriver wd = mock(WebDriver.class);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(stats.getStat("stats.client.spider.action.click.tag.A.noby"), is(1L));
    }

    @ParameterizedTest
    @MethodSource("provideIsSupportedData")
    void shouldReturnExpectedSupportedValue(ClientSideComponent component, boolean expected) {
        // Given
        Predicate<String> scopeChecker = href -> true;

        // When
        boolean supported = ClickElement.isSupported(scopeChecker, component);

        // Then
        assertThat(supported, is(expected));
    }

    static Stream<Arguments> provideIsSupportedData() {
        return Stream.of(
                arguments(component(null, ""), false),
                arguments(component("A", ""), true),
                arguments(component("BUTTON", ""), true),
                arguments(component("INPUT", "submit"), true),
                arguments(component("INPUT", "button"), true),
                arguments(component("INPUT", "text"), false),
                arguments(component("FORM", ""), false));
    }

    @Test
    void shouldNotSupportWhenHrefOutOfScope() {
        // Given
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "",
                        "http://example.com",
                        "http://other.example.com/",
                        "",
                        Type.LINK,
                        "",
                        -1);
        Predicate<String> scopeChecker = href -> false;

        // When / Then
        assertThat(ClickElement.isSupported(scopeChecker, component), is(false));
    }

    @Test
    void shouldSupportWhenHrefInScope() {
        // Given
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "",
                        "http://example.com",
                        "http://example.com/page",
                        "",
                        Type.LINK,
                        "",
                        -1);
        Predicate<String> scopeChecker = href -> true;

        // When / Then
        assertThat(ClickElement.isSupported(scopeChecker, component), is(true));
    }

    private static ClientSideComponent componentWithLocator(
            String tagName, String locatorType, String locatorValue) {
        ClientSideComponent c = component(tagName, "");
        c.setElementLocator(new ElementLocator(locatorType, locatorValue));
        return c;
    }

    private static ClientSideComponent component(String tagName, String tagType) {
        return new ClientSideComponent(
                Map.of(),
                tagName,
                "",
                "http://example.com",
                null,
                "",
                tagName != null ? Type.LINK : Type.UNKNOWN,
                tagType,
                -1);
    }

    private static WebElement visibleElement() {
        WebElement element = mock(WebElement.class);
        given(element.isDisplayed()).willReturn(true);
        return element;
    }

    private static WebElement visibleInput(String name, String type) {
        WebElement input = mock(WebElement.class);
        given(input.isDisplayed()).willReturn(true);
        given(input.getDomAttribute("name")).willReturn(name);
        given(input.getDomAttribute("type")).willReturn(type);
        return input;
    }

    private static WebElement visibleTextArea(String name) {
        WebElement textarea = mock(WebElement.class);
        given(textarea.isDisplayed()).willReturn(true);
        given(textarea.getTagName()).willReturn("textarea");
        given(textarea.getDomAttribute("name")).willReturn(name);
        return textarea;
    }
}
