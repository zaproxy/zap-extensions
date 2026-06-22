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
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
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
    void shouldThrowIfElementDataIsNull() {
        assertThrows(
                NullPointerException.class,
                () -> new ClickElement(valueProvider, uri, null, false));
    }

    @Test
    void shouldClickElementOnRun() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);
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
    void shouldFillInputsBeforeClicking() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);
        WebElement input1 = visibleInput("inputA", "text");
        WebElement input2 = visibleInput("inputB", "text");
        given(wd.findElements(any(By.class))).willReturn(List.of(input1, input2));
        given(valueProvider.getValue(any(), any(), eq("inputA"), any(), any(), any(), any()))
                .willReturn("value1");
        given(valueProvider.getValue(any(), any(), eq("inputB"), any(), any(), any(), any()))
                .willReturn("value2");

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        InOrder inOrder = inOrder(input1, input2);
        inOrder.verify(input1).clear();
        inOrder.verify(input1).sendKeys("value1");
        inOrder.verify(input2).clear();
        inOrder.verify(input2).sendKeys("value2");
    }

    @Test
    void shouldNotFillInputsBeforeClickingWhenPassive() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, true);
        WebDriver wd = mock(WebDriver.class);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);
        WebElement input1 = visibleInput("inputA", "text");
        WebElement input2 = visibleInput("inputB", "text");
        given(wd.findElements(any(By.class))).willReturn(List.of(input1, input2));
        given(valueProvider.getValue(any(), any(), eq("inputA"), any(), any(), any(), any()))
                .willReturn("value1");
        given(valueProvider.getValue(any(), any(), eq("inputB"), any(), any(), any(), any()))
                .willReturn("value2");

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        verifyNoInteractions(input1);
        verifyNoInteractions(input2);
    }

    @Test
    void shouldHandleClickExceptionGracefully() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
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
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
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
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
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
    void shouldUseByIdWhenIdPresent() {
        // Given
        String id = "my-button";
        Map<String, String> elementData = Map.of("tagName", "BUTTON", "id", id);
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement visibleElement = visibleElement();
        ArgumentCaptor<By> byCaptor = ArgumentCaptor.forClass(By.class);
        given(wd.findElement(byCaptor.capture())).willReturn(visibleElement);
        given(wd.findElements(any(By.class))).willReturn(List.of());

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(byCaptor.getValue(), is(By.id(id)));
    }

    @Test
    void shouldUseXpathByValueForInputTag() {
        // Given
        String text = "Submit";
        Map<String, String> elementData = Map.of("tagName", "INPUT", "text", text);
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement visibleElement = visibleElement();
        ArgumentCaptor<By> byCaptor = ArgumentCaptor.forClass(By.class);
        given(wd.findElement(byCaptor.capture())).willReturn(visibleElement);
        given(wd.findElements(any(By.class))).willReturn(List.of());

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(byCaptor.getValue(), is(By.xpath("//INPUT[@value='" + text + "']")));
    }

    @Test
    void shouldUseXpathContainsTextForOtherTag() {
        // Given
        String text = "Click me";
        Map<String, String> elementData = Map.of("tagName", "BUTTON", "text", text);
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement visibleElement = visibleElement();
        ArgumentCaptor<By> byCaptor = ArgumentCaptor.forClass(By.class);
        given(wd.findElement(byCaptor.capture())).willReturn(visibleElement);
        given(wd.findElements(any(By.class))).willReturn(List.of());

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(byCaptor.getValue(), is(By.xpath("//BUTTON[contains(text(), '" + text + "')]")));
    }

    @Test
    void shouldUseByTagNameWhenNoText() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "A");
        ClickElement action = new ClickElement(valueProvider, uri, elementData, false);
        WebDriver wd = mock(WebDriver.class);
        WebElement visibleElement = visibleElement();
        ArgumentCaptor<By> byCaptor = ArgumentCaptor.forClass(By.class);
        given(wd.findElement(byCaptor.capture())).willReturn(visibleElement);
        given(wd.findElements(any(By.class))).willReturn(List.of());

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(byCaptor.getValue(), is(By.tagName("A")));
    }

    @ParameterizedTest
    @MethodSource("provideIsSupportedData")
    void shouldReturnExpectedSupportedValue(Map<String, String> data, boolean expected) {
        // Given
        Predicate<String> scopeChecker = href -> true;

        // When
        boolean supported = ClickElement.isSupported(scopeChecker, data);

        // Then
        assertThat(supported, is(expected));
    }

    static Stream<Arguments> provideIsSupportedData() {
        return Stream.of(
                arguments(Map.of(), false),
                arguments(Map.of("tagName", "A"), true),
                arguments(Map.of("tagName", "BUTTON"), true),
                arguments(Map.of("tagName", "INPUT", "tagType", "submit"), true),
                arguments(Map.of("tagName", "INPUT", "tagType", "button"), true),
                arguments(Map.of("tagName", "INPUT", "tagType", "text"), false),
                arguments(Map.of("tagName", "FORM"), false));
    }

    @Test
    void shouldNotSupportWhenHrefOutOfScope() {
        // Given
        Map<String, String> data = Map.of("tagName", "A", "href", "http://other.example.com/");
        Predicate<String> scopeChecker = href -> false;

        // When / Then
        assertThat(ClickElement.isSupported(scopeChecker, data), is(false));
    }

    @Test
    void shouldSupportWhenHrefInScope() {
        // Given
        Map<String, String> data = Map.of("tagName", "A", "href", "http://example.com/page");
        Predicate<String> scopeChecker = href -> true;

        // When / Then
        assertThat(ClickElement.isSupported(scopeChecker, data), is(true));
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
}
