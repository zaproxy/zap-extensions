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

import java.io.IOException;
import java.util.List;
import java.util.Map;
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
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link SubmitForm}. */
class SubmitFormUnitTest {

    private ValueProvider valueProvider;
    private URI uri;
    private InMemoryStats stats;

    @BeforeEach
    void setUp() throws IOException {
        valueProvider = mock(ValueProvider.class);
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
        assertThrows(NullPointerException.class, () -> new SubmitForm(valueProvider, uri, null));
    }

    @Test
    void shouldSubmitFormOnRun() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "FORM", "formId", "0");
        SubmitForm action = new SubmitForm(valueProvider, uri, elementData);
        WebDriver wd = mock(WebDriver.class);
        WebElement form = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(form);
        given(form.findElements(any(By.class))).willReturn(List.of());

        // When
        action.run(wd);

        // Then
        verify(form).submit();
        assertThat(stats.getStat("stats.client.spider.action.form.0"), is(1L));
    }

    @Test
    void shouldFillInputsFromFormBeforeSubmitting() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "FORM", "formId", "0");
        SubmitForm action = new SubmitForm(valueProvider, uri, elementData);
        WebDriver wd = mock(WebDriver.class);
        WebElement form = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(form);
        WebElement input1 = visibleInput("inputA", "text");
        WebElement input2 = visibleInput("inputB", "text");
        given(form.findElements(any(By.class))).willReturn(List.of(input1, input2));
        given(valueProvider.getValue(any(), any(), eq("inputA"), any(), any(), any(), any()))
                .willReturn("value1");
        given(valueProvider.getValue(any(), any(), eq("inputB"), any(), any(), any(), any()))
                .willReturn("value2");

        // When
        action.run(wd);

        // Then
        InOrder inOrder = inOrder(input1, input2);
        inOrder.verify(input1).clear();
        inOrder.verify(input1).sendKeys("value1");
        inOrder.verify(input2).clear();
        inOrder.verify(input2).sendKeys("value2");
    }

    @Test
    void shouldHandleSubmitExceptionGracefully() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "FORM", "formId", "0");
        SubmitForm action = new SubmitForm(valueProvider, uri, elementData);
        WebDriver wd = mock(WebDriver.class);
        WebElement form = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(form);
        given(form.findElements(any(By.class))).willReturn(List.of());
        willThrow(RuntimeException.class).given(form).submit();

        // When / Then
        assertDoesNotThrow(() -> action.run(wd));
        assertThat(stats.getStat("stats.client.spider.action.form.0"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.form.0.exception"), is(1L));
    }

    @Test
    void shouldIncrementStatsWhenFormNotFound() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "FORM", "formId", "0");
        SubmitForm action = new SubmitForm(valueProvider, uri, elementData);
        WebDriver wd = mock(WebDriver.class);
        given(wd.findElement(any(By.class))).willThrow(RuntimeException.class);

        // When
        action.run(wd);

        // Then
        assertThat(stats.getStat("stats.client.spider.action.form.0"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.form.0.notfound"), is(1L));
    }

    @Test
    void shouldIncrementStatsWhenFormNotDisplayed() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "FORM", "formId", "0");
        SubmitForm action = new SubmitForm(valueProvider, uri, elementData);
        WebDriver wd = mock(WebDriver.class);
        WebElement form = mock(WebElement.class);
        given(wd.findElement(any(By.class))).willReturn(form);
        given(form.isDisplayed()).willReturn(false);

        // When
        action.run(wd);

        // Then
        assertThat(stats.getStat("stats.client.spider.action.form.0"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.form.0.notdisplayed"), is(1L));
    }

    @Test
    void shouldUseXpathWithFormIndexAndTagName() {
        // Given
        Map<String, String> elementData = Map.of("tagName", "FORM", "formId", "1");
        SubmitForm action = new SubmitForm(valueProvider, uri, elementData);
        WebDriver wd = mock(WebDriver.class);
        WebElement visibleForm = visibleElement();
        ArgumentCaptor<By> byCaptor = ArgumentCaptor.forClass(By.class);
        given(wd.findElement(byCaptor.capture())).willReturn(visibleForm);
        given(visibleForm.findElements(any(By.class))).willReturn(List.of());

        // When
        action.run(wd);

        // Then
        assertThat(byCaptor.getValue(), is(By.xpath("(//FORM)[2]")));
    }

    @ParameterizedTest
    @MethodSource("provideIsSupportedData")
    void shouldReturnExpectedSupportedValue(Map<String, String> data, boolean expected) {
        // When
        boolean supported = SubmitForm.isSupported(data);

        // Then
        assertThat(supported, is(expected));
    }

    static Stream<Arguments> provideIsSupportedData() {
        return Stream.of(
                arguments(Map.of("tagName", "FORM", "formId", "0"), true),
                arguments(Map.of("tagName", "FORM"), false),
                arguments(Map.of("tagName", "DIV", "formId", "0"), false),
                arguments(Map.of(), false));
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
