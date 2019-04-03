/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Unit test for {@link BrowserUI}.
 */
public class BrowserUIUnitTest {

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenCreatingBrowserUIWithNullName() {
        // Given
        String name = null;
        // When
        new BrowserUI(name, Browser.FIREFOX);
        // Then = Exception
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenCreatingBrowserUIWithEmptyName() {
        // Given
        String name = "";
        // When
        new BrowserUI(name, Browser.FIREFOX);
        // Then = Exception
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenCreatingBrowserUIWithNullBrowser() {
        // Given
        Browser browser = null;
        // When
        new BrowserUI("Some Browser", browser);
        // Then = Exception
    }

    @Test
    public void shouldGetNamePassedInConstructor() {
        // Given
        String name = "Some Name";
        BrowserUI browserUI = new BrowserUI(name, Browser.FIREFOX);
        // When
        String retrievedName = browserUI.getName();
        // Then
        assertThat(retrievedName, is(equalTo(name)));
    }

    @Test
    public void shouldGetBrowserPassedInConstructor() {
        // Given
        Browser browser = Browser.FIREFOX;
        BrowserUI browserUI = new BrowserUI("Some Name", browser);
        // When
        Browser retrievedBrowser = browserUI.getBrowser();
        // Then
        assertThat(retrievedBrowser, is(equalTo(browser)));
    }

    @Test
    public void shouldReturnNameFromToString() {
        // Given
        String name = "Some Name";
        BrowserUI browserUI = new BrowserUI(name, Browser.FIREFOX);
        // When
        String string = browserUI.toString();
        // Then
        assertThat(string, is(equalTo(name)));
    }

    @Test
    public void shouldReturnPositiveNumberWhenComparingWithNull() {
        // Given
        BrowserUI browserUI = new BrowserUI("Name A", Browser.FIREFOX);
        // When
        int comparisonResult = browserUI.compareTo(null);
        // Then
        assertThat(comparisonResult, is(greaterThanOrEqualTo(1)));
    }

    @Test
    public void shouldReturnNegativeNumberWhenComparingWithGreaterName() {
        // Given
        BrowserUI browserUI = new BrowserUI("Name A", Browser.FIREFOX);
        BrowserUI otherBrowserUI = new BrowserUI("Name B", Browser.FIREFOX);
        // When
        int comparisonResult = browserUI.compareTo(otherBrowserUI);
        // Then
        assertThat(comparisonResult, is(lessThanOrEqualTo(-1)));
    }

    @Test
    public void shouldReturnPositiveNumberWhenComparingWithLesserName() {
        // Given
        BrowserUI browserUI = new BrowserUI("Name B", Browser.FIREFOX);
        BrowserUI otherBrowserUI = new BrowserUI("Name A", Browser.FIREFOX);
        // When
        int comparisonResult = browserUI.compareTo(otherBrowserUI);
        // Then
        assertThat(comparisonResult, is(greaterThanOrEqualTo(1)));
    }

    @Test
    public void shouldReturnZeroWhenComparingWithSameName() {
        // Given
        BrowserUI browserUI = new BrowserUI("Name A", Browser.FIREFOX);
        BrowserUI otherBrowserUI = new BrowserUI("Name A", Browser.FIREFOX);
        // When
        int comparisonResult = browserUI.compareTo(otherBrowserUI);
        // Then
        assertThat(comparisonResult, is(equalTo(0)));
    }
}
