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
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Unit test for {@link Browser}.
 */
public class BrowserUnitTest {

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenGettingBrowserWithNullId() {
        // Given
        String id = null;
        // When
        Browser.getBrowserWithId(id);
        // Then = Exception
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenGettingBrowserWithEmptyId() {
        // Given
        String id = "";
        // When
        Browser.getBrowserWithId(id);
        // Then = Exception
    }

    @Test
    public void shouldReturnChromeWhenGettingBrowserWithChromeId() {
        // Given
        String chromeId = "chrome";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(chromeId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.CHROME)));
        assertThat(chromeId, is(equalTo(Browser.CHROME.getId())));
    }

    @Test
    public void shouldReturnFirefoxWhenGettingBrowserWithFirefoxId() {
        // Given
        String firefoxId = "firefox";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(firefoxId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.FIREFOX)));
        assertThat(firefoxId, is(equalTo(Browser.FIREFOX.getId())));
    }

    @Test
    public void shouldReturnHtmlUnitWhenGettingBrowserWithHtmlUnitId() {
        // Given
        String htmlUnitId = "htmlunit";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(htmlUnitId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.HTML_UNIT)));
        assertThat(htmlUnitId, is(equalTo(Browser.HTML_UNIT.getId())));
    }

    @Test
    public void shouldReturnIEWhenGettingBrowserWithIEId() {
        // Given
        String ieId = "ie";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(ieId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.INTERNET_EXPLORER)));
        assertThat(ieId, is(equalTo(Browser.INTERNET_EXPLORER.getId())));
    }

    @Test
    public void shouldReturnOperaWhenGettingBrowserWithOperaId() {
        // Given
        String operaId = "opera";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(operaId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.OPERA)));
        assertThat(operaId, is(equalTo(Browser.OPERA.getId())));
    }

    @Test
    public void shouldReturnPhantomJSWhenGettingBrowserWithPhantomJSId() {
        // Given
        String phantomJSId = "phantomjs";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(phantomJSId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.PHANTOM_JS)));
        assertThat(phantomJSId, is(equalTo(Browser.PHANTOM_JS.getId())));
    }

    @Test
    public void shouldReturnSafariWhenGettingBrowserWithSafariId() {
        // Given
        String safariId = "safari";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(safariId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.SAFARI)));
        assertThat(safariId, is(equalTo(Browser.SAFARI.getId())));
    }

    @Test
    public void shouldReturnFailSafeBrowserWhenGettingBrowserWithUnknownId() {
        // Given
        String unknowId = "unknowId";
        // When
        Browser retrievedBrowser = Browser.getBrowserWithId(unknowId);
        // Then
        assertThat(retrievedBrowser, is(equalTo(Browser.getFailSafeBrowser())));
    }

    @Test
    public void shouldReturnHtmlUnitBrowserWhenGettingFailSafeBrowser() {
        // Given / When
        Browser failSafeBrowser = Browser.getFailSafeBrowser();
        // Then
        assertThat(failSafeBrowser, is(equalTo(Browser.HTML_UNIT)));
    }
}
