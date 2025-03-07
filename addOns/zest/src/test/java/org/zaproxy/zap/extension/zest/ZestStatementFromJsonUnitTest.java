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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientElementSubmit;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientSwitchToFrame;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowResize;
import org.zaproxy.zest.core.v1.ZestStatement;

class ZestStatementFromJsonUnitTest {

    @Test
    void shouldCreateClientLaunchStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "browserType" : "firefox",
    			  "enabled" : true,
    			  "headless" : true,
    			  "url" : "https://www.example.com",
    			  "capabilities" : "test-capabilities",
    			  "elementType" : "ZestClientLaunch"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientLaunch.class));
        ZestClientLaunch clientStmt = (ZestClientLaunch) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientLaunch")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getBrowserType(), is(equalTo("firefox")));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
        assertThat(clientStmt.isHeadless(), is(equalTo(true)));
        assertThat(clientStmt.getUrl(), is(equalTo("https://www.example.com")));
        assertThat(clientStmt.getCapabilities(), is(equalTo("test-capabilities")));
    }

    @Test
    void shouldCreateClientElementClickStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "type" : "test-type",
    			  "element" : "test-element",
    			  "elementType" : "ZestClientElementClick"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientElementClick.class));
        ZestClientElementClick clientStmt = (ZestClientElementClick) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientElementClick")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getType(), is(equalTo("test-type")));
        assertThat(clientStmt.getElement(), is(equalTo("test-element")));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldCreateClientElementSendKeysStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "type" : "test-type",
    			  "element" : "test-element",
    			  "value" : "test-value",
    			  "elementType" : "ZestClientElementSendKeys"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientElementSendKeys.class));
        ZestClientElementSendKeys clientStmt = (ZestClientElementSendKeys) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientElementSendKeys")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getType(), is(equalTo("test-type")));
        assertThat(clientStmt.getElement(), is(equalTo("test-element")));
        assertThat(clientStmt.getValue(), is(equalTo("test-value")));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldCreateClientElementSubmitStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "type" : "test-type",
    			  "element" : "test-element",
    			  "elementType" : "ZestClientElementSubmit"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientElementSubmit.class));
        ZestClientElementSubmit clientStmt = (ZestClientElementSubmit) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientElementSubmit")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getType(), is(equalTo("test-type")));
        assertThat(clientStmt.getElement(), is(equalTo("test-element")));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldCreateClientElementClearStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "type" : "test-type",
    			  "element" : "test-element",
    			  "elementType" : "ZestClientElementClear"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientElementClear.class));
        ZestClientElementClear clientStmt = (ZestClientElementClear) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientElementClear")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getType(), is(equalTo("test-type")));
        assertThat(clientStmt.getElement(), is(equalTo("test-element")));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldCreateClientWindowCloseStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "sleepInSeconds" : 2,
    			  "elementType" : "ZestClientWindowClose"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientWindowClose.class));
        ZestClientWindowClose clientStmt = (ZestClientWindowClose) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientWindowClose")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getSleepInSeconds(), is(equalTo(2)));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldCreateClientSwitchToFrameStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "frameIndex" : 2,
    			  "frameName" : "my-frame",
    			  "parent" : false,
    			  "elementType" : "ZestClientSwitchToFrame"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientSwitchToFrame.class));
        ZestClientSwitchToFrame clientStmt = (ZestClientSwitchToFrame) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientSwitchToFrame")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getFrameIndex(), is(equalTo(2)));
        assertThat(clientStmt.getFrameName(), is(equalTo("my-frame")));
        assertThat(clientStmt.isParent(), is(equalTo(false)));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldCreateClientWindowResizeStatement() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "x" : 1000,
    			  "y" : 2000,
    			  "elementType" : "ZestClientWindowResize"
    			}
    			""");
        // When
        ZestStatement stmt = ZestStatementFromJson.createZestStatementFromJson(json);
        // Then
        assertThat(stmt, instanceOf(ZestClientWindowResize.class));
        ZestClientWindowResize clientStmt = (ZestClientWindowResize) stmt;
        assertThat(clientStmt.getElementType(), is(equalTo("ZestClientWindowResize")));
        assertThat(clientStmt.getWindowHandle(), is(equalTo("windowHandle1")));
        assertThat(clientStmt.getX(), is(equalTo(1000)));
        assertThat(clientStmt.getY(), is(equalTo(2000)));
        assertThat(clientStmt.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldThrowExceptionOnUnknownStatementType() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "windowHandle" : "windowHandle1",
    			  "elementType" : "ZestClientUnknown"
    			}
    			""");
        // When / Then
        Exception exception =
                assertThrows(
                        Exception.class,
                        () -> ZestStatementFromJson.createZestStatementFromJson(json));

        assertEquals("Element type not found ZestClientUnknown", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionOnNoElementType() throws Exception {
        // Given
        JSONObject json =
                JSONObject.fromObject(
                        """
    			{
    			  "a" : "b",
    			  "b" : "c"
    			}
    			""");
        // When / Then
        Exception exception =
                assertThrows(
                        Exception.class,
                        () -> ZestStatementFromJson.createZestStatementFromJson(json));

        assertEquals("Element not recognised {\"a\":\"b\",\"b\":\"c\"}", exception.getMessage());
    }
}
