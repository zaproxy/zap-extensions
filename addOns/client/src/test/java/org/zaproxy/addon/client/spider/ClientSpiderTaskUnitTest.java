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
package org.zaproxy.addon.client.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;
import org.zaproxy.addon.client.spider.ClientSpiderTask.Status;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientSpiderTask}. */
class ClientSpiderTaskUnitTest extends TestUtils {

    private ClientSpider clientSpider;
    private WebDriverProcess wdp;
    private WebDriver wd;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() {
        clientSpider = mock(ClientSpider.class);
        wdp = mock(WebDriverProcess.class);
        wd = mock(WebDriver.class);
        WebDriver.Options wdOptions = mock(WebDriver.Options.class);
        WebDriver.Timeouts timeouts =
                mock(WebDriver.Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));

        given(clientSpider.isStopped()).willReturn(false);
        given(clientSpider.isPaused()).willReturn(false);
        given(clientSpider.getWebDriverProcess()).willReturn(wdp);
        given(wdp.getWebDriver()).willReturn(wd);
        given(wd.manage()).willReturn(wdOptions);
        given(wdOptions.timeouts()).willReturn(timeouts);
    }

    @Test
    void shouldRunAllActionsInOrder() {
        // Given
        List<String> ran = new ArrayList<>();
        List<SpiderAction> actions = List.of(w -> ran.add("first"), w -> ran.add("second"));
        ClientSpiderTask task = new ClientSpiderTask(1, clientSpider, actions, 5, 0, "test", "");

        // When
        task.run();

        // Then
        assertThat(ran, contains("first", "second"));
        assertThat(task.getStatus(), is(Status.FINISHED));
    }

    @Test
    void shouldWaitAfterEachActionWhenActionWaitTimeIsSet() {
        // Given
        List<Long> timestamps = new ArrayList<>();
        List<SpiderAction> actions =
                List.of(
                        w -> timestamps.add(System.currentTimeMillis()),
                        w -> timestamps.add(System.currentTimeMillis()));
        ClientSpiderTask task = new ClientSpiderTask(1, clientSpider, actions, 5, 1, "test", "");

        // When
        task.run();

        // Then
        assertThat(task.getStatus(), is(Status.FINISHED));
        assertThat(timestamps.size(), is(2));
        assertThat(timestamps.get(1) - timestamps.get(0), greaterThanOrEqualTo(1000L));
    }
}
