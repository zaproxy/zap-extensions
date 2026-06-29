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
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;
import org.zaproxy.addon.client.spider.ClientSpiderTask.Status;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientSpiderTask}. */
class ClientSpiderTaskUnitTest extends TestUtils {

    private ClientSpider clientSpider;
    private ActionWaitStrategy waitStrategy;
    private TaskContext context;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() {
        clientSpider = mock(ClientSpider.class);

        given(clientSpider.isStopped()).willReturn(false);
        given(clientSpider.isPaused()).willReturn(false);
        waitStrategy = mock();
        given(waitStrategy.waitAfterAction()).willReturn(true);
        WebDriverProcess wdp = mock(WebDriverProcess.class);
        given(wdp.getWaitStrategy()).willReturn(waitStrategy);
        context = new TaskContext(wdp, null, null);
        given(clientSpider.createTaskContext()).willReturn(context);
    }

    @Test
    void shouldRunActionWithStateFromWebDriverProcess() {
        // Given
        SpiderAction action = mock();
        ClientSpiderTask task = new ClientSpiderTask(1, clientSpider, List.of(action), "test", "");

        // When
        task.run();

        // Then
        verify(action).run(context);
        assertThat(task.getStatus(), is(Status.FINISHED));
    }

    @Test
    void shouldRunAllActionsInOrder() {
        // Given
        List<String> ran = new ArrayList<>();
        List<SpiderAction> actions = List.of(ctx -> ran.add("first"), ctx -> ran.add("second"));
        ClientSpiderTask task = new ClientSpiderTask(1, clientSpider, actions, "test", "");

        // When
        task.run();

        // Then
        assertThat(ran, contains("first", "second"));
        assertThat(task.getStatus(), is(Status.FINISHED));
    }

    @Test
    void shouldWaitAfterEachAction() {
        // Given
        List<SpiderAction> actions = List.of(ctx -> true, ctx -> true);
        ClientSpiderTask task = new ClientSpiderTask(1, clientSpider, actions, "test", "");

        // When
        task.run();

        // Then
        verify(waitStrategy, times(2)).waitAfterAction();
        assertThat(task.getStatus(), is(Status.FINISHED));
    }

    @Test
    void shouldStopRunningActionsWhenWaitStrategyReturnsFalse() {
        // Given
        given(waitStrategy.waitAfterAction()).willReturn(false);
        List<SpiderAction> actions = List.of(ctx -> true, ctx -> true);
        ClientSpiderTask task = new ClientSpiderTask(1, clientSpider, actions, "test", "");

        // When
        task.run();

        // Then
        verify(waitStrategy).waitAfterAction();
        assertThat(task.getStatus(), is(Status.FINISHED));
    }
}
