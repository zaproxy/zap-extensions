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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideComponent.Type;
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;

/** Unit test for {@link TaskContext}. */
class TaskContextUnitTest {

    private TaskContext context;

    @BeforeEach
    void setUp() {
        WebDriverProcess wdp = mock();
        given(wdp.getWaitStrategy()).willReturn(mock());
        context = new TaskContext(() -> false, wdp, null, null);
    }

    @Test
    void shouldIgnoreStateChangedComponentWhenNoActionInProgress() {
        // Given
        ClientSideComponent component = component("BUTTON", "btn1");
        InteractableState state = new InteractableState(true, true, true);
        // lastActionedComponent is null (no action in progress)

        // When
        context.addStateChangedComponent(component, state);

        // Then
        assertThat(context.getAndClearStateChangedComponents(), is(empty()));
    }

    @Test
    void shouldAcceptStateChangedComponentWhenActionIsInProgress() {
        // Given
        ClientSideComponent actioned = component("A", "link1");
        ClientSideComponent changed = component("BUTTON", "btn1");
        InteractableState state = new InteractableState(true, true, true);
        context.setLastActionedComponent(actioned);

        // When
        context.addStateChangedComponent(changed, state);

        // Then
        assertThat(
                context.getAndClearStateChangedComponents(),
                contains(new ClientGraphVertex.Component(changed, state)));
    }

    private static ClientSideComponent component(String tagName, String id) {
        return new ClientSideComponent(
                Map.of(),
                tagName,
                id,
                "https://example.com",
                null,
                "",
                "A".equals(tagName) ? Type.LINK : Type.BUTTON,
                "",
                -1);
    }
}
