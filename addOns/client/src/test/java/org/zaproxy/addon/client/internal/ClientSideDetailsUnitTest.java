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
package org.zaproxy.addon.client.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.internal.ClientSideComponent.Type;

/** Unit tests for {@code ClientSideDetails}. */
class ClientSideDetailsUnitTest {

    private static final String EXAMPLE_URL = "https://example.com";

    private static final InteractableState INTERACTABLE = new InteractableState(true, true, true);
    private static final InteractableState NOT_INTERACTABLE =
            new InteractableState(false, false, false);

    @Test
    void shouldReturnFalseForUpdateComponentInteractableWhenNoComponentMatchesIdAndTagName() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        details.addComponent(component("BUTTON", "btn1"));

        // When
        boolean changed = details.updateComponentInteractable("btn2", "BUTTON", INTERACTABLE);

        // Then
        assertThat(changed, is(false));
    }

    @Test
    void shouldReturnFalseForUpdateComponentInteractableWhenInteractableAlreadySameValue() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        details.addComponent(component("BUTTON", "btn1"));

        // When
        boolean changed = details.updateComponentInteractable("btn1", "BUTTON", null);

        // Then
        assertThat(changed, is(false));
    }

    @Test
    void shouldReturnTrueAndUpdateForUpdateComponentInteractableWhenInteractableChanges() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        ClientSideComponent component = component("BUTTON", "btn1");
        details.addComponent(component);

        // When
        boolean changed = details.updateComponentInteractable("btn1", "BUTTON", INTERACTABLE);

        // Then
        assertThat(changed, is(true));
        assertThat(component.getInteractable(), is(INTERACTABLE));
    }

    @Test
    void shouldNotMatchByIdAloneForUpdateComponentInteractableWhenTagNameDiffers() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        details.addComponent(component("BUTTON", "btn1"));

        // When
        boolean changed = details.updateComponentInteractable("btn1", "INPUT", INTERACTABLE);

        // Then
        assertThat(changed, is(false));
    }

    @Test
    void shouldNotMatchByTagNameAloneForUpdateComponentInteractableWhenIdDiffers() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        details.addComponent(component("BUTTON", "btn1"));

        // When
        boolean changed = details.updateComponentInteractable("btn2", "BUTTON", INTERACTABLE);

        // Then
        assertThat(changed, is(false));
    }

    @Test
    void shouldMatchComponentWithEmptyIdByTagNameForUpdateComponentInteractable() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        ClientSideComponent component = component("BUTTON", "");
        details.addComponent(component);

        // When
        boolean changed = details.updateComponentInteractable("", "BUTTON", NOT_INTERACTABLE);

        // Then
        assertThat(changed, is(true));
        assertThat(component.getInteractable(), is(NOT_INTERACTABLE));
    }

    @Test
    void shouldSetInteractableToNullForUpdateComponentInteractable() {
        // Given
        ClientSideDetails details = new ClientSideDetails("Page", EXAMPLE_URL);
        ClientSideComponent component = component("BUTTON", "btn1");
        component.setInteractable(INTERACTABLE);
        details.addComponent(component);

        // When
        boolean changed = details.updateComponentInteractable("btn1", "BUTTON", null);

        // Then
        assertThat(changed, is(true));
        assertThat(component.getInteractable(), is(nullValue()));
    }

    private static ClientSideComponent component(String tagName, String id) {
        return new ClientSideComponent(
                Map.of(), tagName, id, EXAMPLE_URL, null, "", Type.BUTTON, "", -1);
    }
}
