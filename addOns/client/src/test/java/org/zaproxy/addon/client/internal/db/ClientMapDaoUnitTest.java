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
package org.zaproxy.addon.client.internal.db;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;

/** Unit tests for {@link ClientMapDao}. */
class ClientMapDaoUnitTest {

    private static final String URL = "https://example.com/page";
    private static final String NAME = "page";
    private static final String TAG_NAME = "A";
    private static final String ELEMENT_ID = "link1";
    private static final String HREF = "https://example.com/other";
    private static final String TEXT = "Click here";
    private static final String TAG_TYPE = "submit";

    @Test
    void shouldConvertNodeToEntry() {
        // Given
        ClientNode node = createNode(URL, NAME, true, false);

        // When
        ClientMapNode entry = ClientMapDao.toNode(node);

        // Then
        assertThat(entry.getUrl(), is(equalTo(URL)));
        assertThat(entry.getName(), is(equalTo(NAME)));
        assertThat(entry.isVisited(), is(true));
        assertThat(entry.isStorage(), is(false));
        assertThat(entry.isContentLoaded(), is(false));
        assertThat(entry.isRedirect(), is(false));
    }

    @Test
    void shouldConvertUnvisitedStorageNodeToEntry() {
        // Given
        ClientNode node = createNode(URL, NAME, false, true);

        // When
        ClientMapNode entry = ClientMapDao.toNode(node);

        // Then
        assertThat(entry.isVisited(), is(false));
        assertThat(entry.isStorage(), is(true));
    }

    @Test
    void shouldConvertRedirectNodeToEntry() {
        // Given
        ClientNode node = createNode(URL, NAME, true, false);
        node.getUserObject().setRedirect(true);

        // When
        ClientMapNode entry = ClientMapDao.toNode(node);

        // Then
        assertThat(entry.isRedirect(), is(true));
    }

    @Test
    void shouldConvertComponentToEntry() {
        // Given
        int formId = 3;
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        TAG_NAME,
                        ELEMENT_ID,
                        URL,
                        HREF,
                        TEXT,
                        ClientSideComponent.Type.LINK,
                        TAG_TYPE,
                        formId);
        ClientNode node = createNode(URL, NAME, true, false);
        node.setPersistenceId(42L);

        // When
        ClientMapComponent entry = ClientMapDao.toComponent(node, component);

        // Then
        assertThat(entry.getNodeId(), is(equalTo(42L)));
        assertThat(entry.getTagName(), is(equalTo(TAG_NAME)));
        assertThat(entry.getElementId(), is(equalTo(ELEMENT_ID)));
        assertThat(entry.getHref(), is(equalTo(HREF)));
        assertThat(entry.getText(), is(equalTo(TEXT)));
        assertThat(entry.getType(), is(equalTo("link")));
        assertThat(entry.getTagType(), is(equalTo(TAG_TYPE)));
        assertThat(entry.getFormId(), is(equalTo(formId)));
    }

    @Test
    void shouldStoreNullFormIdWhenMinusOne() {
        // Given
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        TAG_NAME,
                        ELEMENT_ID,
                        URL,
                        HREF,
                        TEXT,
                        ClientSideComponent.Type.LINK,
                        TAG_TYPE,
                        -1);
        ClientNode node = createNode(URL, NAME, true, false);

        // When
        ClientMapComponent entry = ClientMapDao.toComponent(node, component);

        // Then
        assertThat(entry.getFormId(), is(nullValue()));
    }

    @Test
    void shouldConvertEntryToComponent() {
        // Given
        int formId = 5;
        ClientMapComponent entry = createComponentEntry(formId);

        // When
        ClientSideComponent component = ClientMapDao.toComponent(entry, URL);

        // Then
        assertThat(component.getTagName(), is(equalTo(TAG_NAME)));
        assertThat(component.getId(), is(equalTo(ELEMENT_ID)));
        assertThat(component.getParentUrl(), is(equalTo(URL)));
        assertThat(component.getHref(), is(equalTo(HREF)));
        assertThat(component.getText(), is(equalTo(TEXT)));
        assertThat(component.getType(), is(equalTo(ClientSideComponent.Type.LINK)));
        assertThat(component.getTagType(), is(equalTo(TAG_TYPE)));
        assertThat(component.getFormId(), is(equalTo(formId)));
    }

    @Test
    void shouldDefaultFormIdToMinusOneWhenNull() {
        // Given
        ClientMapComponent entry = createComponentEntry(null);

        // When
        ClientSideComponent component = ClientMapDao.toComponent(entry, URL);

        // Then
        assertThat(component.getFormId(), is(equalTo(-1)));
    }

    @Test
    void shouldConvertUnknownTypeKeyToUnknown() {
        // Given
        ClientMapComponent entry = createComponentEntry(null);
        entry.setType("nonExistentType");

        // When
        ClientSideComponent component = ClientMapDao.toComponent(entry, URL);

        // Then
        assertThat(component.getType(), is(equalTo(ClientSideComponent.Type.UNKNOWN)));
    }

    @Test
    void shouldSetPersistenceIdOnComponent() {
        // Given
        ClientMapComponent entry = createComponentEntry(null);
        entry.setId(42L);

        // When
        ClientSideComponent component = ClientMapDao.toComponent(entry, URL);

        // Then
        assertThat(component.getPersistenceId(), is(equalTo(42L)));
        assertThat(component.getParentUrl(), is(equalTo(URL)));
    }

    @Test
    void shouldNotThrowWhenPersistingNodeWithNullPmf() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            assertThat(
                    ClientMapDao.persistNode(createNode(URL, NAME, false, false)),
                    is(equalTo(-1L)));
        }
    }

    @Test
    void shouldNotThrowWhenPersistingComponentWithNullPmf() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            ClientNode node = createNode(URL, NAME, true, false);
            ClientSideComponent component =
                    new ClientSideComponent(
                            Map.of(),
                            TAG_NAME,
                            ELEMENT_ID,
                            URL,
                            HREF,
                            TEXT,
                            ClientSideComponent.Type.LINK,
                            TAG_TYPE,
                            -1);
            assertThat(ClientMapDao.persistComponent(node, component), is(equalTo(-1L)));
        }
    }

    @Test
    void shouldNotInvokeActionWhenForEachNodeWithNullPmf() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            Consumer<ClientMapNode> action = mock();
            ClientMapDao.forEachNode(action);
            verifyNoInteractions(action);
        }
    }

    @Test
    void shouldNotInvokeActionWhenForEachComponentWithNullPmf() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            Consumer<ClientMapComponent> action = mock();
            ClientMapDao.forEachComponent(action);
            verifyNoInteractions(action);
        }
    }

    @Test
    void shouldNotThrowWhenDeletingNodeByIdWithNullPmf() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            assertDoesNotThrow(() -> ClientMapDao.deleteNodeById(1L));
        }
    }

    @Test
    void shouldNotThrowWhenUpdatingNodeWithNullPmf() {
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            tableJdo.when(TableJdo::getPmf).thenReturn(null);

            ClientNode node = createNode(URL, NAME, true, false);
            node.setPersistenceId(1L);
            assertDoesNotThrow(() -> ClientMapDao.updateNode(node));
        }
    }

    private static ClientNode createNode(
            String url, String name, boolean visited, boolean storage) {
        return new ClientNode(new ClientSideDetails(name, url, visited, storage), storage);
    }

    private static ClientMapComponent createComponentEntry(Integer formId) {
        ClientMapComponent entry = new ClientMapComponent();
        entry.setNodeId(1L);
        entry.setTagName(TAG_NAME);
        entry.setElementId(ELEMENT_ID);
        entry.setHref(HREF);
        entry.setText(TEXT);
        entry.setType("link");
        entry.setTagType(TAG_TYPE);
        entry.setFormId(formId);
        return entry;
    }
}
