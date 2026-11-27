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
package org.zaproxy.addon.client.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.util.List;
import javax.swing.tree.DefaultMutableTreeNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientMapTreeModel}. */
class ClientMapTreeModelUnitTest extends TestUtils {

    private ClientNode root;
    private ClientMap map;
    private ClientMapTreeModel model;

    @BeforeAll
    static void init() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() {
        Session session = mock(Session.class);
        lenient()
                .when(session.getUrlParamParser(any(String.class)))
                .thenReturn(new StandardParameterParser());
        root = new ClientNode(new ClientSideDetails("Root", ""), session);
        map = new ClientMap(root);
        model = new ClientMapTreeModel(map);
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterPublisher(map);
    }

    @Test
    void shouldMirrorRootOfMap() {
        // Given / When
        ClientNode node = ClientMapTreeModel.toClientNode(model.getRoot());
        // Then
        assertThat(node == root, is(true));
    }

    @Test
    void shouldReturnNullClientNodeForNonMapNodes() {
        assertThat(ClientMapTreeModel.toClientNode(null), is(nullValue()));
        assertThat(ClientMapTreeModel.toClientNode("a"), is(nullValue()));
        assertThat(
                ClientMapTreeModel.toClientNode(new DefaultMutableTreeNode("a")), is(nullValue()));
    }

    @Test
    void shouldMirrorAddedNodesInSortedOrder() {
        // Given / When
        map.getOrAddNode("https://ccc.com/b", false, false);
        map.getOrAddNode("https://aaa.com/a", false, false);
        map.getOrAddNode("https://bbb.com/a", false, false);
        // Then
        assertThat(
                names(rootTreeNode()),
                is(List.of("https://aaa.com", "https://bbb.com", "https://ccc.com")));
        assertThat(rootTreeNode().getChildAt(0).getChildCount(), is(1));
    }

    @Test
    void shouldMirrorNodesAlreadyInMap() {
        // Given
        map.getOrAddNode("https://aaa.com/a", false, false);
        // When
        ClientMapTreeModel late = new ClientMapTreeModel(map);
        // Then
        DefaultMutableTreeNode lateRoot = (DefaultMutableTreeNode) late.getRoot();
        assertThat(names(lateRoot), is(List.of("https://aaa.com")));
        assertThat(lateRoot.getChildAt(0).getChildCount(), is(1));
    }

    @Test
    void shouldMirrorDeletedNodes() {
        // Given
        map.getOrAddNode("https://aaa.com/a", false, false);
        ClientNode site = root.getChildAt(0);
        // When
        map.deleteNodes(List.of(site.getChildAt(0)));
        // Then
        assertThat(rootTreeNode().getChildAt(0).getChildCount(), is(0));
    }

    @Test
    void shouldMirrorDeletedNodeAndItsChildren() {
        // Given
        map.getOrAddNode("https://aaa.com/a", false, false);
        map.getOrAddNode("https://bbb.com/a", false, false);
        // When
        map.deleteNodes(List.of(root.getChildAt(0)));
        // Then
        assertThat(names(rootTreeNode()), is(List.of("https://bbb.com")));
    }

    @Test
    void shouldMirrorClearedMap() {
        // Given
        map.getOrAddNode("https://aaa.com/a", false, false);
        // When
        map.clear();
        map.getOrAddNode("https://bbb.com/a", false, false);
        // Then
        assertThat(names(rootTreeNode()), is(List.of("https://bbb.com")));
    }

    private DefaultMutableTreeNode rootTreeNode() {
        return (DefaultMutableTreeNode) model.getRoot();
    }

    private static List<String> names(DefaultMutableTreeNode node) {
        return java.util.Collections.list(node.children()).stream()
                .map(n -> ClientMapTreeModel.toClientNode(n).getUserObject().getName())
                .toList();
    }
}
