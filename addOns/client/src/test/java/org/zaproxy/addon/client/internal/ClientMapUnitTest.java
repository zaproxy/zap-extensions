/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zap.testutils.TestUtils;

class ClientMapUnitTest extends TestUtils {

    private static final String REPORTED_OBJECT_JSON =
            """
            {
              "tagName": "INPUT",
              "id": "",
              "type": "input",
              "url": "%s",
              "href": %s,
              "nodeName": "INPUT",
              "timestamp": 0
            }""";

    private static final String REPORTED_EVENT_JSON =
            """
            {
              "eventName": "pageLoad",
              "url": "%s",
              "count": 1,
              "id": "",
              "tagName": "",
              "nodeName": "",
              "type": "",
              "xpath": "",
              "href": "",
              "text": "",
              "timestamp": 0
            }""";

    @BeforeAll
    static void init() {
        mockMessages(new ExtensionClientIntegration());
    }

    private static final String AAA_URL = "https://aaa.com";
    private static final String BBB_URL = "https://bbb.com";
    private static final String CCC_URL = "https://ccc.com";
    private static final String DDD_URL = "https://ddd.com";

    private static final String BBB_AAA_URL = "https://bbb.com/aaa";
    private static final String BBB_BBB_URL = "https://bbb.com/bbb";
    private static final String BBB_CCC_URL = "https://bbb.com/ccc";
    private static final String BBB_DDD_URL = "https://bbb.com/ddd";

    private ClientNode root;
    private ClientMapListener listener;

    ClientMap map;

    @BeforeEach
    void setUp() {
        Session session = mock(Session.class);
        StandardParameterParser ssp = new StandardParameterParser();
        lenient().when(session.getUrlParamParser(any(String.class))).thenReturn(ssp);
        root = new ClientNode(new ClientSideDetails("Root", ""), session);
        map = new ClientMap(root);
        listener = mock(ClientMapListener.class);
        map.addListener(listener);
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterPublisher(map);
    }

    @Test
    void shouldFailIfGettingNullUrl() {
        // Given / When
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> map.getNode(null, false, false));

        // Then
        assertThat(e.getMessage(), is("The url parameter should not be null"));
    }

    @Test
    void shouldHandleBaseSiteSlashFragmentSlash() {
        // Given / When
        map.getOrAddNode(AAA_URL + "/#/", false, false);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getUserObject().getName(), is("Root"));
        assertThat(root.getUserObject().getUrl(), is(""));

        assertThat(root.getChildAt(0).getUserObject().getName(), is(AAA_URL));
        assertThat(root.getChildAt(0).getUserObject().getUrl(), is(AAA_URL + "/"));
        assertThat(root.getChildAt(0).getChildCount(), is(1));

        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getName(), is("/#"));
        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getUrl(), is(AAA_URL + "/#"));
        assertThat(root.getChildAt(0).getChildAt(0).getChildCount(), is(1));

        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getName(), is("/"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is(AAA_URL + "/#/"));
        assertThat(root.getChildAt(0).getChildAt(0).getChildAt(0).getChildCount(), is(0));
    }

    @Test
    void shouldAddOrderedNodes() {
        // Given / When
        map.getOrAddNode(CCC_URL + "/", false, false);
        map.getOrAddNode(BBB_DDD_URL + "/", false, false);
        map.getOrAddNode(DDD_URL + "/", false, false);
        map.getOrAddNode(BBB_CCC_URL + "/", false, false);
        map.getOrAddNode(AAA_URL + "/", false, false);
        map.getOrAddNode(BBB_BBB_URL + "/", false, false);
        map.getOrAddNode(BBB_AAA_URL + "/", false, false);

        // Then
        assertThat(root.getChildCount(), is(4));
        assertThat(root.getUserObject().getName(), is("Root"));
        assertThat(root.getUserObject().getUrl(), is(""));

        assertThat(root.getChildAt(0).getUserObject().getName(), is(AAA_URL));
        assertThat(root.getChildAt(0).getUserObject().getUrl(), is(AAA_URL + "/"));
        assertThat(root.getChildAt(1).getUserObject().getName(), is(BBB_URL));
        assertThat(root.getChildAt(1).getUserObject().getUrl(), is(BBB_URL + "/"));
        assertThat(root.getChildAt(2).getUserObject().getName(), is(CCC_URL));
        assertThat(root.getChildAt(2).getUserObject().getUrl(), is(CCC_URL + "/"));
        assertThat(root.getChildAt(3).getUserObject().getName(), is(DDD_URL));
        assertThat(root.getChildAt(3).getUserObject().getUrl(), is(DDD_URL + "/"));

        assertThat(root.getChildAt(1).getChildCount(), is(4));
        assertThat(root.getChildAt(1).getChildAt(0).getUserObject().getName(), is("aaa"));
        assertThat(
                root.getChildAt(1).getChildAt(0).getUserObject().getUrl(), is(BBB_AAA_URL + "/"));

        InOrder inOrder = inOrder(listener);

        inOrder.verify(listener).nodeAdded(CCC_URL + "/", 2, 1, 0);
        inOrder.verify(listener).nodeAdded(BBB_DDD_URL + "/", 3, 1, 0);
        inOrder.verify(listener).nodeAdded(DDD_URL + "/", 2, 1, 0);
        inOrder.verify(listener).nodeAdded(BBB_CCC_URL + "/", 3, 1, 0);
        inOrder.verify(listener).nodeAdded(AAA_URL + "/", 2, 1, 0);
        inOrder.verify(listener).nodeAdded(BBB_BBB_URL + "/", 3, 1, 0);
        inOrder.verify(listener).nodeAdded(BBB_AAA_URL + "/", 3, 1, 0);
    }

    @Test
    void shouldNotifyAllListenersOnNodeAdded() {
        // Given
        ClientMapListener otherListener = mock(ClientMapListener.class);
        map.addListener(otherListener);

        // When
        map.getOrAddNode(AAA_URL, false, false);

        // Then
        verify(listener).nodeAdded(AAA_URL, 1, 1, 0);
        verify(otherListener).nodeAdded(AAA_URL, 1, 1, 0);
    }

    @Test
    void shouldNotifyListenerOnceForSameNode() {
        // Given
        map.getOrAddNode(AAA_URL, false, false);
        ClientMapListener otherListener = mock(ClientMapListener.class);
        map.addListener(otherListener);

        // When
        map.getOrAddNode(AAA_URL, false, false);

        // Then
        verify(listener).nodeAdded(AAA_URL, 1, 1, 0);
        verifyNoInteractions(otherListener);
    }

    @Test
    void shouldNotNotifyRemovedListener() {
        // Given
        map.removeListener(listener);

        // When
        map.getOrAddNode(AAA_URL, false, false);

        // Then
        verifyNoInteractions(listener);
    }

    @Test
    void shouldAddStorageAtEnd() {
        // Given / When
        map.getOrAddNode(BBB_DDD_URL + "/", false, false);
        map.getOrAddNode(BBB_CCC_URL + "/", false, true);
        map.getOrAddNode(BBB_BBB_URL + "/", false, false);
        map.getOrAddNode(BBB_AAA_URL + "/", false, true);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildCount(), is(4));
        assertThat(root.getChildAt(0).getSite(), is(BBB_URL + "/"));
        assertThat(root.getChildAt(0).getUserObject().getName(), is(BBB_URL));
        assertThat(root.getChildAt(0).getUserObject().getUrl(), is(BBB_URL + "/"));
        assertThat(root.getChildAt(0).getChildCount(), is(4));

        assertThat(
                root.getChildAt(0).getChildAt(0).getUserObject().getUrl(), is(BBB_AAA_URL + "/"));
        assertThat(
                root.getChildAt(0).getChildAt(1).getUserObject().getUrl(), is(BBB_BBB_URL + "/"));
        assertThat(
                root.getChildAt(0).getChildAt(2).getUserObject().getUrl(), is(BBB_CCC_URL + "/"));
        assertThat(
                root.getChildAt(0).getChildAt(3).getUserObject().getUrl(), is(BBB_DDD_URL + "/"));
    }

    @Test
    void shouldGetExistingNode() {
        // Given
        ClientNode node1 = map.getOrAddNode(BBB_DDD_URL + "/", false, false);
        map.getOrAddNode(BBB_CCC_URL + "/", false, true);
        map.getOrAddNode(BBB_BBB_URL + "/", false, false);
        map.getOrAddNode(BBB_AAA_URL + "/", false, true);

        // When
        ClientNode node2 = map.getNode(BBB_DDD_URL + "/", false, false);

        // Then
        assertThat(node1, is(node2));
    }

    @Test
    void shouldNotGetMissingNode() {
        // Given
        map.getOrAddNode(BBB_DDD_URL + "/", false, false);
        map.getOrAddNode(BBB_CCC_URL + "/", false, true);
        map.getOrAddNode(BBB_BBB_URL + "/", false, false);
        map.getOrAddNode(BBB_AAA_URL + "/", false, true);

        // When
        ClientNode node = map.getNode(BBB_DDD_URL + "/x", false, false);

        // Then
        assertNull(node);
    }

    @Test
    void shouldNormaliseParams() {
        // Given / When
        map.getOrAddNode("https://www.example.com/aaa/bbb?p1=v1&p2=v2", false, false);
        map.getOrAddNode("https://www.example.com/aaa/bbb?p2=v3&p1=v4", false, false);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getUserObject().getName(), is("https://www.example.com"));
        assertThat(root.getChildAt(0).getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getName(), is("aaa"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com/aaa/"));
        assertThat(root.getChildAt(0).getChildAt(0).getChildCount(), is(1));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getName(),
                is("bbb(p1,p2)"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com/aaa/bbb?p1=v1&p2=v2"));
    }

    @Test
    void shouldNormaliseSiteNodesWithParams() {
        // Given / When
        map.getOrAddNode("https://www.example.com?p1=v1&p2=v2", false, false);
        map.getOrAddNode("https://www.example.com?p2=v3&p1=v4", false, false);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getUserObject().getName(), is("https://www.example.com"));
        assertThat(root.getChildAt(0).getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getName(), is("(p1,p2)"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com?p1=v1&p2=v2"));
        assertThat(root.getChildAt(0).getChildAt(0).getChildCount(), is(0));
    }

    @Test
    void shouldNormaliseNonSiteNodesWithParams() {
        // Given / When
        map.getOrAddNode("https://www.example.com/aaa/?p1=v1&p2=v2", false, false);
        map.getOrAddNode("https://www.example.com/aaa?p2=v3&p1=v4", false, false);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getUserObject().getName(), is("https://www.example.com"));
        assertThat(root.getChildAt(0).getChildCount(), is(2));
        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getName(), is("aaa"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com/aaa/"));
        assertThat(root.getChildAt(0).getChildAt(0).getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildAt(1).getUserObject().getName(), is("aaa(p1,p2)"));
        assertThat(
                root.getChildAt(0).getChildAt(1).getUserObject().getUrl(),
                is("https://www.example.com/aaa?p2=v3&p1=v4"));
        assertThat(root.getChildAt(0).getChildAt(1).getChildCount(), is(0));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getName(),
                is("/(p1,p2)"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com/aaa/?p1=v1&p2=v2"));
        assertThat(root.getChildAt(0).getChildAt(0).getChildAt(0).getChildCount(), is(0));
    }

    @Test
    void shouldAddSiteLevelFragmentNodes() {
        // Given / When
        map.getOrAddNode("https://www.example.com/?p2=v3&p1=v4#third", false, false);
        map.getOrAddNode("https://www.example.com#second", false, false);
        map.getOrAddNode("https://www.example.com/#first", false, false);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getUserObject().getName(), is("https://www.example.com"));
        assertThat(root.getChildAt(0).getChildCount(), is(3));

        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getName(), is("#"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getName(),
                is("second"));
        assertThat(
                root.getChildAt(0).getChildAt(0).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com#second"));

        assertThat(root.getChildAt(0).getChildAt(1).getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildAt(1).getUserObject().getName(), is("/#"));
        assertThat(root.getChildAt(0).getChildAt(1).getChildAt(0).getChildCount(), is(0));
        assertThat(
                root.getChildAt(0).getChildAt(1).getChildAt(0).getUserObject().getName(),
                is("first"));
        assertThat(
                root.getChildAt(0).getChildAt(1).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com/#first"));
        assertThat(root.getChildAt(0).getChildAt(1).getChildAt(0).getChildCount(), is(0));

        assertThat(root.getChildAt(0).getChildAt(2).getUserObject().getName(), is("/(p1,p2)"));
        assertThat(
                root.getChildAt(0).getChildAt(2).getUserObject().getUrl(),
                is("https://www.example.com/?p2=v3&p1=v4"));
        assertThat(root.getChildAt(0).getChildAt(2).getChildCount(), is(1));
        assertThat(
                root.getChildAt(0).getChildAt(2).getChildAt(0).getUserObject().getName(), is("#"));
        assertThat(
                root.getChildAt(0).getChildAt(2).getChildAt(0).getUserObject().getUrl(),
                is("https://www.example.com/?p2=v3&p1=v4#"));
        assertThat(root.getChildAt(0).getChildAt(2).getChildAt(0).getChildCount(), is(1));
        assertThat(
                root.getChildAt(0)
                        .getChildAt(2)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getUserObject()
                        .getName(),
                is("third"));
        assertThat(
                root.getChildAt(0)
                        .getChildAt(2)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getUserObject()
                        .getUrl(),
                is("https://www.example.com/?p2=v3&p1=v4#third"));
        assertThat(
                root.getChildAt(0).getChildAt(2).getChildAt(0).getChildAt(0).getChildCount(),
                is(0));
    }

    @Test
    void shouldClearTheMap() {
        // Given / When
        map.getOrAddNode(CCC_URL + "/", false, false);
        map.getOrAddNode(BBB_DDD_URL + "/", false, false);
        map.getOrAddNode(DDD_URL + "/", false, false);
        map.getOrAddNode(BBB_CCC_URL + "/", false, true);
        map.getOrAddNode(AAA_URL + "/", false, false);
        map.getOrAddNode(BBB_BBB_URL + "/", false, true);
        map.getOrAddNode(BBB_AAA_URL + "/", false, false);

        map.clear();

        // Then
        assertThat(map.getRoot().getChildCount(), is(0));
    }

    @Test
    void shouldSetKnownRedirectDetails() {
        // Given
        ClientNode node1 = map.getOrAddNode(BBB_DDD_URL + "/", false, false);

        // When
        ClientNode node2 = map.setRedirect(BBB_DDD_URL + "/", AAA_URL);
        Set<ClientSideComponent> components = node2.getUserObject().getComponents();
        ClientSideComponent c0 = components.iterator().next();

        // Then
        assertThat(node1, is(node2));
        assertThat(node2.getUserObject().isVisited(), is(true));
        assertThat(node2.getUserObject().isRedirect(), is(true));
        assertThat(components.size(), is(1));
        assertThat(c0.getTagName(), is("Redirect"));
        assertThat(c0.getHref(), is(AAA_URL));
    }

    @Test
    void shouldIngnoreUnknownRedirectDetails() {
        // Given / When
        ClientNode node = map.setRedirect(BBB_DDD_URL + "/", AAA_URL);

        // Then
        assertThat(node, is(nullValue()));
    }

    @Test
    void shouldAddComponentCreatingNodeIfAbsent() {
        // Given
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        null,
                        BBB_URL,
                        BBB_AAA_URL,
                        null,
                        ClientSideComponent.Type.LINK,
                        null,
                        -1);

        // When
        map.addComponent(BBB_URL, component);

        // Then
        ClientNode node = map.getNode(BBB_URL, false, false);
        assertThat(node, is(notNullValue()));
        assertThat(node.getUserObject().isVisited(), is(true));
        assertThat(node.getUserObject().getComponents(), is(Set.of(component)));
        verify(listener).nodeAdded(BBB_URL, 1, 1, 0);
        verify(listener).componentAdded(Map.of("siblings", "0", "depth", "1"), 0);
    }

    @Test
    void shouldAddComponentToExistingNode() {
        // Given
        ClientNode existing = map.getOrAddNode(BBB_URL, false, false);
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        null,
                        BBB_URL,
                        BBB_AAA_URL,
                        null,
                        ClientSideComponent.Type.LINK,
                        null,
                        -1);

        // When
        map.addComponent(BBB_URL, component);

        // Then
        assertThat(map.getNode(BBB_URL, false, false), is(existing));
        assertThat(existing.getUserObject().getComponents(), is(Set.of(component)));
        verify(listener).nodeAdded(BBB_URL, 1, 1, 0);
        verify(listener).componentAdded(Map.of("siblings", "0", "depth", "1"), 0);
    }

    @Test
    void shouldAddStorageComponentToStorageNode() {
        // Given
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "",
                        null,
                        BBB_URL,
                        null,
                        null,
                        ClientSideComponent.Type.LOCAL_STORAGE,
                        null,
                        -1);

        // When
        map.addComponent(BBB_URL, component);

        // Then
        ClientNode urlNode = map.getNode(BBB_URL, false, false);
        assertThat(urlNode, is(notNullValue()));
        assertThat(urlNode.getUserObject().getComponents(), is(Set.of(component)));
        verify(listener).nodeAdded(BBB_URL, 1, 1, 0);
        String storageUrl = urlNode.getSite() + component.getTypeForDisplay();
        ClientNode storageNode = map.getNode(storageUrl, false, true);
        assertThat(storageNode, is(notNullValue()));
        assertThat(storageNode.getUserObject().getComponents(), is(Set.of(component)));
        verify(listener, times(2)).componentAdded(Map.of("siblings", "0", "depth", "1"), 0);
    }

    @Test
    void shouldAddComponentToClientMapOnReportObject() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_OBJECT_JSON.formatted(url, null);

        // When
        map.handleReportObject(json);

        // Then
        assertThat(map.getNode(url, false, false), is(notNullValue()));
        verify(listener).nodeAdded(url, 2, 1, 0);
        verify(listener)
                .componentAdded(
                        Map.of(
                                "nodeName", "INPUT",
                                "siblings", "0",
                                "depth", "2",
                                "id", "",
                                "href", "null",
                                "tagName", "INPUT",
                                "type", "input",
                                "url", url,
                                "timestamp", "0"),
                        0);
    }

    @Test
    void shouldNotifyListenerWithCorrectSourceOnReportObject() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_OBJECT_JSON.formatted(url, null);

        // When
        map.handleReportObject(json, 42);

        // Then
        assertThat(map.getNode(url, false, false), is(notNullValue()));
        verify(listener).nodeAdded(url, 2, 1, 42);
        verify(listener)
                .componentAdded(
                        Map.of(
                                "nodeName", "INPUT",
                                "siblings", "0",
                                "depth", "2",
                                "id", "",
                                "href", "null",
                                "tagName", "INPUT",
                                "type", "input",
                                "url", url,
                                "timestamp", "0"),
                        42);
    }

    @Test
    void shouldNotAddComponentForApiUrlOnReportObject() {
        // Given
        String apiUrl = "http://zap/JSON/core/view/version/";
        String json = REPORTED_OBJECT_JSON.formatted(apiUrl, null);

        // When
        map.handleReportObject(json);

        // Then
        assertThat(map.getRoot().getChildCount(), is(0));
        verifyNoInteractions(listener);
    }

    @Test
    void shouldAddHrefNodeOnReportObject() {
        // Given
        String url = "https://www.example.com/page";
        String href = "https://www.example.com/linked";
        String json = REPORTED_OBJECT_JSON.formatted(url, "\"" + href + "\"");

        // When
        map.handleReportObject(json);

        // Then
        assertThat(map.getNode(href, false, false), is(notNullValue()));
        verify(listener).nodeAdded(url, 2, 1, 0);
        verify(listener).nodeAdded(href, 2, 2, 0);
        verify(listener)
                .componentAdded(
                        Map.of(
                                "nodeName", "INPUT",
                                "siblings", "0",
                                "depth", "2",
                                "id", "",
                                "href", href,
                                "tagName", "INPUT",
                                "type", "input",
                                "url", url,
                                "timestamp", "0"),
                        0);
    }

    @Test
    void shouldNotifyListenerWithCorrectSourceOnNodeAddedViaHref() {
        // Given
        String url = "https://www.example.com/page";
        String href = "https://www.example.com/linked";
        String json = REPORTED_OBJECT_JSON.formatted(url, "\"" + href + "\"");

        // When
        map.handleReportObject(json, 42);

        // Then
        assertThat(map.getNode(href, false, false), is(notNullValue()));
        verify(listener).nodeAdded(url, 2, 1, 42);
        verify(listener).nodeAdded(href, 2, 2, 42);
        verify(listener)
                .componentAdded(
                        Map.of(
                                "nodeName", "INPUT",
                                "siblings", "0",
                                "depth", "2",
                                "id", "",
                                "href", href,
                                "tagName", "INPUT",
                                "type", "input",
                                "url", url,
                                "timestamp", "0"),
                        42);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/relative/", "nothttp://www.example.com/"})
    void shouldNotAddNodeForNonSupportedHrefOnReportObject(String href) {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_OBJECT_JSON.formatted(url, "\"" + href + "\"");

        // When
        map.handleReportObject(json);

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildCount(), is(1));
        verify(listener).nodeAdded(url, 2, 1, 0);
    }

    @Test
    void shouldHandleReportObjectWithNoUrl() {
        // Given
        String json =
                """
                {
                  "tagName": "INPUT",
                  "id": "",
                  "type": "input",
                  "href": null,
                  "nodeName": "INPUT",
                  "timestamp": 0
                }""";

        // When
        map.handleReportObject(json);

        // Then
        assertThat(map.getRoot().getChildCount(), is(0));
        verifyNoInteractions(listener);
    }

    @Test
    void shouldSetVisitedOnReportEvent() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_EVENT_JSON.formatted(url);

        map.getOrAddNode(url, false, false);

        // When
        map.handleReportEvent(json);

        // Then
        assertThat(map.getNode(url, false, false).getUserObject().isVisited(), is(true));
        verify(listener).nodeAdded(url, 2, 1, 0);
    }

    @Test
    void shouldNotModifyClientMapForApiUrlOnReportEvent() {
        // Given
        String apiUrl = "http://zap/JSON/core/view/version/";
        String json = REPORTED_EVENT_JSON.formatted(apiUrl);

        // When
        map.handleReportEvent(json);

        // Then
        assertThat(map.getRoot().getChildCount(), is(0));
        verifyNoInteractions(listener);
    }

    @Test
    void shouldCallConsumerOnHandleReportObject() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_OBJECT_JSON.formatted(url, null);
        Consumer<ReportedObject> consumer = mock();
        map.setReportedObjectConsumer(consumer);

        // When
        map.handleReportObject(json);

        // Then
        verify(consumer).accept(any(ReportedElement.class));
        verify(listener).nodeAdded(url, 2, 1, 0);
        verify(listener)
                .componentAdded(
                        Map.of(
                                "nodeName", "INPUT",
                                "siblings", "0",
                                "depth", "2",
                                "id", "",
                                "href", "null",
                                "tagName", "INPUT",
                                "type", "input",
                                "url", url,
                                "timestamp", "0"),
                        0);
    }

    @Test
    void shouldNotifyListenerWithCorrectSourceOnComponentAdded() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_OBJECT_JSON.formatted(url, null);

        // When
        map.handleReportObject(json, 42);

        // Then
        verify(listener).nodeAdded(url, 2, 1, 42);
        verify(listener)
                .componentAdded(
                        Map.of(
                                "nodeName", "INPUT",
                                "siblings", "0",
                                "depth", "2",
                                "id", "",
                                "href", "null",
                                "tagName", "INPUT",
                                "type", "input",
                                "url", url,
                                "timestamp", "0"),
                        42);
    }

    @Test
    void shouldNotCallConsumerForApiUrlOnHandleReportObject() {
        // Given
        String apiUrl = "http://zap/JSON/core/view/version/";
        String json = REPORTED_OBJECT_JSON.formatted(apiUrl, null);
        Consumer<ReportedObject> consumer = mock();
        map.setReportedObjectConsumer(consumer);

        // When
        map.handleReportObject(json);

        // Then
        verify(consumer, never()).accept(any());
        verifyNoInteractions(listener);
    }

    @Test
    void shouldCallConsumerOnHandleReportEvent() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_EVENT_JSON.formatted(url);
        map.getOrAddNode(url, false, false);
        Consumer<ReportedObject> consumer = mock();
        map.setReportedObjectConsumer(consumer);

        // When
        map.handleReportEvent(json);

        // Then
        verify(consumer).accept(any(ReportedEvent.class));
        verify(listener).nodeAdded(url, 2, 1, 0);
    }

    @Test
    void shouldCallConsumerOnHandleReportEventWhenNodeAbsent() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_EVENT_JSON.formatted(url);
        Consumer<ReportedObject> consumer = mock();
        map.setReportedObjectConsumer(consumer);

        // When
        map.handleReportEvent(json);

        // Then
        verify(consumer).accept(any(ReportedEvent.class));
        verifyNoInteractions(listener);
    }

    @Test
    void shouldNotCallConsumerForApiUrlOnHandleReportEvent() {
        // Given
        String apiUrl = "http://zap/JSON/core/view/version/";
        String json = REPORTED_EVENT_JSON.formatted(apiUrl);
        Consumer<ReportedObject> consumer = mock();
        map.setReportedObjectConsumer(consumer);

        // When
        map.handleReportEvent(json);

        // Then
        verify(consumer, never()).accept(any());
        verifyNoInteractions(listener);
    }

    @Test
    void shouldNotThrowWhenChangingListenersDuringNotification() {
        // Given
        ClientMapListener changingListener =
                new ClientMapListener() {
                    @Override
                    public void nodeAdded(String url, int depth, int siblings, int source) {
                        map.removeListener(listener);
                    }

                    @Override
                    public void componentAdded(Map<String, String> parameters, int source) {
                        map.addListener(mock(ClientMapListener.class));
                    }
                };
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        null,
                        AAA_URL,
                        BBB_URL,
                        null,
                        ClientSideComponent.Type.LINK,
                        null,
                        -1);
        map.addListener(changingListener);

        // When / Then
        assertDoesNotThrow(
                () -> {
                    map.getOrAddNode(AAA_URL, false, false);
                    map.addComponent(AAA_URL, component);
                });
    }

    @Test
    void shouldAddGraphEdgeForLinkComponent() {
        // Given
        String url = "https://www.example.com/page";
        String href = "https://www.example.com/linked";
        String json =
                """
                {
                  "tagName": "A",
                  "id": "link1",
                  "type": "link",
                  "url": "%s",
                  "href": "%s",
                  "nodeName": "A",
                  "text": "Click here",
                  "timestamp": 0
                }"""
                        .formatted(url, href);

        // When
        map.handleReportObject(json);

        // Then
        var graph = map.getGraph();
        var sourceVertex = new ClientGraphVertex.Url(url);
        var targetVertex = new ClientGraphVertex.Url(href);
        assertThat(graph.containsVertex(sourceVertex), is(true));
        assertThat(graph.containsVertex(targetVertex), is(true));
        assertThat(graph.vertexSet().size(), is(3));
        assertThat(graph.edgeSet().size(), is(2));
        assertThat(graph.containsEdge(sourceVertex, targetVertex), is(false));
        long componentVertices =
                graph.vertexSet().stream()
                        .filter(ClientGraphVertex.Component.class::isInstance)
                        .count();
        assertThat(componentVertices, is(1L));
    }

    @Test
    void shouldNotAddGraphEdgeForNonLinkComponent() {
        // Given
        String url = "https://www.example.com/page";
        String json = REPORTED_OBJECT_JSON.formatted(url, null);

        // When
        map.handleReportObject(json);

        // Then
        assertThat(map.getGraph().edgeSet().size(), is(0));
        assertThat(map.getGraph().vertexSet().size(), is(0));
    }

    @Test
    void shouldNotAddGraphEdgeForNonHttpHref() {
        // Given
        String url = "https://www.example.com/page";
        String json =
                """
                {
                  "tagName": "A",
                  "id": "",
                  "type": "link",
                  "url": "%s",
                  "href": "/relative/path",
                  "nodeName": "A",
                  "timestamp": 0
                }"""
                        .formatted(url);

        // When
        map.handleReportObject(json);

        // Then
        assertThat(map.getGraph().edgeSet().size(), is(0));
    }

    @Test
    void shouldAllowMultipleEdgesBetweenSameUrls() {
        // Given
        String url = "https://www.example.com/page";
        String href = "https://www.example.com/linked";
        String json1 =
                """
                {
                  "tagName": "A",
                  "id": "link1",
                  "type": "link",
                  "url": "%s",
                  "href": "%s",
                  "nodeName": "A",
                  "text": "First link",
                  "timestamp": 0
                }"""
                        .formatted(url, href);
        String json2 =
                """
                {
                  "tagName": "A",
                  "id": "link2",
                  "type": "link",
                  "url": "%s",
                  "href": "%s",
                  "nodeName": "A",
                  "text": "Second link",
                  "timestamp": 0
                }"""
                        .formatted(url, href);

        // When
        map.handleReportObject(json1);
        map.handleReportObject(json2);

        // Then
        var graph = map.getGraph();
        assertThat(graph.vertexSet().size(), is(4));
        assertThat(graph.edgeSet().size(), is(4));
    }

    @Test
    void shouldClearGraph() {
        // Given
        String url = "https://www.example.com/page";
        String href = "https://www.example.com/linked";
        String json =
                """
                {
                  "tagName": "A",
                  "id": "",
                  "type": "link",
                  "url": "%s",
                  "href": "%s",
                  "nodeName": "A",
                  "timestamp": 0
                }"""
                        .formatted(url, href);
        map.handleReportObject(json);

        // When
        map.clear();

        // Then
        assertThat(map.getGraph().vertexSet().size(), is(0));
        assertThat(map.getGraph().edgeSet().size(), is(0));
    }

    @Test
    void shouldTraverseGraphFromUrlThroughComponentToUrl() {
        // Given
        String url = "https://www.example.com/page";
        String href = "https://www.example.com/linked";
        String json =
                """
                {
                  "tagName": "A",
                  "id": "nav",
                  "type": "link",
                  "url": "%s",
                  "href": "%s",
                  "nodeName": "A",
                  "text": "Navigate",
                  "timestamp": 0
                }"""
                        .formatted(url, href);
        map.handleReportObject(json);

        // When
        var graph = map.getGraph();
        var sourceVertex = new ClientGraphVertex.Url(url);
        var outEdges = graph.outgoingEdgesOf(sourceVertex);

        // Then
        assertThat(outEdges.size(), is(1));
        var componentVertex = graph.getEdgeTarget(outEdges.iterator().next());
        assertThat(componentVertex, is(notNullValue()));
        assertThat(componentVertex instanceof ClientGraphVertex.Component, is(true));
        var componentOutEdges = graph.outgoingEdgesOf(componentVertex);
        assertThat(componentOutEdges.size(), is(1));
        var targetVertex = graph.getEdgeTarget(componentOutEdges.iterator().next());
        assertThat(targetVertex, is(new ClientGraphVertex.Url(href)));
    }
}
