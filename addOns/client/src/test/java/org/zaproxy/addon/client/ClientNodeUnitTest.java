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
package org.zaproxy.addon.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.model.StandardParameterParser;

class ClientNodeUnitTest {

    private static final String EXAMPLE_COM = "https://www.example.com";

    private ClientNode root;
    private ClientMap map;

    @BeforeEach
    void setUp() {
        Session session = mock(Session.class);
        StandardParameterParser ssp = new StandardParameterParser();
        given(session.getUrlParamParser(any(String.class))).willReturn(ssp);
        root = new ClientNode(new ClientSideDetails("Root", ""), session);
        map = new ClientMap(root);
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterPublisher(map);
    }

    @ParameterizedTest
    @ValueSource(strings = {EXAMPLE_COM, EXAMPLE_COM + "2", EXAMPLE_COM + "3"})
    void shouldGetRootChild(String childName) {
        // Given
        map.getOrAddNode(EXAMPLE_COM + "3", false, false);
        map.getOrAddNode(EXAMPLE_COM, false, false);
        map.getOrAddNode(EXAMPLE_COM + "2", false, false);

        // When
        ClientNode child = root.getChild(childName, false);

        // Then
        assertNotNull(child);
        assertThat(child.getUserObject().getName(), is(childName));
    }

    @ParameterizedTest
    @ValueSource(strings = {"cccc", "bbb", "aa"})
    void shouldGetNonRootChild(String childName) {
        // Given
        map.getOrAddNode(EXAMPLE_COM, false, false);
        map.getOrAddNode(EXAMPLE_COM + "/cccc", false, false);
        map.getOrAddNode(EXAMPLE_COM + "/bbb", false, false);
        map.getOrAddNode(EXAMPLE_COM + "/aa", false, false);

        // When
        ClientNode site = root.getChild(EXAMPLE_COM, false);
        assertNotNull(site);
        ClientNode child = site.getChild(childName, false);

        // Then
        assertNotNull(child);
        assertThat(child.getUserObject().getName(), is(childName));
    }

    @Test
    void shouldNotGetNonStorageChild() {
        // Given
        map.getOrAddNode(EXAMPLE_COM, false, false);
        map.getOrAddNode(EXAMPLE_COM + "/cccc", false, false);
        map.getOrAddNode(EXAMPLE_COM + "/bbb", false, true);
        map.getOrAddNode(EXAMPLE_COM + "/aa", false, false);

        // When
        ClientNode site = root.getChild(EXAMPLE_COM, false);
        assertNotNull(site);
        ClientNode child = site.getChild("bbb", false);

        // Then
        assertNull(child);
    }

    @Test
    void shouldGetNonStorageChild() {
        // Given
        map.getOrAddNode(EXAMPLE_COM, false, false);
        map.getOrAddNode(EXAMPLE_COM + "/cccc", false, false);
        map.getOrAddNode(EXAMPLE_COM + "/bbb", false, true);
        map.getOrAddNode(EXAMPLE_COM + "/aa", false, false);

        // When
        ClientNode site = root.getChild(EXAMPLE_COM, false);
        assertNotNull(site);
        ClientNode child = site.getChild("bbb", true);

        // Then
        assertNotNull(child);
        assertThat(child.getUserObject().getName(), is("bbb"));
        assertThat(child.getUserObject().isStorage(), is(true));
    }

    @Test
    void shouldGetSite() {
        // Given
        map.getOrAddNode(EXAMPLE_COM + "/aaa/bbb/ccc?aa=bb#f", false, false);

        // When
        ClientNode site = root.getChild(EXAMPLE_COM, false);

        // Then
        assertNotNull(site);
        assertThat(site.getSite(), is(EXAMPLE_COM + "/"));
        assertThat(site.getChildCount(), is(1));
        assertThat(site.getChildAt(0).getSite(), is(EXAMPLE_COM + "/"));
        assertThat(site.getChildAt(0).getChildCount(), is(1));
        assertThat(site.getChildAt(0).getChildAt(0).getSite(), is(EXAMPLE_COM + "/"));
        assertThat(site.getChildAt(0).getChildAt(0).getChildCount(), is(1));
        assertThat(site.getChildAt(0).getChildAt(0).getChildAt(0).getSite(), is(EXAMPLE_COM + "/"));
        assertThat(site.getChildAt(0).getChildAt(0).getChildAt(0).getChildCount(), is(1));
        assertThat(
                site.getChildAt(0).getChildAt(0).getChildAt(0).getChildAt(0).getSite(),
                is(EXAMPLE_COM + "/"));
        assertThat(
                site.getChildAt(0).getChildAt(0).getChildAt(0).getChildAt(0).getChildCount(),
                is(1));
        assertThat(
                site.getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getSite(),
                is(EXAMPLE_COM + "/"));
        assertThat(
                site.getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildCount(),
                is(0));
    }

    @Test
    void shouldGetSession() {
        // Given
        map.getOrAddNode(EXAMPLE_COM + "/aaa/bbb/ccc?aa=bb#f", false, false);

        // When
        ClientNode site = root.getChild(EXAMPLE_COM, false);

        // Then
        assertNotNull(site);
        assertNotNull(site.getSession());
        assertThat(site.getChildCount(), is(1));
        assertNotNull(site.getChildAt(0).getSession());
        assertThat(site.getChildAt(0).getChildCount(), is(1));
        assertNotNull(site.getChildAt(0).getChildAt(0).getSession());
        assertThat(site.getChildAt(0).getChildAt(0).getChildCount(), is(1));
        assertNotNull(site.getChildAt(0).getChildAt(0).getChildAt(0).getSession());
        assertThat(site.getChildAt(0).getChildAt(0).getChildAt(0).getChildCount(), is(1));
        assertNotNull(site.getChildAt(0).getChildAt(0).getChildAt(0).getChildAt(0).getSession());
        assertThat(
                site.getChildAt(0).getChildAt(0).getChildAt(0).getChildAt(0).getChildCount(),
                is(1));
        assertNotNull(
                site.getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getSession());
        assertThat(
                site.getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildAt(0)
                        .getChildCount(),
                is(0));
    }
}
