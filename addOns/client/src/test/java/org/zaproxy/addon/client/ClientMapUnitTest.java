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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.model.StandardParameterParser;

class ClientMapUnitTest {

    private static final String AAA_URL = "https://aaa.com";
    private static final String BBB_URL = "https://bbb.com";
    private static final String CCC_URL = "https://ccc.com";
    private static final String DDD_URL = "https://ddd.com";

    private static final String BBB_AAA_URL = "https://bbb.com/aaa";
    private static final String BBB_BBB_URL = "https://bbb.com/bbb";
    private static final String BBB_CCC_URL = "https://bbb.com/ccc";
    private static final String BBB_DDD_URL = "https://bbb.com/ddd";

    private ClientNode root;
    ClientMap map;

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
        System.out.println(root.getChildAt(0).getChildAt(2).getChildAt(0).getUserObject().getUrl());
        System.out.println("https://www.example.com/?p2=v3&p1=v4#/");
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
}
