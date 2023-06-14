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
package org.zaproxy.addon.clent;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.ClientMap;
import org.zaproxy.addon.client.ClientNode;
import org.zaproxy.addon.client.ClientSideDetails;

class ClientMapUnitTest {

    private static final String AAA_URL = "https://aaa.com";
    private static final String BBB_URL = "https://bbb.com";
    private static final String CCC_URL = "https://ccc.com";
    private static final String DDD_URL = "https://ddd.com";

    private static final String BBB_AAA_URL = "https://bbb.com/aaa";
    private static final String BBB_BBB_URL = "https://bbb.com/bbb";
    private static final String BBB_CCC_URL = "https://bbb.com/ccc";
    private static final String BBB_DDD_URL = "https://bbb.com/ddd";

    @Test
    void shouldAddOrderedNodes() {
        // Given
        ClientMap map = new ClientMap(new ClientNode(new ClientSideDetails("Root", ""), false));

        // When
        map.getOrAddNode(CCC_URL + "/", false);
        map.getOrAddNode(BBB_DDD_URL + "/", false);
        map.getOrAddNode(DDD_URL + "/", false);
        map.getOrAddNode(BBB_CCC_URL + "/", false);
        map.getOrAddNode(AAA_URL + "/", false);
        map.getOrAddNode(BBB_BBB_URL + "/", false);
        map.getOrAddNode(BBB_AAA_URL + "/", false);

        ClientNode root = map.getRoot();

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
        assertThat(root.getChildAt(1).getChildAt(0).getUserObject().getUrl(), is(BBB_AAA_URL));
    }

    @Test
    void shouldAddStorageAtEnd() {
        // Given
        ClientMap map = new ClientMap(new ClientNode(new ClientSideDetails("Root", ""), false));

        // When
        map.getOrAddNode(BBB_DDD_URL + "/", false);
        map.getOrAddNode(BBB_CCC_URL + "/", true);
        map.getOrAddNode(BBB_BBB_URL + "/", false);
        map.getOrAddNode(BBB_AAA_URL + "/", true);

        ClientNode root = map.getRoot();

        // Then
        assertThat(root.getChildCount(), is(1));
        assertThat(root.getChildAt(0).getChildCount(), is(4));
        assertThat(root.getChildAt(0).getSite(), is(BBB_URL + "/"));
        assertThat(root.getChildAt(0).getUserObject().getName(), is(BBB_URL));
        assertThat(root.getChildAt(0).getUserObject().getUrl(), is(BBB_URL + "/"));
        assertThat(root.getChildAt(0).getChildCount(), is(4));

        assertThat(root.getChildAt(0).getChildAt(0).getUserObject().getUrl(), is(BBB_BBB_URL));
        assertThat(root.getChildAt(0).getChildAt(1).getUserObject().getUrl(), is(BBB_DDD_URL));
        assertThat(root.getChildAt(0).getChildAt(2).getUserObject().getUrl(), is(BBB_AAA_URL));
        assertThat(root.getChildAt(0).getChildAt(3).getUserObject().getUrl(), is(BBB_CCC_URL));
    }

    @Test
    void shouldClearTheMap() {
        // Given
        ClientMap map = new ClientMap(new ClientNode(new ClientSideDetails("Root", ""), false));

        // When
        map.getOrAddNode(CCC_URL + "/", false);
        map.getOrAddNode(BBB_DDD_URL + "/", false);
        map.getOrAddNode(DDD_URL + "/", false);
        map.getOrAddNode(BBB_CCC_URL + "/", true);
        map.getOrAddNode(AAA_URL + "/", false);
        map.getOrAddNode(BBB_BBB_URL + "/", true);
        map.getOrAddNode(BBB_AAA_URL + "/", false);

        map.clear();

        // Then
        assertThat(map.getRoot().getChildCount(), is(0));
    }
}
