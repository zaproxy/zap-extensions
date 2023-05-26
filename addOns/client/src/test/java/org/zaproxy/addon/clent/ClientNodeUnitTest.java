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

class ClientNodeUnitTest {

    private static final String AAA_URL = "https://aaa.com";
    private static final String BBB_URL = "https://bbb.com";

    private static final String BBB_AAA_URL = "https://bbb.com/aaa";

    @Test
    void shouldReturnSite() {
        // Given
        ClientMap map = new ClientMap(new ClientNode(new ClientSideDetails("Root", ""), false));

        // When
        map.getOrAddNode(AAA_URL + "/", false);
        map.getOrAddNode(AAA_URL + "/ccc", false);
        map.getOrAddNode(AAA_URL + "/ddd?ee", false);
        map.getOrAddNode(BBB_AAA_URL + "/", false);
        map.getOrAddNode(BBB_AAA_URL + "/#fff", false);

        ClientNode root = map.getRoot();

        // Then
        assertThat(root.getChildCount(), is(2));
        assertThat(root.getChildAt(0).getChildCount(), is(2));
        assertThat(root.getChildAt(0).getSite(), is(AAA_URL + "/"));
        assertThat(root.getChildAt(0).getChildAt(0).getSite(), is(AAA_URL + "/"));
        assertThat(root.getChildAt(0).getChildAt(1).getSite(), is(AAA_URL + "/"));
        assertThat(root.getChildAt(1).getChildCount(), is(1));
        assertThat(root.getChildAt(1).getSite(), is(BBB_URL + "/"));
        assertThat(root.getChildAt(1).getChildAt(0).getSite(), is(BBB_URL + "/"));
    }
}
