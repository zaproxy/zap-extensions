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
package org.zaproxy.addon.mcp.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link SitesResource}. */
class SitesResourceUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private Model model;
    private Session session;
    private SiteMap siteMap;
    private SitesResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        siteMap = mock(SiteMap.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        given(session.getSiteTree()).willReturn(siteMap);
        Model.setSingletonForTesting(model);
        resource = new SitesResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://sites"));
        assertThat(resource.getName(), equalTo("sites"));
    }

    @Test
    void shouldReturnEmptyArrayWhenRootIsNull() {
        given(siteMap.getRoot()).willReturn(null);

        String content = resource.readContent();

        assertThat(parseJsonArray(content).size(), equalTo(0));
    }

    @Test
    void shouldReturnEmptyArrayWhenRootHasNoChildren() {
        SiteNode root = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));
        given(siteMap.getRoot()).willReturn(root);
        given(root.getChildCount()).willReturn(0);

        String content = resource.readContent();

        assertThat(parseJsonArray(content).size(), equalTo(0));
    }

    @Test
    void shouldReturnTopLevelSitesWhenRootHasChildren() {
        SiteNode root = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));
        SiteNode child1 = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));
        SiteNode child2 = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));

        given(siteMap.getRoot()).willReturn(root);
        given(root.getChildCount()).willReturn(2);
        given(root.getFirstChild()).willReturn(child1);
        given(child1.getNextSibling()).willReturn(child2);
        given(child2.getNextSibling()).willReturn(null);
        given(child1.getHierarchicNodeName()).willReturn("https://example.com");
        given(child2.getHierarchicNodeName()).willReturn("https://other.com");

        String content = resource.readContent();
        JsonNode array = parseJsonArray(content);

        assertThat(array.size(), equalTo(2));
        List<String> sites = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            sites.add(array.get(i).asText());
        }
        assertThat(sites, containsInAnyOrder("https://example.com", "https://other.com"));
    }

    private static JsonNode parseJsonArray(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON: " + json, e);
        }
    }
}
