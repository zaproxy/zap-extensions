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
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.Locale;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link SitesTreeResource}. */
class SitesTreeResourceUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private Model model;
    private Session session;
    private SiteMap siteMap;
    private SitesTreeResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        siteMap = mock(SiteMap.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        given(session.getSiteTree()).willReturn(siteMap);
        Model.setSingletonForTesting(model);
        resource = new SitesTreeResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        // Given / When / Then
        assertThat(resource.getUri(), equalTo("zap://sites-tree"));
        assertThat(resource.getName(), equalTo("sites-tree"));
    }

    @Test
    void shouldReturnEmptyArrayWhenRootIsNull() {
        // Given
        given(siteMap.getRoot()).willReturn(null);

        // When
        String content = resource.readContent();

        // Then
        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnSitesNodeWhenEmptyTree() throws Exception {
        // Given
        SiteNode root = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));
        given(siteMap.getRoot()).willReturn(root);
        given(root.getParent()).willReturn(null);
        given(root.toString()).willReturn("Sites");
        given(root.getHistoryReference()).willReturn(null);
        given(root.getChildCount()).willReturn(0);
        given(root.children()).willReturn(Collections.emptyEnumeration());

        // When / Then
        assertThat(resource.readContent(), equalTo("[{\"node\":\"Sites\"}]"));
    }

    @Test
    void shouldReturnNodeWithUrlAndMethodWhenHasHistoryReference() throws Exception {
        // Given
        SiteNode root = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));
        SiteNode child = mock(SiteNode.class, withSettings().strictness(Strictness.LENIENT));
        HistoryReference href =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));

        given(siteMap.getRoot()).willReturn(root);
        given(root.getParent()).willReturn(null);
        given(root.toString()).willReturn("Sites");
        given(root.getHistoryReference()).willReturn(null);
        given(root.getChildCount()).willReturn(1);
        given(root.children())
                .willReturn(Collections.enumeration(Collections.singletonList(child)));

        given(child.getParent()).willReturn(root);
        given(child.toString()).willReturn("https://example.com");
        given(child.getHistoryReference()).willReturn(href);
        given(child.getChildCount()).willReturn(0);
        given(child.children()).willReturn(Collections.emptyEnumeration());

        given(href.getURI()).willReturn(new URI("https://example.com/", true));
        given(href.getMethod()).willReturn("GET");
        given(href.getStatusCode()).willReturn(200);
        given(href.getResponseHeaderLength()).willReturn(20);
        given(href.getResponseBodyLength()).willReturn(100);

        // When / Then
        assertThat(
                resource.readContent(),
                equalTo(
                        "[{\"node\":\"Sites\",\"children\":[{\"node\":\"https://example.com\",\"url\":\"https://example.com/\",\"method\":\"GET\",\"responseLength\":122,\"statusCode\":200}]}]"));
    }
}
