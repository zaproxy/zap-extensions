/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockSettings;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientPassiveScanHelper}. */
class ClientPassiveScanHelperUnitTest extends TestUtils {

    private static final MockSettings LENIENT = withSettings().strictness(Strictness.LENIENT);
    private ExtensionAlert extAlert;
    private ExtensionHistory extHistory;

    private ClientPassiveScanHelper helper;

    @BeforeEach
    void setup() {
        mockMessages(new ExtensionClientIntegration());

        extHistory = mock(ExtensionHistory.class, LENIENT);
        extAlert = mock(ExtensionAlert.class, LENIENT);

        helper = new ClientPassiveScanHelper(extAlert, extHistory);
    }

    @Test
    void shouldFindHistoryRef() throws Exception {
        // Given
        Model model = mock();
        given(extHistory.getModel()).willReturn(model);
        Session session = mock();
        given(model.getSession()).willReturn(session);
        SiteMap siteTree = mock();
        given(session.getSiteTree()).willReturn(siteTree);
        SiteNode siteNode = mock();
        String url = "http://example.com/";
        given(siteTree.findNode(new URI(url, true))).willReturn(siteNode);
        HistoryReference href = mockHistoryReference(url);
        given(siteNode.getHistoryReference()).willReturn(href);
        // When
        HistoryReference foundHref = helper.findHistoryRef(url);
        // Then
        assertThat(foundHref, is(equalTo(href)));
    }

    @Test
    void shouldNotFindHistoryRefIfNotPresent() throws Exception {
        // Given
        Model model = mock();
        given(extHistory.getModel()).willReturn(model);
        Session session = mock();
        given(model.getSession()).willReturn(session);
        SiteMap siteTree = mock();
        given(session.getSiteTree()).willReturn(siteTree);
        String url = "http://example.com/";
        given(siteTree.findNode(new URI(url, true))).willReturn(null);
        // When
        HistoryReference foundHref = helper.findHistoryRef(url);
        // Then
        assertThat(foundHref, is(nullValue()));
    }

    private static HistoryReference mockHistoryReference(String url) throws URIException {
        HistoryReference href = mock(HistoryReference.class, LENIENT);
        given(href.getURI()).willReturn(new URI(url, true));
        return href;
    }

    @ParameterizedTest
    @ValueSource(strings = {"test123", "{\"'\\:, []]", "@!£$%^&*(_)\n\r\t\\u00A9"})
    void shouldDecodePrintableBase64Strings(String str) {
        // Given / When
        String decoded = ClientPassiveScanHelper.base64Decode(base64Encode(str));
        // Then
        assertThat(decoded, is(str));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u0000", "\b", ""})
    void shouldNotDecodeUnprintableBase64Strings(String str) {
        // Given / When
        String decoded = ClientPassiveScanHelper.base64Decode(base64Encode(str));
        // Then
        assertThat(decoded, is(nullValue()));
    }

    private static String base64Encode(String str) {
        return Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }
}
