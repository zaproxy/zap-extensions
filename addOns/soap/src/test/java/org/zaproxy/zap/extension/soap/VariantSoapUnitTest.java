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
package org.zaproxy.zap.extension.soap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link VariantSoap}. */
class VariantSoapUnitTest {

    private HttpMessage msg;
    private VariantSoap variant;

    @BeforeEach
    void setUp() throws Exception {
        variant = new VariantSoap();
        msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://www.example.org/temp", true));
        msg.setRequestBody(
                "<?xml version=\"1.0\"?>\n"
                        + "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" soap:encodingStyle=\"http://www.w3.org/2003/05/soap-encoding\">\n"
                        + "<soap:Body xmlns:m=\"http://www.example.org/temp\">\n"
                        + "  <m:GetTemp>\n"
                        + "    <m:Location>Sun</m:Location>\n"
                        + "  </m:GetTemp>\n"
                        + "</soap:Body>\n"
                        + "</soap:Envelope>");
    }

    @Test
    void shouldHaveNoParameters() {
        // Given / When
        variant.setMessage(msg);
        // Then
        assertThat(variant.getParamList(), is(empty()));
    }

    @Test
    void shouldUseDefaultLeafName() {
        // Given / When
        String leafName = variant.getLeafName("nodeName", msg);
        // Then
        assertThat(leafName, is(nullValue()));
    }

    @Test
    void shouldReturnTreePathForSoapMessage() throws URIException {
        // Given / When
        List<String> treePath = variant.getTreePath(msg);
        // Then
        assertThat(treePath, is(contains("temp", "GetTemp (v1.2)")));
    }

    @Test
    void shouldReturnDefaultPathForNonSoapMessage() throws URIException {
        // Given
        msg = new HttpMessage();
        // When
        List<String> treePath = variant.getTreePath(msg);
        // Then
        assertThat(treePath, is(nullValue()));
    }
}
