/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zest.core.v1.ZestRequest;

/** Unit test for {@link ZestZapUtils}. */
public class ZestZapUtilsUnitTest {

    @Test
    public void shouldKeepAllHeadersIfIncludingAllWhenConvertingHttpMessageToZestRequest()
            throws Exception {
        // Given
        boolean includeAllHeaders = true;
        ZestParam zestParam = createZestParam();
        zestParam.setIgnoredHeaders(Arrays.asList("B"));
        String headers = "A: 1\r\nB: 2\r\nHost: example.com\r\n";
        HttpMessage httpMessage = createRequest(headers);
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, false, includeAllHeaders, zestParam);
        // Then
        assertThat(zestRequest.getHeaders(), is(equalTo(headers)));
    }

    @Test
    public void shouldRemoveIgnoredHeadersIfNotIncludingAllWhenConvertingHttpMessageToZestRequest()
            throws Exception {
        // Given
        boolean includeAllHeaders = false;
        ZestParam zestParam = createZestParam();
        zestParam.setIgnoredHeaders(Arrays.asList("B"));
        HttpMessage httpMessage = createRequest("A: 1\r\nB: 2\r\nHost: example.com\r\n");
        // When
        ZestRequest zestRequest =
                ZestZapUtils.toZestRequest(httpMessage, false, includeAllHeaders, zestParam);
        // Then
        assertThat(zestRequest.getHeaders(), is(equalTo("A: 1\r\nHost: example.com\r\n")));
    }

    private static ZestParam createZestParam() {
        ZestParam zestParam = new ZestParam();
        zestParam.load(new ZapXmlConfiguration());
        return zestParam;
    }

    private static HttpMessage createRequest(String headers) throws HttpMalformedHeaderException {
        return new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1\r\n" + headers));
    }
}
