/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class JSFunctionPassiveScannerUnitTest extends PassiveScannerTest<JSFunctionPassiveScanner> {

    @Override
    protected JSFunctionPassiveScanner createScanner() {
        return new JSFunctionPassiveScanner();
    }

    @Override
    public void setUpZap() throws Exception {
        super.setUpZap();

        Path xmlDir =
                Files.createDirectories(
                        Paths.get(Constant.getZapHome(), JSFunctionPassiveScanner.FUNC_LIST_DIR));
        Path testFile = xmlDir.resolve(JSFunctionPassiveScanner.FUNC_LIST_FILE);
        Files.write(
                testFile, Arrays.asList("# Test File", "bypassSecurityTrustScript", "trustAsHtml"));
    }

    @Test
    public void shouldRaiseAlertGivenMatch() throws HttpMalformedHeaderException, URIException {
        // Given
        String body = "Some text <script>bypassSecurityTrustScript</script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        Source source = createSource(msg);

        // When
        rule.scanHttpResponseReceive(msg, -1, source);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldNotRaiseAlertGivenNoMatch()
            throws URIException, HttpMalformedHeaderException {
        // Given
        String body = "Some text <script>innocent script</script>\nLine 2\n";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        Source source = createSource(msg);

        // When
        rule.scanHttpResponseReceive(msg, -1, source);

        // Then
        assertThat(alertsRaised, empty());
    }

    private HttpMessage createHttpMessageWithRespBody(String responseBody)
            throws HttpMalformedHeaderException, URIException {

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseBody(responseBody);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: "
                        + "text/javascript;charset=ISO-8859-1"
                        + "\r\n"
                        + "Content-Length: "
                        + responseBody.length()
                        + "\r\n");
        return msg;
    }
}
