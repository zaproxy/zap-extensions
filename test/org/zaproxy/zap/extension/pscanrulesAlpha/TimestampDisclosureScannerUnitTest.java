package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import static org.junit.Assert.assertEquals;

public class TimestampDisclosureScannerUnitTest extends PassiveScannerTest  {
    private HttpMessage msg;

    // Hashes in lower case for "guest" without quotes
    private static final String GUEST_MD5 = "084e0343a0486ff05530df6c705c8bb4";
    private static final String GUEST_SHA1 = "84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec";

    @Before
    public void before() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
    }

    @Override
    protected PluginPassiveScanner createScanner() {
        return new TimestampDisclosureScanner();
    }

    @Test
    public void shouldNotRaiseAlertOnSTSHeader() throws Exception {
        // Given
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n" + "Strict-Transport-Security: max-age=15552000; includeSubDomains\r\n");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

}
