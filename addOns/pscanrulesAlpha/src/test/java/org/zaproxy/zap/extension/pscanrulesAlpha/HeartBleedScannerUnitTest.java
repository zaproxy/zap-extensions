package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/** Unit test for {@link HeartBleedScanner}. */
public class HeartBleedScannerUnitTest extends PassiveScannerTest<HeartBleedScanner> {
    @Override
    protected HeartBleedScanner createScanner() {
        return new HeartBleedScanner();
    }

    /**
     * Scanning Response headers for HeartBleed OpenSSL issue and validates number of fired alerts.
     * @param expectedAlertCount Number of alerts that would be raised
     * @param serverHeaders Headers that starts with "Server:" and contains OpenSSL line to match
     * @throws HttpMalformedHeaderException When Server Headers are malformed
     */
    private void scanHeaderAndValidateAlertsCount(int expectedAlertCount, String serverHeaders)
            throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + serverHeaders);

        try {
            URI testURI = new URI("http://example.com", false);
            msg.getRequestHeader().setURI(testURI);
        } catch (URIException e) {
            //Do nothing, since it would resolve always to example.com
        }

        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), is(expectedAlertCount));
    }

    @Test
    public void shouldAlertOnVersion101c() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(1,
                "Server: Apache/2.4.3 (Win32) OpenSSL/1.0.1c PHP/5.4.7");
    }

    @Test
    public void shouldNotAlertOnVersion1012k() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: (CentOS) PHP/5.4.16 OpenSSL/1.0.2k PHP/5.4.7");
    }

    @Test
    public void shouldNotAlertOnVersion0980() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: Apache/2.2.22 (Unix) mod_ssl/2.2.22 OpenSSL/0.9.8o DAV/2 PHP/5.3");
    }

    @Test
    public void shouldNotAlertOnLowerVersion() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: Apache/2.4.3 (Win32) OpenSSL/0.9.8-pre-reformat PHP/5.4.7");
    }

    @Test
    public void shouldNotAlertOnHigherVersion() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: Apache/2.4.3 (Win32) OpenSSL/1.0.2 PHP/5.4.7");
    }

    @Test
    public void shouldNotAlertOnVersion101eFips() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: Apache/2.4.29 (Unix) mod_ssl/2.2.22 OpenSSL/1.0.1e-fips PHP/5.4");
    }

    @Test
    public void shouldNotAlertOnVersion102kFips() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips Location");
    }

    @Test
    public void shouldNotAlertOnVersion206kFips() throws HttpMalformedHeaderException {
        scanHeaderAndValidateAlertsCount(0,
                "Server: Apache/2.4.6 (CentOS) OpenSSL/2.0.6-fips Location");
    }
}