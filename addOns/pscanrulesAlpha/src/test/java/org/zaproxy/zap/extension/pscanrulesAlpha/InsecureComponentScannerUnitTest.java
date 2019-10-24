/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.util.LinkedList;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class InsecureComponentScannerUnitTest extends PassiveScannerTest<InsecureComponentScanner> {

    @BeforeClass
    public static void setupVulnerabilities() {

        VulnerabilityCache cache = VulnerabilityCache.getSingleton();

        LinkedList<CVE> phpVulnerabilitites = new LinkedList<CVE>();
        phpVulnerabilitites.add(new CVE("insecure", Double.valueOf(7.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_WEBSERVER, "", "PHP", "2.5.0"),
                phpVulnerabilitites);
        LinkedList<CVE> apacheVulnerabilitites = new LinkedList<CVE>();
        apacheVulnerabilitites.add(new CVE("insecure", Double.valueOf(7.0D)));
        cache.add(
                new Product(
                        Product.ProductType.PRODUCTTYPE_WEBSERVER, "Red Hat", "Apache", "1.5.0"),
                apacheVulnerabilitites);

        LinkedList<CVE> perl4Vulnerabilitites = new LinkedList<CVE>();
        perl4Vulnerabilitites.add(new CVE("insecure", Double.valueOf(7.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_APACHE_MODULE, "", "Perl", "4.0.0"),
                perl4Vulnerabilitites);

        LinkedList<CVE> perl5Vulnerabilitites = new LinkedList<CVE>();
        perl5Vulnerabilitites.add(new CVE("code injection", Double.valueOf(8.0D)));
        perl5Vulnerabilitites.add(new CVE("insecure", Double.valueOf(7.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_APACHE_MODULE, "", "Perl", "5.0.0"),
                perl5Vulnerabilitites);

        LinkedList<CVE> generatorVulnerabilitites = new LinkedList<CVE>();
        generatorVulnerabilitites.add(new CVE("man in the middle", Double.valueOf(4.0D)));
        cache.add(
                new Product(
                        Product.ProductType.PRODUCTTYPE_CONTENT_GENERATOR,
                        "",
                        "Frontweaver",
                        "1.2.0"),
                generatorVulnerabilitites);

        LinkedList<CVE> oracleVulnerabilitites = new LinkedList<CVE>();
        oracleVulnerabilitites.add(new CVE("man in the middle", Double.valueOf(4.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_WEBSERVER, "", "Oracle", "2.4.0"),
                oracleVulnerabilitites);

        LinkedList<CVE> jettyVulnerabilitites = new LinkedList<CVE>();
        jettyVulnerabilitites.add(new CVE("man in the middle", Double.valueOf(8.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_WEBSERVER, "", "Jetty", "2.4.0"),
                jettyVulnerabilitites);

        LinkedList<CVE> jbossVulnerabilitites = new LinkedList<CVE>();
        jbossVulnerabilitites.add(new CVE("man in the middle", Double.valueOf(4.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_WEBSERVER, "", "JBoss", "5.0.0"),
                jbossVulnerabilitites);

        LinkedList<CVE> tomcatVulnerabilitites = new LinkedList<CVE>();
        tomcatVulnerabilitites.add(new CVE("man in the middle", Double.valueOf(4.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_WEBSERVER, "", "Tomcat", "9.1.0"),
                tomcatVulnerabilitites);

        LinkedList<CVE> proxyVulnerabilitites = new LinkedList<CVE>();
        proxyVulnerabilitites.add(new CVE("ddos attack", Double.valueOf(4.0D)));
        cache.add(
                new Product(Product.ProductType.PRODUCTTYPE_PROXY_SERVER, "", "proxy", "3.0"),
                tomcatVulnerabilitites);
    }

    private HttpMessage createMessage() throws URIException, HttpMalformedHeaderException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMethod("GET");
        requestHeader.setURI(new URI("https://example.com/fred/", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected InsecureComponentScanner createScanner() {
        return new InsecureComponentScanner();
    }

    private void assertVulnerabilityAlertRaised(int expectedRiskLevel, String expectedEvidence) {
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(expectedRiskLevel));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(expectedEvidence));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecurePHPVersionUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: PHP/2.5.0-RC1");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_MEDIUM, "PHP/2.5.0-RC1");
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecurePHPVersionUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: PHP/2.6.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenApacheWebServerFromRedHatUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 (Red Hat)");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_MEDIUM, "Apache/1.5.0 (Red Hat)");
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenApacheWebServerFromUbuntuUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 (Ubuntu)");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecurePerlVersionAsApacheWebServerModuleUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 Perl/v4.0.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_MEDIUM, "Apache/1.5.0 Perl/v4.0.0");
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecurePerlVersionAsApacheWebServerModuleUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 Perl/v4.0.1");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureContentGeneratorUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 Perl/v4.0.1");
        String metaTag = "<meta name=\"generator\" content=\"Frontweaver 1.2.0\"/>";
        msg.setResponseBody("<html><head>" + metaTag + "</head></html>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_LOW, metaTag);
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecureContentGeneratorUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 Perl/v4.0.1");
        String metaTag = "<meta name=\"generator\" content=\"Frontweaver 1.3.0\"/>";
        msg.setResponseBody("<html><head>" + metaTag + "</head></html>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureOracleWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "Server: Oracle-Application-Server-1g Oracle/2.4.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_LOW, "Oracle-Application-Server-1g Oracle/2.4.0");
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecureOracleWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "Server: Oracle-Application-Server-1g Oracle/2.5.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureJettyWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Jetty(2.4.0)");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_HIGH, "Jetty(2.4.0)");
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecureJettyWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Jetty(2.5.0)");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureJBossWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Servlet A JBoss-5.0.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_LOW, "Servlet A JBoss-5.0.0");
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecureJBossWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Servlet A JBoss-5.0.1");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureApacheTomcatWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: example");
        msg.setResponseBody("<html><head><title>Apache Tomcat/9.1.0 -</title>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_LOW, msg.getResponseBody().toString());
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecureApacheTomcatWebServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: example");
        msg.setResponseBody("<html><head><title>Apache Tomcat/9.1.2 -</title>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureProxyServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Via: (proxy/3.0)");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_LOW, "(proxy/3.0)");
    }

    @Test
    public void shouldNotRaiseVulnerabilityAlertWhenSecureProxyServerUsed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Via: (proxy/3.3)");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    /* In the other methods the Web-Server was leaked in the "Server" header-directive.
      In this method, we verify, that the "X-Powered-By" header-directive is treated equivalent
      to the "Server" header-directive.
    */
    @Test
    public void shouldRaiseVulnerabilityAlertWhenInsecureWebServerIsLeakedInXPoweredByHeader()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "X-Powered-By: Servlet A JBoss-5.0.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_LOW, "Servlet A JBoss-5.0.0");
    }

    @Test
    public void
            shouldRaiseVulnerabilityAlertWithTheHighestRiskLevelWhenMultipleVulnerabilitiesFound()
                    throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache/1.5.0 Perl/v5.0.0");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertVulnerabilityAlertRaised(Alert.RISK_HIGH, "Apache/1.5.0 Perl/v5.0.0");
    }
}
