/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.ByteArrayInputStream;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.junit.jupiter.api.condition.JRE;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SourceCodeDisclosureWebInfScanRule}. */
// XXX Does not work with Java 9+ because of procyon-decompiler.
// Refs:
// - https://github.com/zaproxy/zaproxy/issues/4038
// - https://bitbucket.org/mstrobel/procyon/issues/320/java-9-sunmiscurlclasspath-and
@EnabledOnJre(JRE.JAVA_8)
public class SourceCodeDisclosureWebinfScanRuleUnitTest
        extends ActiveScannerTest<SourceCodeDisclosureWebInfScanRule> {

    private static final String JAVA_LIKE_FILE_NAME_PATH = "/WEB-INF/classes/about/html.class";

    @Override
    protected SourceCodeDisclosureWebInfScanRule createScanner() {
        return new SourceCodeDisclosureWebInfScanRule();
    }

    @Test
    public void shouldTryToObtainWebInfFiles() throws Exception {
        // Given
        rule.init(getHttpMessage("/some/path"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(2));
        assertThat(requestPath(httpMessagesSent.get(0)), is(equalTo("/WEB-INF/web.xml")));
        assertThat(
                requestPath(httpMessagesSent.get(1)),
                is(equalTo("/WEB-INF/applicationContext.xml")));
    }

    @Test
    public void shouldNotContinueScanningIfReturnedContentHasNoJavaLikeFileNames()
            throws Exception {
        // Given
        nano.addHandler(new NotFoundResponse(""));
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    public void shouldContinueScanningIfReturnedContentHasJavaLikeFileNamesEvenIfNotWebInfData()
            throws Exception {
        // Given
        nano.addHandler(new NonWebInfWithJavaLikeFileNameResponse());
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(3));
        assertThat(requestPath(httpMessagesSent.get(2)), is(equalTo(JAVA_LIKE_FILE_NAME_PATH)));
    }

    @Test
    public void shouldNotAlertIfJavaLikeFileNameIsNot200Ok() throws Exception {
        // Given
        nano.addHandler(new NotFoundResponse(JAVA_LIKE_FILE_NAME_PATH));
        nano.addHandler(new NonWebInfWithJavaLikeFileNameResponse());
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(3));
        assertThat(requestPath(httpMessagesSent.get(2)), is(equalTo(JAVA_LIKE_FILE_NAME_PATH)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertIfJavaLikeFileNameIsNotAJavaClassEvenIfIs200Ok() throws Exception {
        // Given
        nano.addHandler(new OkResponse(JAVA_LIKE_FILE_NAME_PATH));
        nano.addHandler(new NonWebInfWithJavaLikeFileNameResponse());
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(3));
        assertThat(requestPath(httpMessagesSent.get(2)), is(equalTo(JAVA_LIKE_FILE_NAME_PATH)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertIfJavaSourceWasDisclosed() throws Exception {
        // Given
        nano.addHandler(new JavaClassResponse(JAVA_LIKE_FILE_NAME_PATH));
        nano.addHandler(new NonWebInfWithJavaLikeFileNameResponse());
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(3));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("class A\n{\n}\n")));
    }

    private static String requestPath(HttpMessage message) {
        try {
            return message.getRequestHeader().getURI().getPath();
        } catch (URIException e) {
            throw new RuntimeException(e);
        }
    }

    private static class NonWebInfWithJavaLikeFileNameResponse extends NanoServerHandler {

        public NonWebInfWithJavaLikeFileNameResponse() {
            super("");
        }

        @Override
        public Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND,
                    "text/html",
                    "<html><body><h1>404 Not Found</h1>\n<a href=\"/about.html\">About Page</a></body></html>");
        }
    }

    private static class JavaClassResponse extends NanoServerHandler {

        private static final byte[] JAVA_CLASS;

        static {
            try {
                JAVA_CLASS =
                        Hex.decodeHex(
                                ("cafebabe00000034000d0a0003000a07000b07000c0100063c696e69743e0100"
                                                + "03282956010004436f646501000f4c696e654e756d6265725461626c6501000a"
                                                + "536f7572636546696c65010006412e6a6176610c00040005010001410100106a"
                                                + "6176612f6c616e672f4f626a6563740020000200030000000000010000000400"
                                                + "05000100060000001d00010001000000052ab70001b100000001000700000006"
                                                + "00010000000100010008000000020009")
                                        .toCharArray());
            } catch (DecoderException e) {
                throw new RuntimeException(e);
            }
        }

        public JavaClassResponse(String path) {
            super(path);
        }

        @Override
        public Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.OK,
                    "application/class",
                    new ByteArrayInputStream(JAVA_CLASS),
                    JAVA_CLASS.length);
        }
    }

    private static class NotFoundResponse extends NanoServerHandler {

        public NotFoundResponse(String path) {
            super(path);
        }

        @Override
        public Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND,
                    "text/html",
                    "<html><body><h1>404 Not Found</h1>\nNot Found.</body></html>");
        }
    }

    private static class OkResponse extends NanoServerHandler {

        public OkResponse(String path) {
            super(path);
        }

        @Override
        public Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.OK,
                    "text/html",
                    "<html><body><h1>Some Title</h1>\nSome content.</body></html>");
        }
    }
}
