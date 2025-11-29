/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.scripts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.graaljs.GraalJsActiveScriptScanRuleTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

public class SwaggerSecretDetectorScriptUnitTest extends GraalJsActiveScriptScanRuleTestUtils {
    @Override
    public Path getScriptPath() throws Exception {
        return Path.of(
                getClass().getResource("/scripts/scripts/active/SwaggerSecretDetector.js").toURI());
    }

    @Test
    void shouldReturnExpectedMappings() {
        MatcherAssert.assertThat(rule.getId(), is(equalTo(100043)));
        MatcherAssert.assertThat(
                rule.getName(), is(equalTo("Swagger UI Secret & Vulnerability Detector")));
        MatcherAssert.assertThat(rule.getCategory(), is(equalTo(Category.INFO_GATHER)));
        MatcherAssert.assertThat(rule.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        MatcherAssert.assertThat(rule.getCweId(), is(equalTo(522)));
        MatcherAssert.assertThat(rule.getWascId(), is(equalTo(0)));
        MatcherAssert.assertThat(
                rule.getAlertTags().keySet(),
                containsInAnyOrder(
                        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag(),
                        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        MatcherAssert.assertThat(rule.getStatus(), is(equalTo(AddOn.Status.alpha)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "SwaggerUIBundle version: 3.20.0",
                "SwaggerUIBundle version: \"3.18.0\"",
                "SwaggerUIBundle version = '3.10.1'",
                "SwaggerUIBundle version = 3.0.0",
                "SwaggerUi version: \"2.1.9\"",
                "window.swaggerUi version = '2.2.5'",
                "swashbuckleConfig version = 2.0.0"
            })
    void shouldAlertForVulnerableVersionBodies(String body) throws Exception {
        // Given
        nano.addHandler(new StaticHandler("/swagger-ui/", body));
        HttpMessage msg = getHttpMessage("/foo/bar");
        rule.setAttackStrength(Plugin.AttackStrength.INSANE);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getAlertRef(), is(equalTo("100043-1")));
        assertThat(alert.getName(), startsWith("Vulnerable Swagger UI Version Detected"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "SwaggerUIBundle version: 3.24.3",
                "SwaggerUi version: 2.2.10",
                "NSwag version: 4.0.0",
                "nswagui version: 4.0.0",
                "zaproxy version: 2.16.0"
            })
    void shouldNotAlertForNonVulnerableVersionBodies(String body) throws Exception {
        // Given
        nano.addHandler(new StaticHandler("/swagger-ui/", body));
        HttpMessage msg = getHttpMessage("/foo/bar");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "clientId:'abcdefgh' clientSecret: 'abcdefgh'",
                "oAuth2ClientId: 'abcdefgh' api_key: \"abcdefgh\"",
                "clientId:'abcdefgh' oAuth2ClientSecret: 'abcdefgh'",
                "clientId:'abcdefgh' api_key: 'abcdefgh'",
                "clientId:\"abcdefgh\" access_token: 'abcdefgh'",
                "clientId:'abcdefgh' authorization: 'Bearer abcdefgh'",
            })
    void shouldAlertForSecretsInBodies(String body) throws Exception {
        // Given
        nano.addHandler(new StaticHandler("/swagger-ui/", body));
        HttpMessage msg = getHttpMessage("/foo/bar");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getAlertRef(), is(equalTo("100043-2")));
        assertThat(alert.getName(), is(equalTo("Exposed Secrets in Swagger/OpenAPI Path")));
    }

    @Test
    void shouldCheckAllStaticPaths() throws Exception {
        // Given
        HttpMessage msg = getHttpMessage("/foo/bar");
        rule.init(msg, parent);
        rule.setAttackStrength(Plugin.AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        MatcherAssert.assertThat(nano.getRequestedUris(), hasSize(20));
        MatcherAssert.assertThat(
                nano.getRequestedUris(),
                containsInAnyOrder(
                        "/swagger",
                        "/swagger/",
                        "/swagger/index.html",
                        "/swagger/ui",
                        "/swagger/ui/",
                        "/swagger/ui/index",
                        "/swagger/ui/index.html",
                        "/swagger-ui",
                        "/swagger-ui/",
                        "/swagger-ui/index.html",
                        "/swagger-ui/index",
                        "/docs",
                        "/docs/",
                        "/api-docs",
                        "/v2/api-docs",
                        "/v3/api-docs",
                        "/swagger.json",
                        "/swagger.yaml",
                        "/openapi.json",
                        "/openapi.yaml"));
    }

    static Stream<String> swaggerRegexSamplePaths() {
        return Stream.of(
                "/foo/swagger",
                "/foo/swagger/index.html",
                "/foo/swagger/ui",
                "/foo/swagger/ui/index.html",
                "/foo/swagger-ui",
                "/foo/swagger-ui/index",
                "/foo/docs",
                "/foo/api-docs",
                "/foo/v2/api-docs",
                "/foo/v3/api-docs",
                "/foo/swagger.json",
                "/foo/openapi.yaml",
                "/foo/api/v1/something",
                "/foo/v1/swagger-ui",
                "/foo/v1/openapi.json",
                "/foo/nswag",
                "/foo/redoc",
                "/foo/admin",
                "/foo/config.json",
                "/foo/debug.log",
                "/foo/.env",
                "/foo/.git/config",
                "/foo/login",
                "/foo/signin",
                "/foo/upload/file.txt",
                "/foo/graphql",
                "/foo/graphiql",
                "/foo/phpinfo.php",
                "/foo/server-status",
                "/foo/actuator/health",
                "/foo/.git/HEAD",
                "/foo/backup.zip",
                "/foo/db.sql");
    }

    @ParameterizedTest
    @MethodSource("swaggerRegexSamplePaths")
    void shouldRaiseAlertsForRegexPath(String path) throws Exception {
        // Given
        String body =
                "clientId: \"abcd12345client\"\nclientSecret: \"secret98765value\"\nSwaggerUIBundle version: 3.20.0";
        nano.addHandler(new StaticHandler(path, body));
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(2));
        MatcherAssert.assertThat(alertsRaised.get(0).getAlertRef(), is(equalTo("100043-1")));
        MatcherAssert.assertThat(alertsRaised.get(1).getAlertRef(), is(equalTo("100043-2")));
    }

    @Test
    void shouldNotRaiseAlertOnNonSwaggerPath() throws Exception {
        // Given
        String path = "/notswagger";
        nano.addHandler(new StaticHandler(path, "<html><body>No swagger here</body></html>"));
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldIgnoreFalsePositiveSecrets() throws Exception {
        // Given
        String path = "/swagger-ui/index.html";
        String body =
                """
                    <html>
                    <script>var SwaggerUIBundle = {};</script>
                    clientId: "clientid"
                    clientSecret: "dummysecret"
                    </html>
                """;
        nano.addHandler(new StaticHandler(path, body));
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    private static class StaticHandler extends NanoServerHandler {
        private final String path;
        private final String body;

        StaticHandler(String path, String body) {
            super(path);
            this.path = path;
            this.body = body;
        }

        @Override
        protected Response serve(NanoHTTPD.IHTTPSession session) {
            return path.equals(session.getUri())
                    ? NanoHTTPD.newFixedLengthResponse(
                            Response.Status.OK, NanoHTTPD.MIME_HTML, body)
                    : NanoHTTPD.newFixedLengthResponse(
                            Response.Status.NOT_FOUND, NanoHTTPD.MIME_PLAINTEXT, "");
        }
    }
}
