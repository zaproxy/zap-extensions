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
package org.zaproxy.addon.commonlib;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URL;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link UriUtils}. */
class UriUtilsUnitTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                // Basic schemes
                "http://example.com",
                "https://example.com",
                "ftp://example.com",
                "file:///etc/hosts",
                // Trailing slash and paths
                "https://example.com/",
                "https://example.com/path/to/resource",
                // Query strings
                "https://example.com/path?key=value",
                "https://example.com/path?a=1&b=2&c=3",
                "https://example.com/?flag",
                // Fragments
                "https://example.com/path#section",
                "https://example.com/path?key=value#section",
                // Non-default ports
                "https://example.com:8080",
                "https://example.com:8080/path?q=1",
                "http://example.com:80",
                // Authentication info
                "https://user:password@example.com",
                "https://user@example.com",
                "https://user:p%40ssword@example.com",
                // IPv4
                "https://192.168.1.1",
                "https://192.168.1.1:443/path",
                "http://127.0.0.1:8080",
                // IPv6
                "http://[::1]",
                "http://[::1]:8080/path",
                "https://[2001:db8::1]",
                // Subdomains and multi-part hosts
                "https://sub.domain.example.com",
                "https://a.b.c.d.example.com/path",
                // Percent-encoded characters
                "https://example.com/path%20with%20encoded%20spaces",
                "https://example.com/search?q=hello%20world&lang=en",
                "https://example.com/%E2%82%AC",
                // Uppercase host (case-insensitive per RFC)
                "https://EXAMPLE.COM/path",
            })
    void shouldNotThrowForValidUrl(String url) {
        assertDoesNotThrow(() -> UriUtils.isValid(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                // No scheme — valid URI relative reference, but not a URL
                "not-a-url",
                "example.com",
                "example.com/path",
                // Protocol-relative — valid URI, invalid URL (no scheme)
                "//example.com",
                "//example.com/path",
                // Empty string — valid URI (empty reference), invalid URL
                "",
                // Unsupported URL schemes (valid URI syntax, no Java URL handler)
                "javascript:alert(1)",
                "ldap://example.com",
                "data:text/plain,hello",
                "ws://example.com",
                "wss://example.com/socket",
                "custom-scheme://example.com",
                // Invalid URI syntax — unencoded characters not allowed in URI
                "https://example.com/path with spaces",
                "https://example.com/path\twith\ttabs",
                "https://user name@example.com",
                // Malformed IPv6
                "https://[::invalid",
                "https://[::1",
                // Invalid port
                "https://example.com:notaport/path",
                // Scheme only, no host
                "https:",
            })
    void shouldThrowForInvalidUrl(String url) {
        assertThrows(ZapUriException.class, () -> UriUtils.isValid(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                // Invalid URI syntax
                "https://example.com/path with spaces",
                "https://user name@example.com",
                "https://[::invalid",
                // Valid URI but unsupported URL scheme
                "not-a-url",
                "javascript:alert(1)",
                "ldap://example.com",
                "",
            })
    void shouldReportInputAndReasonInException(String url) {
        ZapUriException ex = assertThrows(ZapUriException.class, () -> UriUtils.isValid(url));
        assertEquals(url, ex.getInput());
        assertFalse(ex.getMessage().isEmpty());
    }

    @Test
    void shouldThrowForNullUri() {
        ZapUriException ex = assertThrows(ZapUriException.class, () -> UriUtils.isValid(null));
        assertFalse(ex.getMessage().isEmpty());
    }

    @Test
    void shouldReportExactReasonInFromInvalidUriSyntaxException() {
        String url = "https://example.com/path with spaces";
        ZapUriException ex = assertThrows(ZapUriException.class, () -> UriUtils.isValid(url));
        assertEquals("Illegal character in path at index 24: " + url, ex.getMessage());
    }

    @Test
    void shouldReportExactReasonInFromUnsupportedSchemeException() {
        String url = "javascript:alert(1)";
        ZapUriException ex = assertThrows(ZapUriException.class, () -> UriUtils.isValid(url));
        assertEquals("unknown protocol: javascript", ex.getMessage());
    }

    // buildUrl tests

    @ParameterizedTest
    @MethodSource("validUrlComponents")
    void buildUrlShouldRoundTripComponents(String scheme, String host, int port, String file)
            throws ZapUriException {
        URL url = UriUtils.buildUrl(scheme, host, port, file);
        assertEquals(scheme, url.getProtocol());
        assertEquals(host, url.getHost());
        assertEquals(port, url.getPort());
        assertEquals(file, url.getFile());
    }

    static Stream<Arguments> validUrlComponents() {
        return Stream.of(
                // Standard schemes with explicit ports
                Arguments.of("http", "example.com", 80, "/path"),
                Arguments.of("https", "example.com", 443, "/secure"),
                Arguments.of("ftp", "files.example.com", 21, "/pub/file.txt"),
                // Default port (-1 means use scheme default; getPort() returns -1)
                Arguments.of("http", "example.com", -1, "/default-port"),
                Arguments.of("https", "example.com", -1, "/default-port"),
                // Non-standard ports
                Arguments.of("http", "example.com", 8080, "/non-standard"),
                Arguments.of("https", "example.com", 8443, "/non-standard"),
                Arguments.of("http", "example.com", 65535, "/max-port"),
                // Query strings are preserved verbatim in getFile()
                Arguments.of("http", "example.com", 8080, "/path?key=value"),
                Arguments.of("http", "example.com", 80, "/search?q=hello&lang=en"),
                // IPv4 host
                Arguments.of("http", "192.168.1.1", 80, "/api"),
                Arguments.of("https", "10.0.0.1", 443, "/internal"),
                // Subdomain
                Arguments.of("https", "sub.domain.example.com", 443, "/deep/path/resource"),
                // Empty file (path)
                Arguments.of("http", "example.com", 80, ""),
                // Root path
                Arguments.of("http", "example.com", 80, "/"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"javascript", "ldap", "ws", "wss", "custom", "data"})
    void buildUrlShouldThrowForUnsupportedScheme(String scheme) {
        assertThrows(
                ZapUriException.class, () -> UriUtils.buildUrl(scheme, "example.com", 80, "/path"));
    }

    @Test
    void buildUrlShouldThrowWithExactMessageForUnsupportedScheme() throws Exception {
        ZapUriException ex =
                assertThrows(
                        ZapUriException.class,
                        () -> UriUtils.buildUrl("javascript", "example.com", 80, "/path"));
        assertEquals("unknown protocol: javascript", ex.getMessage());
    }
}
