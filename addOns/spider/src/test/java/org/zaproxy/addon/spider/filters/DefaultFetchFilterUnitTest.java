/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.addon.spider.filters;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.zaproxy.addon.spider.DomainAlwaysInScopeMatcher;
import org.zaproxy.addon.spider.filters.FetchFilter.FetchStatus;
import org.zaproxy.zap.model.Context;

/** Unit test for {@link DefaultFetchFilter}. */
@ExtendWith(MockitoExtension.class)
class DefaultFetchFilterUnitTest {

    @Mock Context context;

    @Test
    void shouldFilterUriWithNonSchemeAsIllegalProtocol() {
        // Given
        URI uri = createUri("example.com");
        // When
        FetchStatus status = new DefaultFetchFilter(null, Collections.emptyList()).checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.ILLEGAL_PROTOCOL)));
    }

    @Test
    void shouldFilterUriWithNonHttpOrHttpsSchemeAsIllegalProtocol() {
        // Given
        URI uri = createUri("ftp://example.com");
        // When
        FetchStatus status = new DefaultFetchFilter(null, Collections.emptyList()).checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.ILLEGAL_PROTOCOL)));
    }

    @Test
    void shouldFilterUriWithHttpSchemeAsOutOfScopeByDefault() throws Exception {
        // Given
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = new DefaultFetchFilter(null, Collections.emptyList()).checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.OUT_OF_SCOPE)));
    }

    @Test
    void shouldFilterUriWithHttpsSchemeAsOutOfScopeByDefault() throws Exception {
        // Given
        URI uri = createUri("https://example.com");
        // When
        FetchStatus status = new DefaultFetchFilter(null, Collections.emptyList()).checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.OUT_OF_SCOPE)));
    }

    @Test
    void shouldFilterOutOfScopeUriAsOutOfScope() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, Collections.emptyList());
        filter.addScopeRegex("scope.example.com");
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.OUT_OF_SCOPE)));
    }

    @Test
    void shouldFilterInScopeUriAsValid() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, Collections.emptyList());
        filter.addScopeRegex("example.com");
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    @Test
    void shouldFilterNonAlwaysInScopeUriAsOutOfScope() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, domainsAlwaysInScope("scope.example.com"));
        URI uri = createUri("https://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.OUT_OF_SCOPE)));
    }

    @Test
    void shouldFilterAlwaysInScopeUriAsValid() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, domainsAlwaysInScope("example.com"));
        URI uri = createUri("https://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    @Test
    void shouldFilterExcludedInScopeUriAsUserRules() throws Exception {
        var filter = new DefaultFetchFilter(null, Collections.emptyList());
        // Given
        filter.addScopeRegex("example.com");
        filter.setExcludeRegexes(excludeRegexes(".*example\\.com.*"));
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.USER_RULES)));
    }

    @Test
    void shouldFilterExcludedAlwaysInScopeUriAsUserRules() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, domainsAlwaysInScope("example.com"));
        filter.setExcludeRegexes(excludeRegexes(".*example\\.com.*"));
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.USER_RULES)));
    }

    @Test
    void shouldFilterNonExcludedInScopeUriAsValid() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, Collections.emptyList());
        filter.addScopeRegex("example.com");
        filter.setExcludeRegexes(excludeRegexes("subdomain\\.example\\.com.*"));
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    @Test
    void shouldFilterNonExcludedAlwaysInScopeUriAsValid() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(null, domainsAlwaysInScope("example.com"));
        filter.setExcludeRegexes(excludeRegexes("subdomain\\.example\\.com.*"));
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    @Test
    void shouldFilterOutOfContextUriAsOutOfContext() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(contextInScope(false), Collections.emptyList());
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.OUT_OF_CONTEXT)));
    }

    @Test
    void shouldFilterInContextUriAsValid() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(contextInScope(true), Collections.emptyList());
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    @Test
    void shouldFilterExcludedInContextUriAsUserRules() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(contextInScope(true), Collections.emptyList());

        filter.setExcludeRegexes(excludeRegexes(".*example\\.com.*"));
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.USER_RULES)));
    }

    @Test
    void shouldFilterNonExcludedInContextUriAsValid() throws Exception {
        // Given
        var filter = new DefaultFetchFilter(contextInScope(true), Collections.emptyList());

        filter.setExcludeRegexes(excludeRegexes("subdomain\\.example\\.com.*"));
        URI uri = createUri("http://example.com");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    @Test
    void shouldFilterLogoutUriWhenAvoidLogout() {
        // Given
        var filter = new DefaultFetchFilter(contextInScope(true), Collections.emptyList());
        filter.setLogoutAvoidance(true);
        URI uri = createUri("http://example.com/logout");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.LOGOUT_AVOIDANCE)));
    }

    @Test
    void shouldNotFilterLogoutUriWhenNotAvoidLogout() {
        // Given
        var filter = new DefaultFetchFilter(contextInScope(true), Collections.emptyList());

        filter.setLogoutAvoidance(false);
        URI uri = createUri("http://example.com/logout");
        // When
        FetchStatus status = filter.checkFilter(uri);
        // Then
        assertThat(status, is(equalTo(FetchStatus.VALID)));
    }

    private static URI createUri(String uri) {
        try {
            return new URI(uri, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static List<DomainAlwaysInScopeMatcher> domainsAlwaysInScope(String... domains) {
        return Arrays.stream(domains).map(DomainAlwaysInScopeMatcher::new).toList();
    }

    private static List<String> excludeRegexes(String... regexes) {
        return Arrays.asList(regexes);
    }

    private Context contextInScope(boolean inScope) {
        given(context.isInContext(anyString())).willReturn(inScope);
        return context;
    }
}
