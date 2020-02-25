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
package org.zaproxy.zap.extension.openapi.converter.swagger;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import org.apache.commons.lang3.tuple.Pair;
import org.hamcrest.Matcher;
import org.junit.Test;

/** Unit test for {@link UriBuilder}. */
public class UriBuilderUnitTest {

    private static final ParseMethod PARSE = new ParseMethod("parse", UriBuilder::parse);
    private static final ParseMethod PARSE_LENIENT =
            new ParseMethod("parseLenient", UriBuilder::parseLenient);

    private static final List<ParseMethod> PARSE_METHODS = Arrays.asList(PARSE, PARSE_LENIENT);
    private static final List<Pair<ParseMethod, ParseMethod>> PARSE_METHODS_MERGE =
            Arrays.asList(
                    Pair.of(PARSE, PARSE),
                    Pair.of(PARSE_LENIENT, PARSE_LENIENT),
                    Pair.of(PARSE, PARSE_LENIENT),
                    Pair.of(PARSE_LENIENT, PARSE));

    @Test
    public void shouldParseWithNullValue() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = null;
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method, uriBuilder, is(nullValue()), is(nullValue()), is(nullValue()));
                });
    }

    private static void assertUriComponents(
            ParseMethod method,
            UriBuilder uriBuilder,
            Matcher<Object> schemeMatcher,
            Matcher<Object> authorityMatcher,
            Matcher<Object> pathMatcher) {
        assertUriComponents(method, null, uriBuilder, schemeMatcher, authorityMatcher, pathMatcher);
    }

    private static void assertUriComponents(
            ParseMethod method,
            ParseMethod otherMethod,
            UriBuilder uriBuilder,
            Matcher<Object> schemeMatcher,
            Matcher<Object> authorityMatcher,
            Matcher<Object> pathMatcher) {
        String reason = "Parsed with: " + method.name;
        if (otherMethod != null) {
            reason += " and " + otherMethod.name;
        }
        assertThat(reason, uriBuilder.getScheme(), schemeMatcher);
        assertThat(reason, uriBuilder.getAuthority(), authorityMatcher);
        assertThat(reason, uriBuilder.getPath(), pathMatcher);
    }

    @Test
    public void shouldParseWithEmptyValue() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method, uriBuilder, is(nullValue()), is(nullValue()), is(nullValue()));
                });
    }

    @Test
    public void shouldParseWithJustRelativePath() {
        // Given
        ParseMethod method = PARSE;
        String value = "relativePath";
        // When
        UriBuilder uriBuilder = method.parse(value);
        // Then
        assertUriComponents(
                method, uriBuilder, is(nullValue()), is(nullValue()), is(equalTo(value)));
    }

    @Test
    public void shouldParseLenientWithJustAuthority() {
        // Given
        ParseMethod method = PARSE_LENIENT;
        String value = "authority";
        // When
        UriBuilder uriBuilder = method.parse(value);
        // Then
        assertUriComponents(
                method, uriBuilder, is(nullValue()), is(equalTo(value)), is(nullValue()));
    }

    @Test
    public void shouldParseWithAbsolutePath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "/absolutePath";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(nullValue()),
                            is(nullValue()),
                            is(equalTo(value)));
                });
    }

    @Test
    public void shouldParseWithAuthorityAndNoScheme() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "//example.com";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(nullValue()),
                            is(equalTo("example.com")),
                            is(nullValue()));
                });
    }

    @Test
    public void shouldParseWithEmptyAuthority() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "//";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method, uriBuilder, is(nullValue()), is(nullValue()), is(nullValue()));
                });
    }

    @Test
    public void shouldParseWithScheme() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "http://";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("http")),
                            is(nullValue()),
                            is(nullValue()));
                });
    }

    @Test
    public void shouldFailToParseWithEmptyScheme() {
        PARSE_METHODS.forEach(
                method -> {
                    try {
                        // Given
                        String value = "://";
                        // When
                        UriBuilder.parse(value);
                        fail("Expected IllegalArgumentException");
                    } catch (IllegalArgumentException e) {
                        // Then
                        assertThat(
                                "Parsed with: " + method,
                                e.getMessage(),
                                containsString("Expected non-empty scheme"));
                    }
                });
    }

    @Test
    public void shouldFailToParseWithMalformedScheme() {
        PARSE_METHODS.forEach(
                method -> {
                    try {
                        // Given
                        String value = "notscheme//";
                        // When
                        UriBuilder.parse(value);
                        fail("Expected IllegalArgumentException");
                    } catch (IllegalArgumentException e) {
                        // Then
                        assertThat(
                                "Parsed with: " + method,
                                e.getMessage(),
                                containsString("Expected no scheme"));
                    }
                });
    }

    @Test
    public void shouldParseWithSchemeAndAuthority() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "http://example.com";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(nullValue()));
                });
    }

    @Test
    public void shouldParseWithSchemeAuthorityAndEmptyPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "http://example.com/";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(equalTo("/")));
                });
    }

    @Test
    public void shouldParseWithSchemeAuthorityAndNonEmptyPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    String value = "http://example.com/path";
                    // When
                    UriBuilder uriBuilder = method.parse(value);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(equalTo("/path")));
                });
    }

    @Test
    public void shouldThrowNullPointerIfMergingToNull() {
        PARSE_METHODS.forEach(
                method -> {
                    try {
                        // Given
                        UriBuilder uriBuilder = method.parse("");
                        // When
                        uriBuilder.merge(null);
                        fail("Expected NullPointerException");
                    } catch (NullPointerException e) {
                        // Then
                        assertThat("Parsed with: " + method, e, is(not(nullValue())));
                    }
                });
    }

    @Test
    public void shouldMergeSchemeIfNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("//example.com/path/");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("https")),
                            is(equalTo("example.com")),
                            is(equalTo("/path/")));
                });
    }

    @Test
    public void shouldNotMergeSchemeIfNotNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("http://example.com/path/");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(equalTo("/path/")));
                });
    }

    @Test
    public void shouldMergeAuthorityIfNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("http://");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("other.example.com")),
                            is(not(nullValue())));
                });
    }

    @Test
    public void shouldNotMergeAuthorityIfNotNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("http://example.com");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(not(nullValue())));
                });
    }

    @Test
    public void shouldMergePathIfNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("http://example.com");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(equalTo("/otherpath/")));
                });
    }

    @Test
    public void shouldNotMergePathIfNotNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("http://example.com/");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("http")),
                            is(equalTo("example.com")),
                            is(equalTo("/")));
                });
    }

    @Test
    public void shouldMergeSchemeAuthorityIfJustAbsolutePath() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse("/path");
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("https")),
                            is(equalTo("other.example.com")),
                            is(equalTo("/path")));
                });
    }

    @Test
    public void shouldMergeRelativePath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("relativePath");
                    UriBuilder otherUrlBuilder =
                            method.parse("https://other.example.com/otherpath");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("https")),
                            is(equalTo("other.example.com")),
                            is(equalTo("/otherpath/relativePath")));
                });
    }

    @Test
    public void shouldMergeRelativePathWithPathEndedWithSlash() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("relativePath");
                    UriBuilder otherUrlBuilder =
                            method.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("https")),
                            is(equalTo("other.example.com")),
                            is(equalTo("/otherpath/relativePath")));
                });
    }

    @Test
    public void shouldMergeRelativePathWithNoPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("relativePath");
                    UriBuilder otherUrlBuilder = method.parse("https://other.example.com");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method,
                            uriBuilder,
                            is(equalTo("https")),
                            is(equalTo("other.example.com")),
                            is(equalTo("relativePath")));
                });
    }

    @Test
    public void shouldMergeSchemeAuthorityAndPathIfAllNull() {
        PARSE_METHODS_MERGE.forEach(
                pair -> {
                    // Given
                    ParseMethod method1 = pair.getLeft();
                    ParseMethod method2 = pair.getRight();
                    UriBuilder uriBuilder = method1.parse(null);
                    UriBuilder otherUrlBuilder =
                            method2.parse("https://other.example.com/otherpath/");
                    // When
                    uriBuilder.merge(otherUrlBuilder);
                    // Then
                    assertUriComponents(
                            method1,
                            method2,
                            uriBuilder,
                            is(equalTo("https")),
                            is(equalTo("other.example.com")),
                            is(equalTo("/otherpath/")));
                });
    }

    @Test
    public void shouldSetDefaulPathIfNotAlreadySet() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://example.com");
                    // When
                    uriBuilder.withDefaultPath("path");
                    // Then
                    assertThat("Parsed with: " + method, uriBuilder.getPath(), is(equalTo("path")));
                });
    }

    @Test
    public void shouldNotSetDefaulPathIfAlreadySet() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://example.com/path");
                    // When
                    uriBuilder.withDefaultPath("otherpath");
                    // Then
                    assertThat(
                            "Parsed with: " + method, uriBuilder.getPath(), is(equalTo("/path")));
                });
    }

    @Test
    public void shouldBeEmptyWithoutSchemeAuthorityAndPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("");
                    // When
                    boolean empty = uriBuilder.isEmpty();
                    // Then
                    assertThat("Parsed with: " + method, empty, is(equalTo(true)));
                });
    }

    @Test
    public void shouldNotBeEmptyWithScheme() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://");
                    // When
                    boolean empty = uriBuilder.isEmpty();
                    // Then
                    assertThat("Parsed with: " + method, empty, is(equalTo(false)));
                });
    }

    @Test
    public void shouldNotBeEmptyWithAuthority() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("//example.com");
                    // When
                    boolean empty = uriBuilder.isEmpty();
                    // Then
                    assertThat("Parsed with: " + method, empty, is(equalTo(false)));
                });
    }

    @Test
    public void shouldNotBeEmptyWithPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("/path");
                    // When
                    boolean empty = uriBuilder.isEmpty();
                    // Then
                    assertThat("Parsed with: " + method, empty, is(equalTo(false)));
                });
    }

    @Test
    public void shouldCopy() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder original = method.parse("/path");
                    // When
                    UriBuilder copy = original.copy();
                    // Then
                    assertUriComponents(
                            method,
                            copy,
                            is(equalTo(original.getScheme())),
                            is(equalTo(original.getAuthority())),
                            is(equalTo(original.getPath())));
                    assertThat(
                            "Parsed with: " + method,
                            copy.toString(),
                            is(equalTo(original.toString())));
                });
    }

    @Test
    public void shouldBuildWithSchemeAndAuthority() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://example.com");
                    // When
                    String url = uriBuilder.build();
                    // Then
                    assertThat("Parsed with: " + method, url, is(equalTo("http://example.com")));
                });
    }

    @Test
    public void shouldBuildWithSchemeAuthorityAndPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://example.com/path");
                    // When
                    String url = uriBuilder.build();
                    // Then
                    assertThat(
                            "Parsed with: " + method, url, is(equalTo("http://example.com/path")));
                });
    }

    @Test
    public void shouldBuildAfterMergeRelativePathWithNoPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("relativePath");
                    UriBuilder otherUrlBuilder = method.parse("http://example.com");
                    // When
                    String url = uriBuilder.merge(otherUrlBuilder).build();
                    // Then
                    assertThat(
                            "Parsed with: " + method,
                            url,
                            is(equalTo("http://example.com/relativePath")));
                });
    }

    @Test
    public void shouldBuildAfterMergeRelativePathWithEmptyPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("relativePath");
                    UriBuilder otherUrlBuilder = method.parse("http://example.com/");
                    // When
                    String url = uriBuilder.merge(otherUrlBuilder).build();
                    // Then
                    assertThat(
                            "Parsed with: " + method,
                            url,
                            is(equalTo("http://example.com/relativePath")));
                });
    }

    @Test
    public void shouldBuildAfterMergeAbsolutePathWithNoPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("/absolutePath");
                    UriBuilder otherUrlBuilder = method.parse("http://example.com");
                    // When
                    String url = uriBuilder.merge(otherUrlBuilder).build();
                    // Then
                    assertThat(
                            "Parsed with: " + method,
                            url,
                            is(equalTo("http://example.com/absolutePath")));
                });
    }

    @Test
    public void shouldBuildAfterMergeAbsolutePathWithEmptyPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = UriBuilder.parse("/absolutePath");
                    UriBuilder otherUrlBuilder = method.parse("http://example.com/");
                    // When
                    String url = uriBuilder.merge(otherUrlBuilder).build();
                    // Then
                    assertThat(
                            "Parsed with: " + method,
                            url,
                            is(equalTo("http://example.com/absolutePath")));
                });
    }

    @Test
    public void shouldBuildRemovingSlashAtTheEnd() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://example.com/path/");
                    // When
                    String url = uriBuilder.build();
                    // Then
                    assertThat(
                            "Parsed with: " + method, url, is(equalTo("http://example.com/path")));
                });
    }

    @Test
    public void shouldBuildNormalisingPath() {
        PARSE_METHODS.forEach(
                method -> {
                    // Given
                    UriBuilder uriBuilder = method.parse("http://example.com/path/../other/.");
                    // When
                    String url = uriBuilder.build();
                    // Then
                    assertThat(
                            "Parsed with: " + method, url, is(equalTo("http://example.com/other")));
                });
    }

    @Test
    public void shouldFailToBuildWithNoScheme() {
        PARSE_METHODS.forEach(
                method -> {
                    try {
                        // Given
                        UriBuilder uriBuilder = method.parse("//example.com/");
                        // When
                        uriBuilder.build();
                        fail("Expected IllegalArgumentException");
                    } catch (IllegalArgumentException e) {
                        // Then
                        assertThat(
                                "Parsed with: " + method, e.getMessage(), containsString("scheme"));
                    }
                });
    }

    @Test
    public void shouldFailToBuildWithNoAuthority() {
        PARSE_METHODS.forEach(
                method -> {
                    try {
                        // Given
                        UriBuilder uriBuilder = method.parse("http://");
                        // When
                        uriBuilder.build();
                        fail("Expected IllegalArgumentException");
                    } catch (IllegalArgumentException e) {
                        // Then
                        assertThat(
                                "Parsed with: " + method,
                                e.getMessage(),
                                containsString("authority"));
                    }
                });
    }

    @Test
    public void shouldFailToBuildWithMalformedUri() {
        PARSE_METHODS.forEach(
                method -> {
                    try {
                        // Given
                        UriBuilder uriBuilder = method.parse("http://x%0");
                        // When
                        uriBuilder.build();
                        fail("Expected IllegalArgumentException");
                    } catch (IllegalArgumentException e) {
                        // Then
                        assertThat(
                                "Parsed with: " + method,
                                e.getMessage(),
                                containsString("normalise"));
                    }
                });
    }

    private static class ParseMethod {
        final String name;
        private final Function<String, UriBuilder> method;

        ParseMethod(String name, Function<String, UriBuilder> method) {
            this.name = name;
            this.method = method;
        }

        UriBuilder parse(String value) {
            return method.apply(value);
        }
    }
}
