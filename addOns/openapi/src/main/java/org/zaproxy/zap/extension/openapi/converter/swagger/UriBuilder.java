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

import java.net.URI;
import java.net.URISyntaxException;

/** A simple URI builder, from strings containing (optionally) scheme, authority, and path. */
public class UriBuilder {

    private static final char PATH_SEPARATOR_CHAR = '/';
    private static final String PATH_SEPARATOR = String.valueOf(PATH_SEPARATOR_CHAR);
    private static final String AUTHORITY_SEPARATOR = "//";
    private static final String SCHEME_SEPARATOR = ":" + AUTHORITY_SEPARATOR;
    private static final int NOT_FOUND = -1;

    private String originalUri;
    private String scheme;
    private String authority;
    private String path;
    private boolean appendPath;

    /**
     * Parses the given value, leniently.
     *
     * <p>It parses the following URI components {@code scheme://authority/path}, all optional. If
     * the value does not have scheme nor path it's parsed as authority.
     *
     * @param value the value to parse.
     * @return the URI builder.
     * @throws IllegalArgumentException if any of the conditions is true:
     *     <ul>
     *       <li>the {@code scheme} component is empty when it shouldn't, for example, {@code
     *           ://authority};
     *       <li>the {@code scheme} component is not empty when it should, for example, {@code
     *           //authority}.
     *     </ul>
     */
    public static UriBuilder parseLenient(String value) {
        return new UriBuilder(value, true);
    }

    /**
     * Parses the given value
     *
     * <p>It parses the following URI components {@code scheme://authority/path}, all optional. If
     * the value does not have scheme it's parsed as path.
     *
     * @param value the value to parse.
     * @return the URI builder.
     * @throws IllegalArgumentException if any of the conditions is true:
     *     <ul>
     *       <li>the {@code scheme} component is empty when it shouldn't, for example, {@code
     *           ://authority};
     *       <li>the {@code scheme} component is not empty when it should, for example, {@code
     *           //authority}.
     *     </ul>
     */
    public static UriBuilder parse(String value) {
        return new UriBuilder(value, false);
    }

    private UriBuilder() {}

    private UriBuilder(String value, boolean lenient) {
        if (value == null || value.isEmpty()) {
            return;
        }

        originalUri = value;

        int idxScheme = extractScheme();
        int idxPath = extractPath(idxScheme, lenient);
        extractAuthority(idxScheme, idxPath);
    }

    private int extractScheme() {
        int idxScheme = originalUri.indexOf(SCHEME_SEPARATOR);
        if (idxScheme != NOT_FOUND) {
            scheme = originalUri.substring(0, idxScheme);
            if (scheme.isEmpty()) {
                throw new IllegalArgumentException("Expected non-empty scheme in: " + originalUri);
            }
            return idxScheme + SCHEME_SEPARATOR.length();
        }
        idxScheme = originalUri.indexOf(AUTHORITY_SEPARATOR);
        if (idxScheme != NOT_FOUND) {
            if (!originalUri.substring(0, idxScheme).isEmpty()) {
                throw new IllegalArgumentException("Expected no scheme in: " + originalUri);
            }
            return idxScheme + AUTHORITY_SEPARATOR.length();
        }
        return 0;
    }

    private int extractPath(int idxScheme, boolean lenient) {
        if (idxScheme == 0 && !lenient) {
            path = originalUri;
            appendPath = !path.startsWith(PATH_SEPARATOR);
            return 0;
        }

        int idxPath = originalUri.indexOf(PATH_SEPARATOR_CHAR, idxScheme);
        if (idxPath != NOT_FOUND) {
            path = originalUri.substring(idxPath);
            return idxPath;
        }
        return originalUri.length();
    }

    private void extractAuthority(int idxScheme, int idxPath) {
        authority = originalUri.substring(idxScheme, idxPath);
        if (authority.isEmpty()) {
            authority = null;
        }
    }

    /**
     * Gets the scheme component, for example, {@code http}.
     *
     * @return the scheme, might be {@code null}.
     */
    String getScheme() {
        return scheme;
    }

    /**
     * Gets the authority component, for example, {@code example.com}
     *
     * @return the scheme, might be {@code null}.
     */
    String getAuthority() {
        return authority;
    }

    /**
     * Gets the path component, for example, {@code /absolutePath} or {@code relativePath}.
     *
     * @return the scheme, might be {@code null}.
     */
    String getPath() {
        return path;
    }

    /**
     * Sets the path to the given value, if not already set.
     *
     * @param value the path to default to.
     * @return {@code this}, for chaining.
     */
    UriBuilder withDefaultPath(String value) {
        path = nonNullOf(path, value);
        return this;
    }

    /**
     * Tells whether or not this builder is empty.
     *
     * <p>A builder is empty when it has no scheme, authority, and path.
     *
     * @return {@core true} if empty, {@code false} otherwise.
     */
    boolean isEmpty() {
        return scheme == null && authority == null && path == null;
    }

    /**
     * Copies this builder.
     *
     * @return a copy with the same scheme, authority, and path.
     */
    UriBuilder copy() {
        UriBuilder copy = new UriBuilder();
        copy.scheme = scheme;
        copy.authority = authority;
        copy.path = path;
        copy.appendPath = appendPath;
        copy.originalUri = originalUri;
        return copy;
    }

    /**
     * Merges the URI components of the given builder into {@code this} builder.
     *
     * <p>It uses the scheme, authority, and path of the given builder if not already set (that is,
     * {@code null}).
     *
     * <p>For non-lenient parsed URLs with relative path, it's appended to the path of the given
     * builder. For example, the URI {@code v2/} merged with {@code http://example.com/api/} results
     * in {@code http://example.com/api/v2/}.
     *
     * @param other other builder to merge.
     * @return {@code this}, for chaining.
     * @throws NullPointerException if {@code other} is {@code null}.
     */
    UriBuilder merge(UriBuilder other) {
        scheme = nonNullOf(scheme, other.scheme);
        authority = nonNullOf(authority, other.authority);
        if (appendPath && other.path != null) {
            path =
                    other.path.endsWith(PATH_SEPARATOR)
                            ? other.path + path
                            : other.path + PATH_SEPARATOR_CHAR + path;
            appendPath = false;
        } else {
            path = nonNullOf(path, other.path);
        }

        return this;
    }

    private static String nonNullOf(String value, String otherValue) {
        if (value == null) {
            return otherValue;
        }
        return value;
    }

    /**
     * Builds the URI from the components set.
     *
     * <p>The path is normalised, by removing {@code .} and {@code ..} segments. The trailing slash
     * is also removed (if present), the slash is not required as OpenAPI operations' paths already
     * start with a slash, thus just requiring appending the operation path to the built URI.
     *
     * @return the URI.
     * @throws IllegalArgumentException if any of the conditions is true:
     *     <ul>
     *       <li>the {@code scheme} is {@code null};
     *       <li>the {@code authority} is {@code null};
     *       <li>the resulting URI is malformed.
     *     </ul>
     */
    String build() {
        validateNotNull(scheme, "scheme");
        validateNotNull(authority, "authority");

        StringBuilder strBuilder =
                new StringBuilder().append(scheme).append(SCHEME_SEPARATOR).append(authority);
        if (path != null) {
            if (!path.endsWith(PATH_SEPARATOR)) {
                strBuilder.append(PATH_SEPARATOR_CHAR);
            }
            strBuilder.append(path);
        }

        String uri = strBuilder.toString();
        try {
            uri = new URI(strBuilder.toString()).normalize().toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Failed to normalise the URI: " + uri, e);
        }

        if (uri.endsWith(PATH_SEPARATOR)) {
            return uri.substring(0, uri.length() - PATH_SEPARATOR.length());
        }
        return uri;
    }

    private static void validateNotNull(String object, String name) {
        if (object == null) {
            throw new IllegalArgumentException("The " + name + " must not be null.");
        }
    }

    /**
     * Returns the URI parsed originally.
     *
     * @see #build()
     */
    @Override
    public String toString() {
        return originalUri;
    }
}
