/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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

import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Utility class for checking whether a {@code HttpMessage} pertains to various resource type
 * messages (JS, CSS, Fonts, Binary [control characters], etc) based on request path elements or
 * response content type.
 *
 * @since 1.7.0
 */
public final class ResourceIdentificationUtils {
    private ResourceIdentificationUtils() {}

    private static final Pattern PATTERN_FONT_EXTENSIONS =
            Pattern.compile("(?:\\.ttf|\\.woff|\\.woff2|\\.otf)\\z", Pattern.CASE_INSENSITIVE);
    private static final Pattern PATTERN_JS_EXTENSIONS =
            Pattern.compile("(?:\\.js|\\.jsx)\\z", Pattern.CASE_INSENSITIVE);

    /**
     * Returns whether or not the given {@link HttpMessage} has a font content type in its response
     * or request URL path.
     *
     * @param msg the {@link HttpMessage} to check
     * @return {@code true} if the given {@link HttpMessage} has a font content type in its response
     *     or request URL path, {@code false} otherwise
     */
    public static boolean isFont(HttpMessage msg) {
        if (msg.getResponseHeader().hasContentType("font")) {
            return true;
        }

        String path = msg.getRequestHeader().getURI().getEscapedPath();
        if (path != null) {
            return PATTERN_FONT_EXTENSIONS.matcher(path).find();
        }
        return false;
    }

    /**
     * Returns whether or not the given {@link HttpMessage} has a JavaScript content type in its
     * response or request URL path
     *
     * @param msg the {@link HttpMessage} to check
     * @return {@code true} if the given {@link HttpMessage} has a JavaScript content type in its
     *     response or request URL path, {@code false} otherwise.
     */
    public static boolean isJavaScript(HttpMessage msg) {
        if (msg.getResponseHeader().isJavaScript()) {
            return true;
        }

        String path = msg.getRequestHeader().getURI().getEscapedPath();
        if (path != null) {
            return PATTERN_JS_EXTENSIONS.matcher(path).find();
        }
        return false;
    }

    /**
     * Returns whether or not the given {@link HttpMessage} has an image content type in its
     * response or request URL path.
     *
     * @param msg the {@link HttpMessage} to check
     * @return {@code true} if the given {@link HttpMessage} has an image content type in its
     *     response or request URL path, {@code false} otherwise.
     */
    public static boolean isImage(HttpMessage msg) {
        return msg.getResponseHeader().isImage() || msg.getRequestHeader().isImage();
    }

    /**
     * Returns whether or not the given {@link HttpMessage} has a CSS content type in its response
     * or request URL path.
     *
     * @param msg the {@link HttpMessage} to check
     * @return {@code true} if the given {@link HttpMessage} has a CSS content type in its response
     *     or request URL path, {@code false} otherwise.
     */
    public static boolean isCss(HttpMessage msg) {
        return msg.getResponseHeader().isCss() || msg.getRequestHeader().isCss();
    }

    /**
     * Returns whether or not the response of the passed {@link HttpMessage} contains control
     * characters other than whitespace (such as carriage return, line feed, tab).
     *
     * @param msg the {@code HttpMessage} to be assessed
     * @return {@code true} if the response does contain non-whitespace control characters, {@code
     *     false} otherwise.
     */
    public static boolean responseContainsControlChars(HttpMessage msg) {
        String content = msg.getResponseBody().toString();
        return content.codePoints()
                .filter(cp -> !Character.isWhitespace(cp))
                .anyMatch(Character::isISOControl);
    }
}
