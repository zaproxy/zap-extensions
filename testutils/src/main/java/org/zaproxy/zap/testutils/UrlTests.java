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
package org.zaproxy.zap.testutils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assumptions.assumingThat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.testutils.UrlValidationError.Cause;

public interface UrlTests {

    Pattern META_REFRESH_PATTERN = Pattern.compile("url\\s*=\\s*[\"']?([^'\"]*)[\"']?");

    default void shouldHaveValidUrls(Collection<String> urls) {
        if (urls.isEmpty()) {
            return;
        }

        List<UrlValidationError> errors = new ArrayList<>();
        for (String url : urls) {
            if (!url.startsWith(HttpHeader.HTTP)) {
                errors.add(UrlValidationError.Cause.NOT_LINK.create(url, ""));
                continue;
            }

            URI uri;
            try {
                uri = new URI(url, true);
            } catch (Exception e) {
                errors.add(UrlValidationError.Cause.INVALID_URI.create(url, e));
                continue;
            }

            if (!HttpHeader.HTTPS.equals(uri.getScheme())) {
                errors.add(UrlValidationError.Cause.NOT_HTTPS.create(url, ""));
            } else {
                assumingThat(
                        "1".equals(System.getenv("ZAP_REMOTE_TESTS")),
                        () -> fetchUrl(uri, url, errors));
            }
        }

        assertThat(errors.toString(), errors, is(empty()));
    }

    default boolean isAllowedUrlValidationError(
            UrlValidationError.Cause cause, String reference, Object detail) {
        return false;
    }

    private void fetchUrl(URI uri, String reference, List<UrlValidationError> errors) {
        try {
            HttpMessage message = new HttpMessage(uri);
            List<URI> redirections = new ArrayList<>();
            new HttpSender(0)
                    .sendAndReceive(
                            message,
                            HttpRequestConfig.builder()
                                    .setRedirectionValidator(redirections::add)
                                    .build());
            var responseHeader = message.getResponseHeader();
            int statusCode = responseHeader.getStatusCode();
            if (statusCode == 429) {
                // Assume exists.
            } else if (statusCode != HttpStatusCode.OK) {
                addErrorIfNotAllowed(
                        errors,
                        UrlValidationError.Cause.UNEXPECTED_STATUS_CODE,
                        reference,
                        statusCode);
            } else if (!redirections.isEmpty()) {
                addErrorIfNotAllowed(
                        errors,
                        UrlValidationError.Cause.REDIRECTED,
                        reference,
                        redirections.get(redirections.size() - 1));
            } else {
                String metaRefreshUrl = getMetaRefreshUrl(message.getResponseBody().toString());
                if (metaRefreshUrl != null) {
                    addErrorIfNotAllowed(
                            errors,
                            UrlValidationError.Cause.META_REFRESH,
                            reference,
                            metaRefreshUrl);
                }
            }
        } catch (IOException e) {
            addErrorIfNotAllowed(errors, UrlValidationError.Cause.IO_EXCEPTION, reference, e);
        }
    }

    private static String getMetaRefreshUrl(String responseBody) {
        Source htmlSource = new Source(responseBody);
        for (var element : htmlSource.getAllElements(HTMLElementName.META)) {
            String httpEquiv = element.getAttributeValue("http-equiv");
            if ("refresh".equalsIgnoreCase(httpEquiv)) {
                String content = element.getAttributeValue("content");
                if (content != null) {
                    Matcher matcher = META_REFRESH_PATTERN.matcher(content);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                }
            }
        }
        return null;
    }

    private void addErrorIfNotAllowed(
            List<UrlValidationError> errors, Cause cause, String reference, Object detail) {
        if (isAllowedUrlValidationError(cause, reference, detail)) {
            return;
        }
        errors.add(cause.create(reference, detail));
    }
}
