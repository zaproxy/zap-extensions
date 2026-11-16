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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpMessage;

/** Utility methods for HTML forms. */
final class FormUtils {

    /**
     * A URL a form can be submitted to.
     *
     * @param url the trimmed value of the {@code action} or {@code formaction} attribute.
     * @param element the element containing the URL, the form or one of its submit buttons.
     */
    record SubmissionTarget(String url, Element element) {}

    private FormUtils() {}

    /**
     * Gets the URLs the given form can be submitted to, that is, its {@code action} and the {@code
     * formaction} of its submit buttons, which overrides the {@code action}.
     *
     * @param form the form element.
     * @return the submission targets, never {@code null}.
     */
    static List<SubmissionTarget> getSubmissionTargets(Element form) {
        List<SubmissionTarget> targets = new ArrayList<>();
        addTarget(targets, form, "action");
        for (Element element : form.getAllElements()) {
            if (isSubmitButton(element)) {
                addTarget(targets, element, "formaction");
            }
        }
        return targets;
    }

    /**
     * Tells whether or not the given URL, resolved against the request URI of the message, has the
     * given scheme.
     *
     * @param msg the message that contains the URL.
     * @param url the URL, absolute or relative.
     * @param scheme the scheme, for example, {@code http}.
     * @return {@code true} if the resolved URL has the given scheme, {@code false} otherwise.
     */
    static boolean hasScheme(HttpMessage msg, String url, String scheme) {
        try {
            return scheme.equalsIgnoreCase(
                    new URI(msg.getRequestHeader().getURI(), new URI(url, false)).getScheme());
        } catch (URIException e) {
            return false;
        }
    }

    private static void addTarget(List<SubmissionTarget> targets, Element element, String attr) {
        String url = element.getAttributeValue(attr);
        if (url != null) {
            targets.add(new SubmissionTarget(url.trim(), element));
        }
    }

    private static boolean isSubmitButton(Element element) {
        String type = element.getAttributeValue("type");
        return switch (element.getName()) {
            // A missing or invalid type defaults to submit.
            case HTMLElementName.BUTTON ->
                    !"reset".equalsIgnoreCase(type) && !"button".equalsIgnoreCase(type);
            case HTMLElementName.INPUT ->
                    "submit".equalsIgnoreCase(type) || "image".equalsIgnoreCase(type);
            default -> false;
        };
    }
}
