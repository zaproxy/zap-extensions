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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Detect missing attribute integrity in supported elements */
public class SubResourceIntegrityAttributeScanRule extends PluginPassiveScanner {

    private enum SupportedElements {
        // From
        // https://w3c.github.io/webappsec-subresource-integrity/#verification-of-html-document-subresources
        // To support integrity metadata for some of these elements, a new integrity attribute is
        // added
        // to the list of content attributes for the link and script elements.
        // Note: A future revision of this specification is likely to include integrity support for
        // all
        // possible subresources, i.e., a, audio, embed, iframe, img, link, object, script, source,
        // track, and video elements.

        SCRIPT(HTMLElementName.SCRIPT, "src"),
        LINK(HTMLElementName.LINK, "href");

        final String tag;
        final String attribute;

        SupportedElements(String tag, String attribute) {
            this.tag = tag;
            this.attribute = attribute;
        }

        public static boolean contains(String tag) {
            return Stream.of(values()).anyMatch(e -> tag.equals(e.tag));
        }

        public static Optional<String> getHost(Element element, String origin) {
            String url =
                    element.getAttributeValue(
                            SupportedElements.valueOf(element.getName().toUpperCase(Locale.ROOT))
                                    .attribute);
            if (url == null || url.startsWith("data:")) {
                return Optional.of(origin);
            }
            URI uri = null;

            try {
                uri = new URI(url);
            } catch (URISyntaxException e) {
                return Optional.empty();
            }
            if (!uri.isAbsolute()) {
                return Optional.of(origin);
            }
            return Optional.ofNullable(uri.getHost());
        }
    }

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.sri-integrity.";

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        List<Element> sourceElements = source.getAllElements();
        sourceElements.stream()
                .filter(element -> SupportedElements.contains(element.getName()))
                .filter(unsafeSubResource(msg.getRequestHeader().getHostName()))
                .forEach(
                        element -> {
                            newAlert()
                                    .setRisk(Alert.RISK_MEDIUM)
                                    .setConfidence(Alert.CONFIDENCE_HIGH)
                                    .setDescription(getString("desc"))
                                    .setSolution(getString("soln"))
                                    .setReference(getString("refs"))
                                    .setEvidence(element.toString())
                                    .setCweId(16) // CWE CATEGORY: Configuration
                                    .setWascId(15) // Application Misconfiguration
                                    .raise();
                        });
    }

    private static Predicate<Element> unsafeSubResource(String origin) {
        return element -> {
            Optional<String> maybeHostname = SupportedElements.getHost(element, origin);
            return element.getAttributeValue("integrity") == null
                    && !maybeHostname.map(hostname -> hostname.matches(origin)).orElse(false);
        };
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return getString("name");
    }

    private static String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param);
    }

    @Override
    public int getPluginId() {
        return 90003;
    }
}
