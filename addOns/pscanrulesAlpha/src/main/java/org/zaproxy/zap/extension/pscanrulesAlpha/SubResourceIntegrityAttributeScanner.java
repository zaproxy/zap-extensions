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

import static net.htmlparser.jericho.HTMLElementName.LINK;
import static net.htmlparser.jericho.HTMLElementName.SCRIPT;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Detect missing attribute integrity in tag <script> */
public class SubResourceIntegrityAttributeScanner extends PluginPassiveScanner {
    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.sri-integrity.";

    // From
    // https://w3c.github.io/webappsec-subresource-integrity/#verification-of-html-document-subresources
    // To support integrity metadata for some of these elements, a new integrity attribute is added
    // to
    // the list of content attributes for the link and script elements.
    // Note: A future revision of this specification is likely to include integrity support for all
    // possible subresources, i.e., a, audio, embed, iframe, img, link, object, script, source,
    // track,
    // and video elements.
    private static final List<String> SUPPORTED_ELEMENTS = Arrays.asList(SCRIPT, LINK);

    private static final Map<String, String> CONTENT_ATTRIBUTES = new HashMap<String, String>();

    static {
        CONTENT_ATTRIBUTES.put(SCRIPT, "src");
        CONTENT_ATTRIBUTES.put(LINK, "href");
    }

    // TODO Replace "rules.domains.trusted" with RuleConfigParam.RULE_DOMAINS_TRUSTED once
    // available.
    static final String TRUSTED_DOMAINS_PROPERTY = "rules.domains.trusted";

    private PassiveScanThread parent;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        Collection<String> trustedDomains =
                Stream.of(getConfig().getString(TRUSTED_DOMAINS_PROPERTY, "").split(","))
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toList());

        List<Element> sourceElements = source.getAllElements();
        sourceElements.stream()
                .filter(element -> SUPPORTED_ELEMENTS.contains(element.getName()))
                .filter(excludeSafeResourceFrom(trustedDomains))
                .filter(unsafeSubResource(msg.getRequestHeader().getHostName()))
                .forEach(
                        element -> {
                            Alert alert =
                                    new Alert(
                                            getPluginId(),
                                            Alert.RISK_MEDIUM,
                                            Alert.CONFIDENCE_HIGH,
                                            getName());

                            alert.setDetail(
                                    getString("desc"),
                                    msg.getRequestHeader().getURI().toString(),
                                    "",
                                    "",
                                    "",
                                    getString("soln"),
                                    getString("refs"),
                                    element.toString(),
                                    16, // CWE CATEGORY: Configuration
                                    15, // Application Misconfiguration
                                    msg);
                            parent.raiseAlert(id, alert);
                        });
    }

    private Predicate<Element> excludeSafeResourceFrom(Collection<String> trustedDomains) {
        return element -> {
            String domain = element.getAttributeValue(CONTENT_ATTRIBUTES.get(element.getName()));
            return trustedDomains.stream().noneMatch(domain::matches);
        };
    }

    private static Predicate<Element> unsafeSubResource(String hostname) {
        return element ->
                element.getAttributeValue("integrity") == null
                        && !element.getAttributeValue(CONTENT_ATTRIBUTES.get(element.getName()))
                                .matches("^https?://[^/]*" + hostname + "/.*");
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public String getName() {
        return getString("name");
    }

    private String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param);
    }

    @Override
    public int getPluginId() {
        return 90003;
    }
}
