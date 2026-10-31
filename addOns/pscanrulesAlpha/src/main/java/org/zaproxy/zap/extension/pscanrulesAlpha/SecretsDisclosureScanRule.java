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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksConfigLoader;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksConfigLoader.Config;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksRule;

/**
 * Detects secrets (API keys, tokens, private keys...) in responses, using the patterns of the
 * Gitleaks default config.
 *
 * <p>Images, fonts, and binary content are skipped. Binary content is detected with {@link
 * #isBinary}, which is deliberately not the commonlib {@code
 * ResourceIdentificationUtils#responseContainsControlChars}.
 *
 * <p>The generic rule ({@value #GENERIC_RULE_ID}) is the slowest, as it can't be limited to the
 * windows around its keywords (they are too common), and the noisiest, so it is only run at Low
 * threshold.
 *
 * <p>Each response is scanned as follows:
 *
 * <ol>
 *   <li>At High threshold the request path is matched against the allowlist paths. In Gitleaks an
 *       allowlist holds what to ignore (e.g. vendored libraries), so if the path matches, the
 *       message is not scanned. This is the cheapest check, done first. If no path matches (or
 *       there are none) the scan continues.
 *   <li>Each Gitleaks rule is run against the body, see {@link GitleaksRule#find}, giving at most
 *       one finding per rule (the generic rule is skipped, unless the threshold is Low), and an
 *       alert is raised for each.
 * </ol>
 */
public class SecretsDisclosureScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final int PLUGIN_ID = 10005;
    private static final String MESSAGE_PREFIX = "pscanalpha.secrets.";

    /**
     * The path of the bundled Gitleaks default config ({@code gitleaks.toml}), which is a copy of
     * the one of <a href="https://github.com/gitleaks/gitleaks">Gitleaks</a>, updated
     * automatically.
     *
     * <p>Gitleaks is licensed under the MIT License, Copyright (c) 2019 Zachary Rice, see <a
     * href="https://github.com/gitleaks/gitleaks/blob/master/LICENSE">its licence</a>.
     */
    private static final String CONFIG_RESOURCE =
            "/org/zaproxy/zap/extension/pscanrulesAlpha/resources/gitleaks.toml";

    private static final int MAX_CONTROL_CHARS_PERCENT = 1;
    private static final String GENERIC_RULE_ID = "generic-api-key";

    /**
     * The rules which match values that are usually public by design, as they are meant to be used
     * in client side code, so their alerts have a lower risk and confidence. Gitleaks does not tell
     * those rules apart, it reports any credential like value found in a source repository.
     *
     * <p>Google API keys ({@code gcp-api-key}) are deliberately not included: although many are
     * public (e.g. Maps), an unrestricted key can also access other APIs enabled in its project,
     * such as Gemini, which has a cost and data impact, and a passive scan can't tell if it is
     * restricted.
     *
     * <ul>
     *   <li>Publishable and public keys: Flutterwave (test public keys), Lob, Mailgun (public
     *       validation key) and Mapbox ({@code pk.} tokens).
     *   <li>Browser and client side tokens: New Relic browser, GitLab feature flag client.
     *   <li>Algolia, as its search only keys are public, but they have the same format as the admin
     *       keys, so they can't be told apart.
     *   <li>OAuth client IDs, which are public (they are in the authorization URLs), unlike the
     *       client secrets.
     * </ul>
     */
    private static final Set<String> PUBLIC_BY_DESIGN_RULE_IDS =
            Set.of(
                    "adobe-client-id",
                    "algolia-api-key",
                    "asana-client-id",
                    "bitbucket-client-id",
                    "discord-client-id",
                    "flutterwave-public-key",
                    "gitlab-feature-flag-client-token",
                    "linkedin-client-id",
                    "lob-pub-api-key",
                    "looker-client-id",
                    "mailgun-pub-key",
                    "mapbox-api-token",
                    "messagebird-client-id",
                    "new-relic-browser-api-token",
                    "plaid-client-id");

    private static final String EXAMPLE_RULE_ID = "aws-access-token";
    private static final String EXAMPLE_SECRET = "AKIAQYLPMN5HFIQR7XYZ";

    private static final int MAX_EVIDENCE_LENGTH = 256;
    private static final Logger LOGGER = LogManager.getLogger(SecretsDisclosureScanRule.class);

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL,
                                CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL,
                                CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                                CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /** Loads the bundled Gitleaks config once, when first needed. */
    private static final class ConfigHolder {
        static final Config CONFIG = loadConfig();
    }

    // Visible for testing. Null if the config failed to load, the rule then does nothing.
    final Config config;

    public SecretsDisclosureScanRule() {
        this(ConfigHolder.CONFIG);
    }

    SecretsDisclosureScanRule(Config config) {
        this.config = config;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (config == null) {
            return;
        }
        if (ResourceIdentificationUtils.isImage(msg) || ResourceIdentificationUtils.isFont(msg)) {
            return;
        }
        String body = msg.getResponseBody().toString();
        if (body.isEmpty()) {
            return;
        }
        // The allowlists paths are only used at High threshold, they can hide real issues.
        String path =
                getAlertThreshold() == AlertThreshold.HIGH
                        ? msg.getRequestHeader().getURI().getEscapedPath()
                        : null;
        if (config.global().allowsPath(path)) {
            return;
        }
        // Binary content is not worth scanning and causes noise.
        if (isBinary(body)) {
            return;
        }
        String lowerCaseBody = toLowerCase(body);
        boolean skipGeneric = getAlertThreshold() != AlertThreshold.LOW;
        for (GitleaksRule rule : config.rules()) {
            if (skipGeneric && GENERIC_RULE_ID.equals(rule.getId())) {
                continue;
            }
            rule.find(body, lowerCaseBody, config.global(), path)
                    .ifPresent(
                            finding -> {
                                LOGGER.debug("Found secret, Gitleaks rule: {}", finding.ruleId());
                                buildAlert(finding).raise();
                            });
        }
    }

    /**
     * Lower cases the content character by character, so that the offsets are the same as in the
     * content (String#toLowerCase changes the length for some characters, e.g. U+0130).
     */
    private static String toLowerCase(String content) {
        char[] chars = content.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = Character.toLowerCase(chars[i]);
        }
        return new String(chars);
    }

    /**
     * Tells whether the content is binary, which is the case if more than {@value
     * #MAX_CONTROL_CHARS_PERCENT}% of its characters are control characters, which are rare in
     * text. Binary content has far more, typically 10% or more of its bytes, so a stray character
     * in a large text file (e.g. a {@code \u0001} placeholder in minified JS) is not enough to skip
     * it.
     *
     * <p>Only the C0 control characters (U+0000 to U+001F) other than whitespace count, e.g. NUL,
     * which is in practically all binary content.
     *
     * <p>This is deliberately not the commonlib {@code
     * ResourceIdentificationUtils#responseContainsControlChars}, which uses {@link
     * Character#isISOControl} and so also counts DEL (U+007F) and the C1 control characters (U+0080
     * to U+009F), and any single one of them makes it return {@code true}. Those show up in text
     * served with the wrong charset, for example Windows-1252 (curly quotes, dashes) or UTF-8
     * labelled as ISO-8859-1, and treating it as binary would skip the whole response, and any
     * secrets in it.
     *
     * <p>Whitespace as defined by {@link Character#isWhitespace}, includes the C0 characters tab,
     * line feed, vertical tab, form feed, carriage return and U+001C to U+001F.
     */
    private static boolean isBinary(String content) {
        long max = content.length() * MAX_CONTROL_CHARS_PERCENT / 100;
        long count = 0;
        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c < ' ' && !Character.isWhitespace(c) && ++count > max) {
                return true;
            }
        }
        return false;
    }

    private AlertBuilder buildAlert(GitleaksRule.Finding finding) {
        String evidence = finding.match();
        if (evidence.length() > MAX_EVIDENCE_LENGTH) {
            evidence = evidence.substring(0, MAX_EVIDENCE_LENGTH);
        }
        boolean publicByDesign = PUBLIC_BY_DESIGN_RULE_IDS.contains(finding.ruleId());
        return newAlert()
                .setName(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "alert.name", finding.ruleId()))
                .setConfidence(
                        publicByDesign || GENERIC_RULE_ID.equals(finding.ruleId())
                                ? Alert.CONFIDENCE_LOW
                                : Alert.CONFIDENCE_MEDIUM)
                .setRisk(publicByDesign ? Alert.RISK_LOW : Alert.RISK_HIGH)
                .setEvidence(evidence)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo",
                                finding.ruleId(),
                                finding.description()))
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setWascId(13) // WASC-13 Information Leakage
                .setCweId(798); // CWE-798: Use of Hard-coded Credentials
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        GitleaksRule rule =
                config.rules().stream()
                        .filter(r -> EXAMPLE_RULE_ID.equals(r.getId()))
                        .findFirst()
                        .orElseThrow();
        GitleaksRule.Finding finding =
                rule.find(EXAMPLE_SECRET, toLowerCase(EXAMPLE_SECRET), config.global(), null)
                        .orElseThrow();
        return List.of(buildAlert(finding).build());
    }

    private static Config loadConfig() {
        try (InputStream is =
                SecretsDisclosureScanRule.class.getResourceAsStream(CONFIG_RESOURCE)) {
            return GitleaksConfigLoader.load(is);
        } catch (IOException | RuntimeException e) {
            LOGGER.error("Failed to load the Gitleaks config, the rule is disabled.", e);
            return null;
        }
    }
}
