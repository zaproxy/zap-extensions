/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContext;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContextAnalyser;

public class CrossSiteScriptingScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.crosssitescripting.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A07_XSS,
                                CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_CICD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    protected static final String GENERIC_SCRIPT_ALERT = "<scrIpt>alert(1);</scRipt>";
    protected static final String GENERIC_ONERROR_ALERT = "<img src=x onerror=prompt()>";
    protected static final String IMG_ONERROR_LOG = "<img src=x onerror=console.log(1);>";
    protected static final String SVG_ONLOAD_ALERT = "<svg onload=alert(1)>";
    protected static final String B_MOUSE_ALERT = "<b onMouseOver=alert(1);>test</b>";
    protected static final String ACCESSKEY_ATTRIBUTE_ALERT = "accesskey='x' onclick='alert(1)' b";
    protected static final String TAG_ONCLICK_ALERT = "button onclick='alert(1)'/";

    /**
     * Null byte injection payload. C/C++ languages treat Null byte or \0 as special character which
     * marks end of the String so if validators are written in C/C++ then validators might not check
     * bytes after null byte and hence can be bypassed.
     */
    private static final String GENERIC_NULL_BYTE_SCRIPT_ALERT =
            NULL_BYTE_CHARACTER + GENERIC_SCRIPT_ALERT;

    private static final List<String> GENERIC_SCRIPT_ALERT_LIST =
            Arrays.asList(
                    GENERIC_SCRIPT_ALERT, GENERIC_NULL_BYTE_SCRIPT_ALERT, GENERIC_ONERROR_ALERT);
    private static final List<Integer> GET_POST_TYPES =
            Arrays.asList(NameValuePair.TYPE_QUERY_STRING, NameValuePair.TYPE_POST_DATA);

    private static final List<String> OUTSIDE_OF_TAGS_PAYLOADS =
            Arrays.asList(
                    GENERIC_SCRIPT_ALERT,
                    GENERIC_NULL_BYTE_SCRIPT_ALERT,
                    GENERIC_ONERROR_ALERT,
                    IMG_ONERROR_LOG,
                    B_MOUSE_ALERT,
                    SVG_ONLOAD_ALERT,
                    getURLEncode(GENERIC_SCRIPT_ALERT));

    private static final String HEADER_SPLITTING = "\n\r\n\r";

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_8");
    private static final Logger LOGGER = LogManager.getLogger(CrossSiteScriptingScanRule.class);
    private int currentParamType;

    /**
     * Stores the eyecatcher baseline response for the current scan. Used by eyecatcher-based
     * comparison detection to identify new XSS blocks that appear only in payload responses.
     */
    private HttpMessage eyecatcherMessage;

    private static final char FULL_WIDTH_LESS_THAN_CHAR = '＜';
    private static final char FULL_WIDTH_GREATER_THAN_CHAR = '＞';

    /**
     * Mutations can either be where one character can be safely replaced by another or where one
     * character can be incorrectly converted back to the original
     */
    private static final List<List<Mutation>> MUTATIONS =
            List.of(
                    List.of(new Mutation('(', '`'), new Mutation(')', '`')),
                    List.of(
                            new Mutation('<', FULL_WIDTH_LESS_THAN_CHAR, true),
                            new Mutation('>', FULL_WIDTH_GREATER_THAN_CHAR, true)),
                    List.of(
                            new Mutation('(', '`'),
                            new Mutation(')', '`'),
                            new Mutation('<', FULL_WIDTH_LESS_THAN_CHAR, true),
                            new Mutation('>', FULL_WIDTH_GREATER_THAN_CHAR, true)));

    @Override
    public int getId() {
        return 40012;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        currentParamType = originalParam.getType();
        super.scan(msg, originalParam);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            int ignoreFlags) {
        return performAttack(msg, param, attack, targetContext, ignoreFlags, false, false, false);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            int ignoreFlags,
            boolean findDecoded) {
        return performAttack(
                msg, param, attack, targetContext, ignoreFlags, findDecoded, false, false);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            int ignoreFlags,
            boolean findDecoded,
            boolean isNullByteSpecialHandling,
            boolean ignoreSafeParents) {
        return this.performAttack(
                msg,
                param,
                attack,
                targetContext,
                attack,
                ignoreFlags,
                findDecoded,
                isNullByteSpecialHandling,
                ignoreSafeParents);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            String evidence,
            int ignoreFlags,
            boolean findDecoded,
            boolean isNullByteSpecialHandling,
            boolean ignoreSafeParents) {
        return this.performAttack(
                msg,
                param,
                attack,
                targetContext,
                evidence,
                ignoreFlags,
                findDecoded,
                isNullByteSpecialHandling,
                ignoreSafeParents,
                false);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            String evidence,
            int ignoreFlags,
            boolean findDecoded,
            boolean isNullByteSpecialHandling,
            boolean ignoreSafeParents,
            boolean mutateAttack) {
        if (isStop()) {
            return null;
        }

        HttpMessage msg2 = msg.cloneRequest();
        setParameter(msg2, param, attack);
        try {
            sendAndReceive(msg2);
        } catch (URIException e) {
            LOGGER.debug("Failed to send HTTP message, cause: {}", e.getMessage());
            return null;
        } catch (UnknownHostException e) {
            // Not an error, just means we probably attacked the redirect
            // location
            return null;
        } catch (IOException e) {
            LOGGER.debug(e.getMessage(), e);
        }

        if (isStop()) {
            return null;
        }
        if (isNullByteSpecialHandling) {
            /* Special handling for case where Attack Vector is reflected outside of html tag.
             * Removing Null Byte as parser tries to find the enclosing tag on attack vector (e.g.
             * \0<script>alert(1);</script>) starting from first character
             * and as null byte is not starting any tag and there is no enclosing tag for null byte
             * so parent context is null.
             */
            attack = attack.replaceFirst(NULL_BYTE_CHARACTER, "");
            evidence = attack;
        }
        HtmlContextAnalyser hca = new HtmlContextAnalyser(msg2);
        List<HtmlContext> contexts;
        if (Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            // Low level, so don't check all results are in the expected context
            contexts =
                    hca.getHtmlContexts(
                            findDecoded ? getURLDecode(evidence) : evidence,
                            null,
                            0,
                            ignoreSafeParents);
        } else {
            // High or Medium level, so check all results are in the expected context
            contexts =
                    hca.getHtmlContexts(
                            findDecoded ? getURLDecode(evidence) : evidence,
                            targetContext,
                            ignoreFlags,
                            ignoreSafeParents);
        }

        if (mutateAttack || !contexts.isEmpty()) {
            return contexts;
        }
        return this.mutateAttack(
                msg2,
                param,
                attack,
                targetContext,
                evidence,
                ignoreFlags,
                findDecoded,
                isNullByteSpecialHandling,
                ignoreSafeParents);
    }

    /**
     * Detects XSS when an injected {@code alert()} (or similar) appears in a short, standalone
     * {@code <script>} element in the response. This is indicative of script-breaking payloads such
     * as {@code </script><scrIpt>alert(1);</scRipt><script>} being parsed so that the injected
     * script becomes its own executable script element.
     *
     * <p><b>How it works:</b> HTML parsers process {@code </script>} tags before JavaScript
     * execution. Even if a payload is inside {@code eval(escape('...'))}, the HTML parser closes
     * the script tag when it encounters {@code </script>}, creating a new executable script
     * context.
     *
     * <p><b>Detection methods (in order):</b>
     *
     * <ol>
     *   <li><b>Pattern matching:</b> Searches for regex patterns like {@code
     *       </script><script>alert(...)</script>} in the raw HTML
     *   <li><b>Jericho parsing with length heuristic:</b> Uses the Jericho HTML parser to find
     *       script elements, then applies a length heuristic ({@link #MAX_INJECTED_SCRIPT_LENGTH})
     *       to identify likely injected scripts
     * </ol>
     *
     * <p><b>Note:</b> This serves as a fallback detection method. The primary detection strategy
     * uses eyecatcher-based comparison to identify new XSS patterns that appear only in payload
     * responses.
     *
     * @param msg2 The HTTP response message
     * @param attack The attack payload sent
     * @param evidence The evidence string to search for (e.g., {@code alert(1)})
     * @return List of HtmlContext if XSS is detected via analysis of standalone script elements,
     *     empty list otherwise
     */
    private List<HtmlContext> detectFragmentedScriptInjection(
            HttpMessage msg2, String attack, String evidence) {
        String responseBody = msg2.getResponseBody().toString();

        // Look for key components of script-breaking XSS
        // Component 1: </script> that closes original script
        // Component 2: alert(1) or similar in a NEW script element

        LOGGER.debug(
                "detectFragmentedScriptInjection: checking response of length {}",
                responseBody.length());

        // Case-insensitive check for script closing tags and alert patterns
        String responseBodyLower = responseBody.toLowerCase();
        boolean hasScriptClose = responseBodyLower.contains("</script>");
        boolean hasAlert = responseBodyLower.contains("alert(");

        LOGGER.debug("Contains </script> (case-insensitive): {}", hasScriptClose);
        LOGGER.debug("Contains alert( (case-insensitive): {}", hasAlert);
        LOGGER.debug(
                "Response body (first 500 chars): {}",
                responseBody.substring(0, Math.min(500, responseBody.length())));

        if (!hasScriptClose || !hasAlert) {
            LOGGER.debug("Skipping fragmented detection - missing required components");
            return List.of();
        }

        // NEW: Check for script-breaking XSS pattern in raw HTML
        // Pattern: </script><script>alert(...)</script>
        // This handles cases where Jericho treats script content as raw text
        Pattern scriptBreakPattern =
                Pattern.compile(
                        "</script>\\s*<scr[iI]pt[^>]*>\\s*alert\\([^)]*\\)",
                        Pattern.CASE_INSENSITIVE);
        Matcher matcher = scriptBreakPattern.matcher(responseBody);

        if (matcher.find()) {
            int matchStart = matcher.start();
            int matchEnd = matcher.end();

            LOGGER.info(
                    "✓ detectFragmentedScriptInjection: Pattern-based detection SUCCESS at position {}",
                    matchStart);
            LOGGER.debug("Detected script-breaking XSS pattern at position {}", matchStart);
            LOGGER.debug(
                    "Matched pattern: '{}'",
                    responseBody.substring(
                            matchStart, Math.min(matchEnd + 20, responseBody.length())));

            // Create context for the script-breaking XSS
            HtmlContext context = new HtmlContext(msg2, evidence, matchStart, matchEnd);
            context.addParentTag("script");
            context.addParentTag("body");
            context.addParentTag("html");

            return List.of(context);
        }

        // EXISTING: Jericho-based detection (keep as fallback for other cases)
        // Use Jericho to parse HTML and find script elements
        Source src = new Source(responseBody);
        src.fullSequentialParse();

        // Search for alert(1) or alert(1); in the response
        String[] alertPatterns = {"alert(1)", "alert(1);"};
        for (String alertPattern : alertPatterns) {
            int alertPos = responseBody.indexOf(alertPattern);
            LOGGER.debug(
                    "Searching for pattern '{}', found at position: {}", alertPattern, alertPos);
            if (alertPos >= 0) {
                // Found alert() - check if it's in a script element
                Element enclosingElement = src.getEnclosingElement(alertPos);
                LOGGER.debug(
                        "Enclosing element: {}",
                        enclosingElement != null ? enclosingElement.getName() : "null");
                if (enclosingElement != null
                        && "script".equalsIgnoreCase(enclosingElement.getName())) {
                    // Verify this is a standalone injected script element
                    // by checking if the ENTIRE script content is just our payload
                    String scriptContent = enclosingElement.getContent().toString().trim();
                    LOGGER.debug("Script element content: '{}'", scriptContent);

                    // Only flag if the script element contains ONLY the alert pattern
                    // (possibly with whitespace/semicolons) - this indicates a successful
                    // script-breaking injection, not legitimate application code
                    if (scriptContent.equals(alertPattern)
                            || scriptContent.equals(alertPattern + ";")
                            || scriptContent.trim().equals(alertPattern)) {
                        // alert() is in a standalone/injected script element
                        HtmlContext context =
                                new HtmlContext(
                                        msg2, evidence, alertPos, alertPos + alertPattern.length());
                        context.addParentTag("script");
                        context.addParentTag("body");
                        context.addParentTag("html");

                        LOGGER.info(
                                "✓ detectFragmentedScriptInjection: Jericho-based detection SUCCESS - standalone script at position {}",
                                alertPos);
                        LOGGER.debug(
                                "Detected fragmented script injection: alert() found in standalone script element at position {}",
                                alertPos);
                        return List.of(context);
                    } else {
                        LOGGER.debug(
                                "Script element contains additional code, likely not a pure injection");
                    }
                }
            }
        }

        LOGGER.debug("No fragmented script injection detected");
        return List.of();
    }

    /**
     * Performs eyecatcher-based comparison detection to identify XSS vulnerabilities. This method
     * uses ComparableResponse to detect structural HTML changes and HtmlContextAnalyser to verify
     * that new script elements contain only our injected payload.
     *
     * <p><b>Strategy:</b>
     *
     * <ol>
     *   <li>Use ComparableResponse to compare eyecatcher vs payload responses
     *   <li>Check if the payload response contains new script elements with standalone XSS payloads
     *   <li>Use HtmlContextAnalyser to verify the payload is in an exploitable script context
     *   <li>Only flag as vulnerable if a NEW standalone script element contains ONLY our payload
     * </ol>
     *
     * <p>This conservative approach minimizes false positives by only detecting cases where: (1)
     * the response structure changed, (2) a new script element appeared, and (3) it contains only
     * our attack payload (not legitimate filtered/escaped content).
     *
     * @param eyecatcherMsg The baseline eyecatcher HTTP message
     * @param payloadMsg The HTTP message with the XSS payload
     * @param payload The attack payload that was sent
     * @return true if new exploitable XSS context detected, false otherwise
     */
    private boolean detectXssViaEyecatcherComparison(
            HttpMessage eyecatcherMsg, HttpMessage payloadMsg, String payload) {
        try {
            // Use ComparableResponse to detect if there are structural differences
            ComparableResponse eyecatcherResp = new ComparableResponse(eyecatcherMsg, payload);
            ComparableResponse payloadResp = new ComparableResponse(payloadMsg, payload);

            // If responses are equivalent (same structure), no new XSS context was created
            if (eyecatcherResp.equals(payloadResp)) {
                LOGGER.debug("Responses are structurally equivalent, no new XSS context");
                return false;
            }

            LOGGER.info(
                    "detectXssViaEyecatcherComparison: Structural difference detected, analyzing script elements...");
            LOGGER.debug("Structural difference detected between eyecatcher and payload responses");

            // Parse the payload response to find script elements
            Source src = new Source(payloadMsg.getResponseBody().toString());
            src.fullSequentialParse();
            List<Element> scriptElements = src.getAllElements("script");

            // Check if any script element contains ONLY our alert payload
            String[] alertPatterns = {"alert(1)", "alert(1);"};
            for (Element scriptElement : scriptElements) {
                String scriptContent = scriptElement.getContent().toString().trim();
                for (String alertPattern : alertPatterns) {
                    if (scriptContent.equals(alertPattern)
                            || scriptContent.equals(alertPattern + ";")
                            || scriptContent.trim().equals(alertPattern)) {
                        LOGGER.info(
                                "✓ detectXssViaEyecatcherComparison: SUCCESS - Found standalone injected script: '{}'",
                                scriptContent);
                        LOGGER.debug(
                                "Found standalone injected script element with content: '{}'",
                                scriptContent);
                        return true;
                    }
                }
            }

            LOGGER.debug(
                    "Structural changes detected but no standalone injected script elements found");
            return false;

        } catch (Exception e) {
            LOGGER.debug("Error during eyecatcher comparison: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Attempts to detect XSS using script-breaking payloads with both eyecatcher-based comparison
     * and fragmented script detection. This consolidates the detection logic used across multiple
     * attack methods.
     *
     * <p><b>Detection strategy:</b>
     *
     * <ol>
     *   <li><b>PRIMARY:</b> Eyecatcher-based comparison (if eyecatcher available)
     *   <li><b>FALLBACK:</b> Fragmented script injection detection
     * </ol>
     *
     * <p><b>Note:</b> This method is skipped for LOW attack strength to minimize the number of HTTP
     * requests sent during scanning.
     *
     * @param msg The original HTTP message
     * @param param The parameter name being tested
     * @param useProcessContexts If true, use processContexts() to raise alerts; if false, return
     *     contexts for caller to handle
     * @return true if XSS detected and alert raised (when useProcessContexts=true), false otherwise
     */
    private boolean tryScriptBreakingDetection(
            HttpMessage msg, String param, boolean useProcessContexts) {
        // Skip script-breaking detection for LOW attack strength to reduce HTTP request count
        if (Plugin.AttackStrength.LOW.equals(this.getAttackStrength())) {
            LOGGER.debug("Skipping script-breaking detection for LOW attack strength");
            return false;
        }

        LOGGER.info(
                "tryScriptBreakingDetection: Starting script-breaking detection for param '{}'",
                param);

        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            HttpMessage msg2 = getNewMsg();
            setParameter(msg2, param, scriptAlert);
            try {
                sendAndReceive(msg2);
            } catch (Exception e) {
                LOGGER.debug("Failed to send script-breaking attack payload", e);
                continue;
            }

            // Primary detection: eyecatcher-based comparison (if available)
            if (eyecatcherMessage != null
                    && detectXssViaEyecatcherComparison(eyecatcherMessage, msg2, scriptAlert)) {
                LOGGER.info(
                        "✓ tryScriptBreakingDetection: XSS DETECTED via eyecatcher comparison for payload: {}",
                        scriptAlert);
                LOGGER.debug("XSS detected via eyecatcher comparison for payload: {}", scriptAlert);
                if (useProcessContexts) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(scriptAlert)
                            .setEvidence(scriptAlert)
                            .setMessage(msg2)
                            .raise();
                    return true;
                } else {
                    // For mutateAttack, we don't directly raise - return contexts instead
                    // But eyecatcher detection doesn't produce contexts, so we raise here too
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(scriptAlert)
                            .setEvidence(scriptAlert)
                            .setMessage(msg2)
                            .raise();
                    return true;
                }
            }

            // Fallback detection: fragmented script injection (only for script-breaking payloads)
            String scriptAlertLower = scriptAlert.toLowerCase();
            if (scriptAlertLower.contains("</script>") && scriptAlertLower.contains("alert(")) {
                List<HtmlContext> contexts3 =
                        detectFragmentedScriptInjection(msg2, scriptAlert, scriptAlert);
                if (!contexts3.isEmpty()) {
                    LOGGER.info(
                            "✓ tryScriptBreakingDetection: XSS DETECTED via fragmented detection for payload: {}",
                            scriptAlert);
                    LOGGER.debug(
                            "XSS detected via fragmented detection for payload: {}", scriptAlert);
                    if (useProcessContexts) {
                        if (processContexts(contexts3, param, scriptAlert, false)) {
                            return true;
                        }
                    } else {
                        // For performScriptAttack, raise alert directly
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(param)
                                .setAttack(scriptAlert)
                                .setEvidence(scriptAlert)
                                .setMessage(msg2)
                                .raise();
                        return true;
                    }
                }
            }

            if (isStop()) {
                break;
            }
        }

        return false;
    }

    /**
     * Checks to see if the payload is reflected in the response with specific characters filtered.
     * If so it attempts the same attack but with those characters replaced by other ones known to
     * work instead.
     */
    private List<HtmlContext> mutateAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            String evidence,
            int ignoreFlags,
            boolean findDecoded,
            boolean isNullByteSpecialHandling,
            boolean ignoreSafeParents) {

        /** Check response for attacks with specific chrs filtered */
        for (List<Mutation> mList : MUTATIONS) {
            // check if the attack contains the first of the chrs to be mutated, it doesnt matter
            // which one
            if (attack.contains(String.valueOf(mList.get(0).original))) {
                HtmlContextAnalyser hca = new HtmlContextAnalyser(msg);
                // Remove all of the chrs to be mutated
                String filteredEvidence = attack;
                for (Mutation mutation : mList) {
                    filteredEvidence =
                            filteredEvidence.replace(String.valueOf(mutation.original), "");
                }

                List<HtmlContext> contexts =
                        hca.getHtmlContexts(
                                findDecoded ? getURLDecode(filteredEvidence) : filteredEvidence,
                                targetContext,
                                ignoreFlags,
                                ignoreSafeParents);
                if (!contexts.isEmpty()) {
                    // Try again with new attack
                    String mutatedAttack = attack;
                    String mutatedEvidence = attack;
                    for (Mutation mutation : mList) {
                        mutatedAttack =
                                mutatedAttack.replace(
                                        mutation.getOriginal(), mutation.getMutation());
                        if (!mutation.isCheckOriginal()) {
                            mutatedEvidence =
                                    mutatedEvidence.replace(
                                            mutation.getOriginal(), mutation.getMutation());
                        }
                    }
                    return this.performAttack(
                            msg,
                            param,
                            mutatedAttack,
                            targetContext,
                            mutatedEvidence,
                            ignoreFlags,
                            findDecoded,
                            isNullByteSpecialHandling,
                            ignoreSafeParents,
                            true);
                }
            }
        }
        return List.of();
    }

    private void raiseAlert(int confidence, String param, HtmlContext ctx, String otherInfo) {
        newAlert()
                .setConfidence(confidence)
                .setParam(param)
                .setAttack(ctx.getTarget())
                .setEvidence(ctx.getTarget())
                .setMessage(ctx.getMsg())
                .setOtherInfo(otherInfo)
                .raise();
    }

    private boolean performDirectAttack(HttpMessage msg, String param) {
        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            List<HtmlContext> contexts2 = performAttack(msg, param, "'\"" + scriptAlert, null, 0);
            if (contexts2 == null) {
                continue;
            }
            if (!contexts2.isEmpty()) {
                // Yep, its vulnerable
                if (processContexts(contexts2, param, scriptAlert, false)) {
                    return true;
                }
            }

            if (isStop()) {
                break;
            }
        }

        // Try script-breaking detection (eyecatcher-based + fragmented detection)
        // This handles cases like Firing Range where quote escaping prevents normal attacks
        if (tryScriptBreakingDetection(msg, param, true)) {
            return true;
        }

        return false;
    }

    private boolean performTagAttack(HtmlContext context, HttpMessage msg, String param) {

        if (context.isInScriptAttribute()) {
            // Good chance this will be vulnerable
            // Try a simple alert attack
            List<HtmlContext> contexts2 = performAttack(msg, param, ";alert(1)", context, 0);
            if (contexts2 == null) {
                return false;
            }

            for (HtmlContext context2 : contexts2) {
                if (context2.getTagAttribute() != null && context2.isInScriptAttribute()) {
                    // Yep, its vulnerable
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(context2.getTarget())
                            .setEvidence(context2.getTarget())
                            .setMessage(context2.getMsg())
                            .raise();
                    return true;
                }
            }
            LOGGER.debug(
                    "Failed to find vuln in script attribute on {}",
                    msg.getRequestHeader().getURI());

        } else if (context.isInUrlAttribute()) {
            // Its a url attribute
            List<HtmlContext> contexts2 =
                    performAttack(msg, param, "javascript:alert(1);", context, 0);
            if (contexts2 == null) {
                return false;
            }

            for (HtmlContext ctx : contexts2) {
                if (ctx.isInUrlAttribute() && isJavaScriptSchemeInjectionValid(ctx)) {
                    // Yep, its vulnerable
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(ctx.getTarget())
                            .setEvidence(ctx.getTarget())
                            .setMessage(ctx.getMsg())
                            .raise();
                    return true;
                }
            }
            LOGGER.debug(
                    "Failed to find vuln in url attribute on {}", msg.getRequestHeader().getURI());
        }
        if (context.isInTagWithSrc()) {
            // Its in an attribute in a tag which supports src
            // attributes
            List<HtmlContext> contexts2 =
                    performAttack(
                            msg,
                            param,
                            context.getSurroundingQuote() + " src=http://badsite.com",
                            context,
                            HtmlContext.IGNORE_TAG
                                    | HtmlContext.IGNORE_IN_URL
                                    | HtmlContext.IGNORE_WITH_SRC);
            if (contexts2 == null) {
                return false;
            }

            if (!contexts2.isEmpty()) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(contexts2.get(0).getTarget())
                        .setEvidence(contexts2.get(0).getTarget())
                        .setMessage(contexts2.get(0).getMsg())
                        .raise();
                return true;
            }
            LOGGER.debug(
                    "Failed to find vuln in tag with src attribute on {}",
                    msg.getRequestHeader().getURI());
        }

        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            // Try a simple alert attack
            List<HtmlContext> contexts2 =
                    performAttack(
                            msg,
                            param,
                            context.getSurroundingQuote() + ">" + scriptAlert,
                            context,
                            HtmlContext.IGNORE_TAG);
            if (contexts2 == null) {
                return false;
            }
            if (!contexts2.isEmpty()) {
                // Yep, its vulnerable
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(contexts2.get(0).getTarget())
                        .setEvidence(contexts2.get(0).getTarget())
                        .setMessage(contexts2.get(0).getMsg())
                        .raise();
                return true;
            }
            LOGGER.debug(
                    "Failed to find vuln with simple script attack {}",
                    msg.getRequestHeader().getURI());
            if (isStop()) {
                return false;
            }
        }
        // Try adding an onMouseOver
        List<HtmlContext> contexts2 =
                performAttack(
                        msg,
                        param,
                        context.getSurroundingQuote()
                                + " onMouseOver="
                                + context.getSurroundingQuote()
                                + "alert(1);",
                        context,
                        HtmlContext.IGNORE_TAG | HtmlContext.IGNORE_IN_URL);
        if (contexts2 == null) {
            return false;
        }
        if (!contexts2.isEmpty()) {
            // Yep, its vulnerable
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(param)
                    .setAttack(contexts2.get(0).getTarget())
                    .setEvidence(contexts2.get(0).getTarget())
                    .setMessage(contexts2.get(0).getMsg())
                    .raise();
            return true;
        }
        LOGGER.debug(
                "Failed to find vuln in with simple onmounseover {}",
                msg.getRequestHeader().getURI());
        return false;
    }

    private static boolean isJavaScriptSchemeInjectionValid(HtmlContext ctx) {
        return ctx.getTagAttributeValue().stripLeading().startsWith(ctx.getTarget());
    }

    private boolean performCommentAttack(HtmlContext context, HttpMessage msg, String param) {
        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            List<HtmlContext> contexts2 =
                    performAttack(
                            msg,
                            param,
                            "-->" + scriptAlert + "<!--",
                            context,
                            HtmlContext.IGNORE_HTML_COMMENT);
            if (contexts2 == null) {
                return false;
            }
            if (!contexts2.isEmpty()) {
                // Yep, its vulnerable
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(contexts2.get(0).getTarget())
                        .setEvidence(contexts2.get(0).getTarget())
                        .setMessage(contexts2.get(0).getMsg())
                        .raise();
                return true;
            }

            if (isStop()) {
                return false;
            }
        }
        // Maybe they're blocking script tags
        List<HtmlContext> contexts2 =
                performAttack(
                        msg,
                        param,
                        "-->" + B_MOUSE_ALERT + "<!--",
                        context,
                        HtmlContext.IGNORE_HTML_COMMENT);
        if (contexts2 == null) {
            return false;
        }
        if (!contexts2.isEmpty()) {
            // Yep, its vulnerable
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(param)
                    .setAttack(contexts2.get(0).getTarget())
                    .setEvidence(contexts2.get(0).getTarget())
                    .setMessage(contexts2.get(0).getMsg())
                    .raise();
            return true;
        }
        return false;
    }

    private boolean performBodyAttack(HtmlContext context, HttpMessage msg, String param) {
        // Try a simple alert attack
        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            List<HtmlContext> contexts2 =
                    performAttack(msg, param, scriptAlert, null, HtmlContext.IGNORE_PARENT);
            if (contexts2 == null) {
                continue;
            }
            if (!contexts2.isEmpty()) {
                // Yep, its vulnerable
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(contexts2.get(0).getTarget())
                        .setEvidence(contexts2.get(0).getTarget())
                        .setMessage(contexts2.get(0).getMsg())
                        .raise();
                return true;
            }
            if (isStop()) {
                return false;
            }
        }
        // Maybe they're blocking script tags
        List<HtmlContext> contexts2 =
                performAttack(msg, param, B_MOUSE_ALERT, context, HtmlContext.IGNORE_PARENT);
        if (contexts2 != null) {
            for (HtmlContext context2 : contexts2) {
                if ("body".equalsIgnoreCase(context2.getParentTag())
                        || "b".equalsIgnoreCase(context2.getParentTag())) {
                    // Yep, its vulnerable
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(contexts2.get(0).getTarget())
                            .setEvidence(contexts2.get(0).getTarget())
                            .setMessage(contexts2.get(0).getMsg())
                            .raise();
                    return true;
                }
            }
        }
        if (GET_POST_TYPES.contains(currentParamType)) {
            // Try double encoded
            List<HtmlContext> contexts3 =
                    performAttack(msg, param, getURLEncode(GENERIC_SCRIPT_ALERT), null, 0, true);
            if (contexts3 != null && !contexts3.isEmpty()) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(getURLEncode(getURLEncode(contexts3.get(0).getTarget())))
                        .setEvidence(GENERIC_SCRIPT_ALERT)
                        .setMessage(contexts3.get(0).getMsg())
                        .raise();
                return true;
            }
        }
        return false;
    }

    private boolean performCloseTagAttack(HtmlContext context, HttpMessage msg, String param) {
        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            String attack =
                    "</"
                            + context.getParentTag()
                            + ">"
                            + scriptAlert
                            + "<"
                            + context.getParentTag()
                            + ">";
            List<HtmlContext> contexts2 =
                    performAttack(msg, param, attack, context, HtmlContext.IGNORE_IN_SCRIPT);
            if (contexts2 == null) {
                return false;
            }
            for (HtmlContext ctx : contexts2) {
                if (ctx.getSurroundingQuote().isEmpty()) {
                    // Yep, its vulnerable
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(ctx.getTarget())
                            .setEvidence(ctx.getTarget())
                            .setMessage(ctx.getMsg())
                            .raise();
                    return true;
                }
            }
            if (isStop()) {
                return false;
            }
        }

        return false;
    }

    private boolean performScriptAttack(HtmlContext context, HttpMessage msg, String param) {
        List<HtmlContext> contexts2 =
                performAttack(
                        msg,
                        param,
                        context.getSurroundingQuote()
                                + ";alert(1);"
                                + context.getSurroundingQuote(),
                        context,
                        0);
        if (contexts2 == null) {
            return false;
        }
        for (HtmlContext ctx : contexts2) {
            if (context.getSurroundingQuote().isEmpty() || !ctx.getSurroundingQuote().isEmpty()) {
                // Yep, its vulnerable
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(ctx.getTarget())
                        .setEvidence(ctx.getTarget())
                        .setMessage(ctx.getMsg())
                        .raise();
                return true;
            }
        }

        // Try script-breaking detection (eyecatcher-based + fragmented detection)
        // This is the main detection method for eval() contexts and script-breaking scenarios
        // where traditional context analysis may fail
        return tryScriptBreakingDetection(msg, param, false);
    }

    private boolean processContexts(
            List<HtmlContext> contexts, String param, String attack, boolean requiresParent) {
        for (HtmlContext ctx : contexts) {
            if (ctx.getParentTag() != null || !requiresParent) {
                if (ctx.getMsg().getResponseHeader().isHtml()) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(ctx.getTarget())
                            .setEvidence(ctx.getTarget())
                            .setMessage(contexts.get(0).getMsg())
                            .raise();
                } else if (AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                    HttpMessage ctx2Message = contexts.get(0).getMsg();
                    if (Strings.CI.contains(
                            ctx.getMsg()
                                    .getResponseHeader()
                                    .getHeader(HttpFieldsNames.CONTENT_TYPE),
                            "json")) {
                        newAlert()
                                .setRisk(Alert.RISK_LOW)
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setName(Constant.messages.getString(MESSAGE_PREFIX + "json.name"))
                                .setDescription(
                                        Constant.messages.getString(MESSAGE_PREFIX + "json.desc"))
                                .setParam(param)
                                .setAttack(attack)
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX + "otherinfo.nothtml"))
                                .setMessage(ctx2Message)
                                .raise();
                    } else {
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setParam(param)
                                .setAttack(ctx.getTarget())
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX + "otherinfo.nothtml"))
                                .setEvidence(ctx.getTarget())
                                .setMessage(ctx2Message)
                                .raise();
                    }
                }
                return true;
            }
        }
        return false;
    }

    private boolean performOutsideTagsAttack(HtmlContext context, HttpMessage msg, String param) {
        for (String scriptAlert : OUTSIDE_OF_TAGS_PAYLOADS) {
            if (context.getMsg().getResponseBody().toString().contains(context.getTarget())) {
                List<HtmlContext> contexts2 =
                        performAttack(msg, param, scriptAlert, null, 0, false, true, true);
                if (contexts2 == null) {
                    continue;
                }
                if (processContexts(contexts2, param, scriptAlert, true)) {
                    return true;
                }
            }
            if (isStop()) {
                return false;
            }
        }
        return false;
    }

    private boolean performImageTagAttack(HtmlContext context, HttpMessage msg, String param) {
        List<HtmlContext> contextsA =
                performAttack(
                        msg,
                        param,
                        GENERIC_ONERROR_ALERT,
                        context,
                        HtmlContext.IGNORE_IN_SCRIPT,
                        false,
                        false,
                        true);
        if (contextsA != null && !contextsA.isEmpty()) {
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(param)
                    .setAttack(contextsA.get(0).getTarget())
                    .setEvidence(contextsA.get(0).getTarget())
                    .setMessage(contextsA.get(0).getMsg())
                    .raise();
            return true;
        }
        return false;
    }

    private void raiseAccessKeyAlert(String param, HtmlContext ctx) {
        raiseAlert(
                Alert.CONFIDENCE_MEDIUM,
                param,
                ctx,
                Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.accesskey"));
    }

    private boolean performAttributeAttack(HtmlContext context, HttpMessage msg, String param) {
        List<HtmlContext> context2 =
                performAttack(msg, param, ACCESSKEY_ATTRIBUTE_ALERT, context, 0);
        if (context2 == null) {
            return false;
        }
        for (HtmlContext ctx : context2) {
            if (ctx.hasAttribute("onclick", "alert(1)") && ctx.hasAttribute("accesskey", "x")) {
                // Yep, its vulnerable
                raiseAccessKeyAlert(param, ctx);
                return true;
            }
        }
        return false;
    }

    private boolean performElementAttack(HtmlContext context, HttpMessage msg, String param) {
        String attackString1 = "tag " + ACCESSKEY_ATTRIBUTE_ALERT;
        // In this case the parent effectively changes
        List<HtmlContext> context2 =
                performAttack(msg, param, attackString1, context, HtmlContext.IGNORE_PARENT);

        if (context2 == null || context2.isEmpty()) {
            context2 = performAttack(msg, param, TAG_ONCLICK_ALERT, null, 0);
            if (context2 == null) {
                return false;
            }
            for (HtmlContext ctx : context2) {
                if (ctx.hasAttribute("onclick", "alert(1)")) {
                    // Yep, its vulnerable
                    raiseAlert(Alert.CONFIDENCE_MEDIUM, param, ctx, "");
                    return true;
                }
            }
        }

        for (HtmlContext ctx : context2) {
            if (ctx.hasAttribute("accesskey", "x") && ctx.hasAttribute("onclick", "alert(1)")) {
                // Yep, its vulnerable
                raiseAccessKeyAlert(param, ctx);
                return true;
            }
        }
        return false;
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        if (!AlertThreshold.LOW.equals(getAlertThreshold())
                && HttpRequestHeader.PUT.equals(msg.getRequestHeader().getMethod())) {
            return;
        }

        try {
            // Inject the 'safe' eyecatcher and see where it appears
            boolean attackWorked = false;
            boolean appendedValue = false;
            HttpMessage msg2 = getNewMsg();
            setParameter(msg2, param, Constant.getEyeCatcher());
            try {
                sendAndReceive(msg2);
            } catch (URIException e) {
                LOGGER.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            } catch (UnknownHostException e) {
                // Not an error, just means we probably attacked the redirect
                // location
                // Try the second eye catcher
            }

            if (isStop()) {
                return;
            }

            // Store eyecatcher message for eyecatcher-based comparison detection
            eyecatcherMessage = msg2;

            HtmlContextAnalyser hca = new HtmlContextAnalyser(msg2);
            List<HtmlContext> contexts = hca.getHtmlContexts(Constant.getEyeCatcher(), null, 0);
            if (contexts.isEmpty()) {
                // Lower case?
                contexts = hca.getHtmlContexts(Constant.getEyeCatcher().toLowerCase(), null, 0);
            }
            if (contexts.isEmpty()) {
                // Upper case?
                contexts = hca.getHtmlContexts(Constant.getEyeCatcher().toUpperCase(), null, 0);
            }
            if (contexts.isEmpty()) {
                // No luck - try again, appending the eyecatcher to the original
                // value
                msg2 = getNewMsg();
                setParameter(msg2, param, value + Constant.getEyeCatcher());
                appendedValue = true;
                try {
                    sendAndReceive(msg2);
                } catch (URIException e) {
                    LOGGER.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                    return;
                } catch (UnknownHostException e) {
                    // Second eyecatcher failed for some reason, no need to
                    // continue
                    return;
                }
                // Update eyecatcher message if appended version was successful
                eyecatcherMessage = msg2;
                hca = new HtmlContextAnalyser(msg2);
                contexts = hca.getHtmlContexts(value + Constant.getEyeCatcher(), null, 0);
            }
            if (contexts.isEmpty()) {
                attackWorked = performDirectAttack(msg, param);
            }

            for (HtmlContext context : contexts) {
                // Loop through the returned contexts and launch targeted
                // attacks
                if (attackWorked || isStop()) {
                    break;
                }
                if (context.getTagAttribute() != null) {
                    // its in a tag attribute - lots of attack vectors possible
                    attackWorked = performTagAttack(context, msg, param);

                } else if (context.isInAttributeName()) {

                    attackWorked = performAttributeAttack(context, msg, param);

                } else if (context.isHtmlComment()) {
                    // Try breaking out of the comment
                    attackWorked = performCommentAttack(context, msg, param);
                } else {
                    // its not in a tag attribute
                    if ("body".equalsIgnoreCase(context.getParentTag())) {
                        // Immediately under a body tag
                        attackWorked = performBodyAttack(context, msg, param);

                    } else if (context.getParentTag() != null) {
                        // Its not immediately under a body tag, try to close
                        // the tag
                        attackWorked = performCloseTagAttack(context, msg, param);

                        if (attackWorked) {
                            break;
                        } else if ("script".equalsIgnoreCase(context.getParentTag())) {
                            // its in a script tag...
                            attackWorked = performScriptAttack(context, msg, param);
                        } else {
                            // Try an img tag
                            attackWorked = performImageTagAttack(context, msg, param);
                        }
                    } else {
                        // Last chance - is the payload reflected outside of any
                        // tags
                        attackWorked = performOutsideTagsAttack(context, msg, param);
                    }
                }
                if (context.isInElementName()) {

                    attackWorked = performElementAttack(context, msg, param);
                }
            }
            // Always attack the header if the eyecatcher is reflected in it - this will be
            // different to any alert raised above
            if (msg2.getResponseHeader().toString().contains(Constant.getEyeCatcher())) {
                attackHeader(msg, param, appendedValue ? value : "");
            }

        } catch (IOException e) {
            LOGGER.debug(e.getMessage(), e);
        }
    }

    private void attackHeader(HttpMessage msg, String param, String value) {
        // We know the eyecatcher was reflected in the header, lets try some header splitting
        // attacks
        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
            String attack = value + HEADER_SPLITTING + scriptAlert;
            List<HtmlContext> contexts2 =
                    performAttack(msg, param, attack, null, scriptAlert, 0, false, false, true);
            if (contexts2 != null && !contexts2.isEmpty()) {
                // Yep, its vulnerable
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(param)
                        .setAttack(attack)
                        .setEvidence(contexts2.get(0).getTarget())
                        .setMessage(contexts2.get(0).getMsg())
                        .raise();
                return;
            }
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 79;
    }

    @Override
    public int getWascId() {
        return 8;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String attack = "</p><scrIpt>alert`1`;</scRipt><p>";
        return List.of(
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam("name")
                        .setAttack(attack)
                        .setEvidence(attack)
                        .build());
    }

    private static class Mutation {
        private char original;
        private char mutation;
        private boolean checkOriginal;

        public Mutation(char original, char mutation) {
            this(original, mutation, false);
        }

        public Mutation(char original, char mutation, boolean checkOriginal) {
            this.original = original;
            this.mutation = mutation;
            this.checkOriginal = checkOriginal;
        }

        public char getOriginal() {
            return original;
        }

        public char getMutation() {
            return mutation;
        }

        public boolean isCheckOriginal() {
            return checkOriginal;
        }
    }
}
