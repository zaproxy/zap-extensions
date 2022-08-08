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

import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContext;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class CrossSiteScriptingScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.crosssitescripting.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A07_XSS,
                    CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS);

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

    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private static Logger log = LogManager.getLogger(CrossSiteScriptingScanRule.class);
    private int currentParamType;

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
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
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
        if (isStop()) {
            return null;
        }

        HttpMessage msg2 = msg.cloneRequest();
        setParameter(msg2, param, attack);
        try {
            sendAndReceive(msg2);
        } catch (URIException e) {
            log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
            return null;
        } catch (UnknownHostException e) {
            // Not an error, just means we probably attacked the redirect
            // location
            return null;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
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
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // High level, so check all results are in the expected context
            return hca.getHtmlContexts(
                    findDecoded ? getURLDecode(evidence) : evidence,
                    targetContext,
                    ignoreFlags,
                    ignoreSafeParents);
        }
        return hca.getHtmlContexts(
                findDecoded ? getURLDecode(evidence) : evidence, null, 0, ignoreSafeParents);
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

    private boolean performDirectAttack(HttpMessage msg, String param, String value) {
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
        return false;
    }

    private boolean performTagAttack(
            HtmlContext context, HttpMessage msg, String param, String value) {

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
            log.debug(
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
                if (ctx.isInUrlAttribute()) {
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
            log.debug(
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
                            HtmlContext.IGNORE_TAG);
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
            log.debug(
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
            log.debug(
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
        log.debug(
                "Failed to find vuln in with simple onmounseover {}",
                msg.getRequestHeader().getURI());
        return false;
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
            List<HtmlContext> contexts2 =
                    performAttack(
                            msg,
                            param,
                            "</"
                                    + context.getParentTag()
                                    + ">"
                                    + scriptAlert
                                    + "<"
                                    + context.getParentTag()
                                    + ">",
                            context,
                            HtmlContext.IGNORE_IN_SCRIPT);
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
        return false;
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
                    if (StringUtils.containsIgnoreCase(
                            ctx.getMsg().getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE),
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
        List<HtmlContext> context2 = performAttack(msg, param, attackString1, context, 0);
        if (context2 == null) {
            context2 = performAttack(msg, param, TAG_ONCLICK_ALERT, context, 0);
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
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            } catch (UnknownHostException e) {
                // Not an error, just means we probably attacked the redirect
                // location
                // Try the second eye catcher
            }

            if (isStop()) {
                return;
            }

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
                    log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                    return;
                } catch (UnknownHostException e) {
                    // Second eyecatcher failed for some reason, no need to
                    // continue
                    return;
                }
                hca = new HtmlContextAnalyser(msg2);
                contexts = hca.getHtmlContexts(value + Constant.getEyeCatcher(), null, 0);
            }
            if (contexts.isEmpty()) {
                attackWorked = performDirectAttack(msg, param, value);
            }

            for (HtmlContext context : contexts) {
                // Loop through the returned contexts and launch targeted
                // attacks
                if (attackWorked || isStop()) {
                    break;
                }
                if (context.getTagAttribute() != null) {
                    // its in a tag attribute - lots of attack vectors possible
                    attackWorked = performTagAttack(context, msg, param, value);

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

        } catch (Exception e) {
            log.error(e.getMessage(), e);
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
}
