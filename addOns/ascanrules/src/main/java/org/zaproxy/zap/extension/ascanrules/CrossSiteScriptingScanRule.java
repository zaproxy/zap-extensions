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
import org.apache.commons.httpclient.InvalidRedirectLocationException;
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
import org.zaproxy.zap.httputils.HtmlContext;
import org.zaproxy.zap.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class CrossSiteScriptingScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.crosssitescripting.";

    private static final String GENERIC_SCRIPT_ALERT = "<script>alert(1);</script>";

    /**
     * Null byte injection payload. C/C++ languages treat Null byte or \0 as special character which
     * marks end of the String so if validators are written in C/C++ then validators might not check
     * bytes after null byte and hence can be bypassed.
     */
    private static final String GENERIC_NULL_BYTE_SCRIPT_ALERT =
            NULL_BYTE_CHARACTER + GENERIC_SCRIPT_ALERT;

    private static final List<String> GENERIC_SCRIPT_ALERT_LIST =
            Arrays.asList(GENERIC_SCRIPT_ALERT, GENERIC_NULL_BYTE_SCRIPT_ALERT);
    private static final List<Integer> GET_POST_TYPES =
            Arrays.asList(NameValuePair.TYPE_QUERY_STRING, NameValuePair.TYPE_POST_DATA);
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
        return performAttack(msg, param, attack, targetContext, ignoreFlags, false, false);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            int ignoreFlags,
            boolean findDecoded) {
        return performAttack(msg, param, attack, targetContext, ignoreFlags, findDecoded, false);
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            int ignoreFlags,
            boolean findDecoded,
            boolean isNullByteSpecialHandling) {
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
        } catch (InvalidRedirectLocationException | UnknownHostException e) {
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
        }
        HtmlContextAnalyser hca = new HtmlContextAnalyser(msg2);
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // High level, so check all results are in the expected context
            return hca.getHtmlContexts(
                    findDecoded ? getURLDecode(attack) : attack, targetContext, ignoreFlags);
        }

        return hca.getHtmlContexts(findDecoded ? getURLDecode(attack) : attack);
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
            HttpMessage msg2 = getNewMsg();
            setParameter(msg2, param, Constant.getEyeCatcher());
            try {
                sendAndReceive(msg2);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            } catch (InvalidRedirectLocationException | UnknownHostException e) {
                // Not an error, just means we probably attacked the redirect
                // location
                // Try the second eye catcher
            }

            if (isStop()) {
                return;
            }

            HtmlContextAnalyser hca = new HtmlContextAnalyser(msg2);
            List<HtmlContext> contexts = hca.getHtmlContexts(Constant.getEyeCatcher(), null, 0);
            if (contexts.size() == 0) {
                // Lower case?
                contexts = hca.getHtmlContexts(Constant.getEyeCatcher().toLowerCase(), null, 0);
            }
            if (contexts.size() == 0) {
                // Upper case?
                contexts = hca.getHtmlContexts(Constant.getEyeCatcher().toUpperCase(), null, 0);
            }
            if (contexts.size() == 0) {
                // No luck - try again, appending the eyecatcher to the original
                // value
                msg2 = getNewMsg();
                setParameter(msg2, param, value + Constant.getEyeCatcher());
                try {
                    sendAndReceive(msg2);
                } catch (URIException e) {
                    log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                    return;
                } catch (InvalidRedirectLocationException | UnknownHostException e) {
                    // Second eyecatcher failed for some reason, no need to
                    // continue
                    return;
                }
                hca = new HtmlContextAnalyser(msg2);
                contexts = hca.getHtmlContexts(value + Constant.getEyeCatcher(), null, 0);
            }
            if (contexts.size() == 0) {
                // No luck - lets just try a direct attack
                for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
                    List<HtmlContext> contexts2 =
                            performAttack(msg, param, "'\"" + scriptAlert, null, 0);
                    if (contexts2 == null) {
                        return;
                    }
                    if (contexts2.size() > 0) {
                        // Yep, its vulnerable
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setParam(param)
                                .setAttack(contexts2.get(0).getTarget())
                                .setEvidence(contexts2.get(0).getTarget())
                                .setMessage(contexts2.get(0).getMsg())
                                .raise();
                        attackWorked = true;
                    }

                    if (attackWorked || isStop()) {
                        return;
                    }
                }
            }

            for (HtmlContext context : contexts) {
                // Loop through the returned contexts and launch targeted
                // attacks
                if (attackWorked || isStop()) {
                    break;
                }
                if (context.getTagAttribute() != null) {
                    // its in a tag attribute - lots of attack vectors possible

                    if (context.isInScriptAttribute()) {
                        // Good chance this will be vulnerable
                        // Try a simple alert attack
                        List<HtmlContext> contexts2 =
                                performAttack(msg, param, ";alert(1)", context, 0);
                        if (contexts2 == null) {
                            break;
                        }

                        for (HtmlContext context2 : contexts2) {
                            if (context2.getTagAttribute() != null
                                    && context2.isInScriptAttribute()) {
                                // Yep, its vulnerable
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setAttack(context2.getTarget())
                                        .setEvidence(context2.getTarget())
                                        .setMessage(context2.getMsg())
                                        .raise();
                                attackWorked = true;
                                break;
                            }
                        }
                        if (!attackWorked) {
                            log.debug(
                                    "Failed to find vuln in script attribute on {}",
                                    msg.getRequestHeader().getURI());
                        }

                    } else if (context.isInUrlAttribute()) {
                        // Its a url attribute
                        List<HtmlContext> contexts2 =
                                performAttack(msg, param, "javascript:alert(1);", context, 0);
                        if (contexts2 == null) {
                            break;
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
                                attackWorked = true;
                                break;
                            }
                        }
                        if (!attackWorked) {
                            log.debug(
                                    "Failed to find vuln in url attribute on {}",
                                    msg.getRequestHeader().getURI());
                        }
                    }
                    if (!attackWorked && context.isInTagWithSrc()) {
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
                            break;
                        }

                        if (contexts2.size() > 0) {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(contexts2.get(0).getTarget())
                                    .setEvidence(contexts2.get(0).getTarget())
                                    .setMessage(contexts2.get(0).getMsg())
                                    .raise();
                            attackWorked = true;
                        }
                        if (!attackWorked) {
                            log.debug(
                                    "Failed to find vuln in tag with src attribute on {}",
                                    msg.getRequestHeader().getURI());
                        }
                    }

                    if (!attackWorked) {
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
                                return;
                            }
                            if (contexts2.size() > 0) {
                                // Yep, its vulnerable
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setAttack(contexts2.get(0).getTarget())
                                        .setEvidence(contexts2.get(0).getTarget())
                                        .setMessage(contexts2.get(0).getMsg())
                                        .raise();
                                attackWorked = true;
                            }
                            if (!attackWorked) {
                                log.debug(
                                        "Failed to find vuln with simple script attack {}",
                                        msg.getRequestHeader().getURI());
                            }

                            if (attackWorked || isStop()) {
                                return;
                            }
                        }
                    }
                    if (!attackWorked) {
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
                            break;
                        }
                        if (contexts2.size() > 0) {
                            // Yep, its vulnerable
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(contexts2.get(0).getTarget())
                                    .setEvidence(contexts2.get(0).getTarget())
                                    .setMessage(contexts2.get(0).getMsg())
                                    .raise();
                            attackWorked = true;
                        }
                        if (!attackWorked) {
                            log.debug(
                                    "Failed to find vuln in with simple onmounseover {}",
                                    msg.getRequestHeader().getURI());
                        }
                    }
                } else if (context.isHtmlComment()) {
                    // Try breaking out of the comment
                    for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
                        List<HtmlContext> contexts2 =
                                performAttack(
                                        msg,
                                        param,
                                        "-->" + scriptAlert + "<!--",
                                        context,
                                        HtmlContext.IGNORE_HTML_COMMENT);
                        if (contexts2 == null) {
                            return;
                        }
                        if (contexts2.size() > 0) {
                            // Yep, its vulnerable
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(contexts2.get(0).getTarget())
                                    .setEvidence(contexts2.get(0).getTarget())
                                    .setMessage(contexts2.get(0).getMsg())
                                    .raise();
                            attackWorked = true;
                        }

                        if (attackWorked || isStop()) {
                            return;
                        }
                    }
                    // Maybe they're blocking script tags
                    List<HtmlContext> contexts2 =
                            performAttack(
                                    msg,
                                    param,
                                    "--><b onMouseOver=alert(1);>test</b><!--",
                                    context,
                                    HtmlContext.IGNORE_HTML_COMMENT);
                    if (contexts2 == null) {
                        break;
                    }
                    if (contexts2.size() > 0) {
                        // Yep, its vulnerable
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(param)
                                .setAttack(contexts2.get(0).getTarget())
                                .setEvidence(contexts2.get(0).getTarget())
                                .setMessage(contexts2.get(0).getMsg())
                                .raise();
                        attackWorked = true;
                    }

                } else {
                    // its not in a tag attribute
                    if ("body".equalsIgnoreCase(context.getParentTag())) {
                        // Immediately under a body tag
                        // Try a simple alert attack
                        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
                            List<HtmlContext> contexts2 =
                                    performAttack(
                                            msg,
                                            param,
                                            scriptAlert,
                                            null,
                                            HtmlContext.IGNORE_PARENT);
                            if (contexts2 == null) {
                                return;
                            }
                            if (contexts2.size() > 0) {
                                // Yep, its vulnerable
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setAttack(contexts2.get(0).getTarget())
                                        .setEvidence(contexts2.get(0).getTarget())
                                        .setMessage(contexts2.get(0).getMsg())
                                        .raise();
                                attackWorked = true;
                            }
                            if (attackWorked || isStop()) {
                                return;
                            }
                        }
                        // Maybe they're blocking script tags
                        List<HtmlContext> contexts2 =
                                performAttack(
                                        msg,
                                        param,
                                        "<b onMouseOver=alert(1);>test</b>",
                                        context,
                                        HtmlContext.IGNORE_PARENT);
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
                                    attackWorked = true;
                                    break;
                                }
                            }
                        }
                        if (!attackWorked) {
                            if (GET_POST_TYPES.contains(currentParamType)) {
                                // Try double encoded
                                List<HtmlContext> contexts3 =
                                        performAttack(
                                                msg,
                                                param,
                                                getURLEncode(GENERIC_SCRIPT_ALERT),
                                                null,
                                                0,
                                                true);
                                if (contexts3 != null && contexts3.size() > 0) {
                                    attackWorked = true;
                                    newAlert()
                                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                            .setParam(param)
                                            .setAttack(
                                                    getURLEncode(
                                                            getURLEncode(
                                                                    contexts3.get(0).getTarget())))
                                            .setEvidence(GENERIC_SCRIPT_ALERT)
                                            .setMessage(contexts3.get(0).getMsg())
                                            .raise();
                                }
                                break;
                            }
                        }

                    } else if (context.getParentTag() != null) {
                        // Its not immediately under a body tag, try to close
                        // the tag
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
                                return;
                            }
                            if (contexts2.size() > 0) {
                                // Yep, its vulnerable
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setAttack(contexts2.get(0).getTarget())
                                        .setEvidence(contexts2.get(0).getTarget())
                                        .setMessage(contexts2.get(0).getMsg())
                                        .raise();
                                attackWorked = true;
                            }
                            if (attackWorked || isStop()) {
                                return;
                            }
                        }
                        if ("script".equalsIgnoreCase(context.getParentTag())) {
                            // its in a script tag...
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
                                break;
                            }
                            if (contexts2.size() > 0) {
                                // Yep, its vulnerable
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setAttack(contexts2.get(0).getTarget())
                                        .setEvidence(contexts2.get(0).getTarget())
                                        .setMessage(contexts2.get(0).getMsg())
                                        .raise();
                                attackWorked = true;
                            }
                        } else {
                            // Try an img tag
                            List<HtmlContext> contextsA =
                                    performAttack(
                                            msg,
                                            param,
                                            "<img src=x onerror=alert(1);>",
                                            context,
                                            HtmlContext.IGNORE_IN_SCRIPT);
                            if (contextsA != null && contextsA.size() > 0) {
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setAttack(contextsA.get(0).getTarget())
                                        .setEvidence(contextsA.get(0).getTarget())
                                        .setMessage(contextsA.get(0).getMsg())
                                        .raise();
                                attackWorked = true;
                                break;
                            }
                        }
                    } else {
                        // Last chance - is the payload reflected outside of any
                        // tags
                        for (String scriptAlert : GENERIC_SCRIPT_ALERT_LIST) {
                            if (context.getMsg()
                                    .getResponseBody()
                                    .toString()
                                    .contains(context.getTarget())) {
                                List<HtmlContext> contexts2 =
                                        performAttack(
                                                msg, param, scriptAlert, null, 0, false, true);
                                if (contexts2 == null) {
                                    return;
                                }
                                for (HtmlContext ctx : contexts2) {
                                    if (ctx.getParentTag() != null) {
                                        // Yep, its vulnerable
                                        if (ctx.getMsg().getResponseHeader().isHtml()) {
                                            newAlert()
                                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                                    .setParam(param)
                                                    .setAttack(ctx.getTarget())
                                                    .setEvidence(ctx.getTarget())
                                                    .setMessage(contexts2.get(0).getMsg())
                                                    .raise();
                                        } else {
                                            HttpMessage ctx2Message = contexts2.get(0).getMsg();
                                            if (StringUtils.containsIgnoreCase(
                                                    ctx.getMsg()
                                                            .getResponseHeader()
                                                            .getHeader(HttpHeader.CONTENT_TYPE),
                                                    "json")) {
                                                newAlert()
                                                        .setRisk(Alert.RISK_LOW)
                                                        .setConfidence(Alert.CONFIDENCE_LOW)
                                                        .setName(
                                                                Constant.messages.getString(
                                                                        MESSAGE_PREFIX
                                                                                + "json.name"))
                                                        .setDescription(
                                                                Constant.messages.getString(
                                                                        MESSAGE_PREFIX
                                                                                + "json.desc"))
                                                        .setParam(param)
                                                        .setAttack(GENERIC_SCRIPT_ALERT)
                                                        .setOtherInfo(
                                                                Constant.messages.getString(
                                                                        MESSAGE_PREFIX
                                                                                + "otherinfo.nothtml"))
                                                        .setMessage(ctx2Message)
                                                        .raise();
                                            } else {
                                                newAlert()
                                                        .setConfidence(Alert.CONFIDENCE_LOW)
                                                        .setParam(param)
                                                        .setAttack(ctx.getTarget())
                                                        .setOtherInfo(
                                                                Constant.messages.getString(
                                                                        MESSAGE_PREFIX
                                                                                + "otherinfo.nothtml"))
                                                        .setEvidence(ctx.getTarget())
                                                        .setMessage(ctx2Message)
                                                        .raise();
                                            }
                                        }
                                        attackWorked = true;
                                        break;
                                    }
                                }
                            }
                            if (attackWorked || isStop()) {
                                return;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
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
