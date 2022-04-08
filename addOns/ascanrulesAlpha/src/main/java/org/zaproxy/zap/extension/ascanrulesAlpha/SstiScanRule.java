/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.SourceSinkUtils;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.DjangoTemplateFormat;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.GoTemplateFormat;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.InputPoint;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.ReflectedSinkPoint;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.SinkPoint;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.StoredSinkPoint;
import org.zaproxy.zap.extension.ascanrulesAlpha.ssti.TemplateFormat;

/**
 * Active Plugin for Server Side Template Injection testing and verification.
 *
 * @author DiogoMRSilva (2018)
 */
public class SstiScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanalpha.ssti.";

    static final String DELIMITER = "zj";

    private static final float SIMILARITY_THRESHOLD = 0.75f;

    private static String[] errorPolyglots = {"<%={{={@{#{${zj}}%>", "<th:t=\"${zj}#foreach"};
    // Innocuous versions of the polyglots may be useful in the future if more complex error
    // detection is required
    // "\\{*\\<\\%\\=\\{\\{\\=\\{\\@\\{\\#\\{\\$\\{zj\\}\\}\\%\\>\\*}"
    // the first and last tag are the commentaries from twig
    // "\\\"\\<th\\:t\\=\\$\\{zj\\}\\#\\foreach"

    private static final TemplateFormat[] TEMPLATE_FORMATS = {
        new TemplateFormat(" ", " "),
        new TemplateFormat("{", "}"),
        new TemplateFormat("${", "}"),
        new TemplateFormat("#{", "}"),
        new TemplateFormat("{#", "}"),
        new TemplateFormat("{@", "}"),
        new TemplateFormat("{{", "}}"),
        new TemplateFormat("{{=", "}}"),
        new TemplateFormat("<%=", "%>"),
        new TemplateFormat("#set($x=", ")${x}"),
        new TemplateFormat("<p th:text=\"${", "}\"></p>"),
        new TemplateFormat(
                "{", "}", "{@math key=\"%d\" method=\"multiply\" operand=\"%d\"/}"), // Dustjs
        new DjangoTemplateFormat(),
        new GoTemplateFormat()
    };

    private static final String[] WAYS_TO_FIX_CODE_SYNTAX = {"\"", "'", "1", ""};

    private static final Logger LOG = LogManager.getLogger(SstiScanRule.class);

    @Override
    public int getId() {
        return 90035;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String[] getDependency() {
        return new String[] {};
        // TODO activate when start to work properly
        // return new String[] {"TestPersistentXSSSpider"};
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCweId() {
        return 94; // WE-94: Improper Control of Generation of Code ('Code Injection').
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    /**
     * Scan for Server Side Template Injection Vulnerabilities
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {

        // In LOW mode we can only make 6 requests by parameter
        // so we use an greedy approach where we reduce the number of
        // request in exchange for an increase in false negatives.
        if (Plugin.AttackStrength.LOW.equals(this.getAttackStrength())) {
            efficientScan(msg, paramName, value);
        } else if (Plugin.AttackStrength.MEDIUM.equals(this.getAttackStrength())
                || AttackStrength.HIGH.equals(this.getAttackStrength())) {
            reliableScan(msg, paramName, value, false);
        }
        // When the scanner can do more requests it tries less common cases.
        else {
            reliableScan(msg, paramName, value, true);
        }
    }

    /**
     * Scan for Server Side Template Injection Vulnerabilities in an efficient way making use of
     * polyglots and heuristics (less than 6 requests when not vulnerable).
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    private void efficientScan(HttpMessage msg, String paramName, String value) {

        // The efficient scanner detects the existence of vulnerabilities by causing
        // and detecting errors. To detect errors we start by looking to how the
        // responses change when we send different inputs. Later, with this information
        // we can detect which changes caused by our inputs are not normal and which
        // may indicate an error.
        // To detect the normal changes we send an random input. This input has the same
        // size as the polyglot to detect errors caused by size limits.
        String alphabet;
        if (value != null && value.length() > 0) {
            alphabet = value;
        } else {
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        }

        String referenceValue = RandomStringUtils.random(errorPolyglots[0].length(), alphabet);
        HttpMessage refMsg = getNewMsg();
        setParameter(refMsg, paramName, referenceValue);
        try {
            sendAndReceive(refMsg, false);
        } catch (IOException e) {
            LOG.warn(
                    "SSTI vulnerability check failed for parameter [{}] due to an I/O error",
                    paramName,
                    e);
            return;
        }

        // The input point will have associated the several locations where the user
        // input is reflected("sinks"). This are the locations where it is possible to
        // see the result of a successful SSTI. The objects representing this "sink"
        // points contain information about the usual behavior the server has to
        // different inputs.
        InputPoint inputPoint =
                createInputPointWithAllSinks(
                        getBaseMsg(), value, refMsg, referenceValue, paramName);
        inputPoint.addReferenceReqToAllSinkPoints(refMsg, paramName, referenceValue);

        if (isStop()) {
            return;
        }

        if (hasSuspectBehaviourWithPolyglot(paramName, inputPoint)) {
            searchForMathsExecution(paramName, inputPoint, false);
        }
    }

    private InputPoint createInputPointWithAllSinks(
            HttpMessage originalMsg,
            String originalValue,
            HttpMessage referenceMsg,
            String referenceValue,
            String paramName) {

        InputPoint inputPoint = new InputPoint();

        inputPoint.addSinkPoint(
                new ReflectedSinkPoint(originalMsg, originalValue, referenceMsg, referenceValue));

        Set<Integer> sinks = SourceSinkUtils.getSinksIdsForSource(originalMsg, paramName);
        if (sinks != null) {
            for (int sinkMsgId : sinks) {
                HttpMessage sinkMsg = SourceSinkUtils.getMessage(sinkMsgId);
                if (sinkMsg == null) {
                    continue;
                }
                inputPoint.addSinkPoint(new StoredSinkPoint(sinkMsg, originalValue));
            }
        }

        return inputPoint;
    }

    /**
     * Scan for Server Side Template Injection Vulnerabilities in an less efficient way but the
     * results are more reliable.
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     * @param fixSyntax declares if should use several prefixes to fix a possible syntax error
     */
    private void reliableScan(HttpMessage msg, String paramName, String value, boolean fixSyntax) {

        InputPoint inputPoint = createInputPointWithAllSinks(msg, value, msg, value, paramName);

        if (isStop()) {
            return;
        }

        searchForMathsExecution(paramName, inputPoint, fixSyntax);
    }

    /**
     * Function checks if the end-point has suspect behaviour when receive one of the polyglot
     * payloads and remove the elements of input point which do not have error
     *
     * @param paramName the name of the parameter will be used for testing for injection
     * @param inputPoint input point being tested and its possible sinks
     * @return {@code true} if the server has suspect behaviour when receive polyglot, {@code false}
     *     otherwise.
     */
    private boolean hasSuspectBehaviourWithPolyglot(String paramName, InputPoint inputPoint) {
        boolean hasSuspectBehavior = false;
        List<SinkPoint> sinksWithErrors = new ArrayList<>();

        for (String polyglot : errorPolyglots) {

            try {
                HttpMessage msg = getNewMsg();
                setParameter(msg, paramName, polyglot);
                sendAndReceive(msg, false);

                for (SinkPoint sink : inputPoint.getSinkPoints()) {
                    if (sink.getSimilarityToOriginal(msg, paramName, polyglot)
                                    / sink.getSimilarityOfReference()
                            < SIMILARITY_THRESHOLD) {
                        sinksWithErrors.add(sink);
                        hasSuspectBehavior = true;
                    }
                }

            } catch (SocketException ex) {
                LOG.debug("Caught {} {}", ex.getClass().getName(), ex.getMessage());
            } catch (IOException ex) {
                LOG.warn(
                        "SSTI vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                        paramName,
                        polyglot,
                        ex);
            }
        }
        // We are only going to search in the sinks were we got error
        inputPoint.getSinkPoints().removeIf(s -> !sinksWithErrors.contains(s));
        return hasSuspectBehavior;
    }

    /**
     * See if mathematical operation results are seen in some of the sinks
     *
     * @param paramName the name of the parameter will be used for testing for injection
     * @param inputPoint input point being tested and its possible sinks
     * @param fixSyntax declares if should use several prefixes to fix a possible syntax error
     */
    private void searchForMathsExecution(
            String paramName, InputPoint inputPoint, boolean fixSyntax) {
        ArrayList<SinkPoint> sinksToTest = new ArrayList<>(inputPoint.getSinkPoints());
        boolean found = false;
        String[] codeFixPrefixes = {""};
        String templateFixingPrefix;

        if (fixSyntax) {
            codeFixPrefixes = WAYS_TO_FIX_CODE_SYNTAX;
        }

        for (TemplateFormat sstiPayload : TEMPLATE_FORMATS) {

            if (fixSyntax) {
                templateFixingPrefix = sstiPayload.getEndTag();
            } else {
                templateFixingPrefix = "";
            }

            for (String codeFixPrefix : codeFixPrefixes) {
                if (isStop() || found) {
                    break;
                }

                List<String> payloadsAndResults = sstiPayload.getRenderTestAndResult();
                List<String> renderExpectedResults =
                        payloadsAndResults.subList(1, payloadsAndResults.size());

                // Some template engines only support numbers up to a given size.
                // If we send a template that results a number above the maximum
                // supported we get an overflow and the result will not be the one
                // expected leaving the injection undetected.
                // To avoid this false negatives we use smaller numbers in the payload
                // but this increases the probability of creating an operation result
                // number that already exist in the page leading to false positives.
                // To reduce this probability we add delimiters to ensure that the
                // number in the response was generated by our payload.
                String renderTest =
                        codeFixPrefix
                                + templateFixingPrefix
                                + DELIMITER
                                + payloadsAndResults.get(0)
                                + DELIMITER;

                try {

                    HttpMessage newMsg = getNewMsg();
                    setParameter(newMsg, paramName, renderTest);
                    sendAndReceive(newMsg, false);

                    for (SinkPoint sink : sinksToTest) {

                        String output = sink.getCurrentStateInString(newMsg, paramName, renderTest);

                        for (String renderResult : renderExpectedResults) {
                            // Some rendering tests add html tags so we can not only search for
                            // the delimiters with the arithmetic result inside. Regex searches
                            // may be expensive, so first we check if the result exist in the
                            // response and only then we check if it inside the delimiters and
                            // was originated by our payload.
                            String regex =
                                    "[\\w\\W]*"
                                            + DELIMITER
                                            + ".*"
                                            + renderResult
                                            + ".*"
                                            + DELIMITER
                                            + "[\\w\\W]*";

                            if (output.contains(renderResult) && output.matches(regex)) {

                                String attack =
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX + "alert.otherinfo",
                                                sink.getLocation(),
                                                output);

                                this.newAlert()
                                        .setConfidence(Alert.CONFIDENCE_HIGH)
                                        .setUri(newMsg.getRequestHeader().getURI().toString())
                                        .setParam(paramName)
                                        .setAttack(renderTest)
                                        .setOtherInfo(attack)
                                        .setMessage(newMsg)
                                        .raise();
                                found = true;
                            }
                        }
                    }
                } catch (SocketException ex) {
                    LOG.debug("Caught {} {}", ex.getClass().getName(), ex.getMessage());
                } catch (IOException ex) {
                    LOG.warn(
                            "SSTI vulnerability check failed for parameter [{}]  due to an I/O error",
                            paramName,
                            ex);
                }
            }
        }
    }
}
