/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.base64.Base64CharProbability;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.base64.Base64Data;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.PATTERN_NO_HMAC;

/**
 * A class to passively scan responses for Base64 encoded data, including ASP ViewState data, which
 * is Base64 encoded.
 *
 * @author 70pointer@gmail.com
 */
public class Base64Disclosure extends PluginPassiveScanner {

    private PassiveScanThread parent = null;

    private static final Pattern BASE64_PATTERN =
            Pattern.compile("[a-zA-Z0-9+\\\\/\\-_]{30,}={0,2}");

    private static final Map<Plugin.AlertThreshold, Float> PROBABILITY_THRESHOLD =
            new EnumMap<>(Plugin.AlertThreshold.class);

    static {
        // 0% probability threshold (all structurally valid Base64 data is
        // considered, regardless of how improbable  it is given character
        // frequencies, etc)
        PROBABILITY_THRESHOLD.put(Plugin.AlertThreshold.DEFAULT, 0.0F);
        PROBABILITY_THRESHOLD.put(Plugin.AlertThreshold.OFF, 0.0F);
        PROBABILITY_THRESHOLD.put(Plugin.AlertThreshold.LOW, 0.10F);
        PROBABILITY_THRESHOLD.put(Plugin.AlertThreshold.MEDIUM, 0.25F);
        // 50% probability threshold (ie, "on balance of probability")
        PROBABILITY_THRESHOLD.put(Plugin.AlertThreshold.HIGH, 0.50F);
    }
    /**
     * patterns used to identify strings withut each of the given character sets which is used to
     * calculate the probability of this occurring, and eliminate potential Base64 strings which are
     * extremely improbable
     */
    static Pattern digitPattern = Pattern.compile("[0-9]");

    static Pattern alphaPattern = Pattern.compile("[a-zA-Z]");
    static Pattern otherPattern = Pattern.compile("[\\+\\\\/\\-_]");
    static Pattern lowercasePattern = Pattern.compile("[a-z]");
    static Pattern uppercasePattern = Pattern.compile("[A-Z]");

    /** the logger. logs stuff. strange that! */
    private static Logger log = Logger.getLogger(Base64Disclosure.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.base64disclosure.";

    /**
     * gets the name of the scanner
     *
     * @return
     */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    /**
     * scans the HTTP request sent (in fact, does nothing)
     *
     * @param msg
     * @param id
     */
    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // TODO: implement checks for base64 encoding in the request?
    }

    /**
     * scans the HTTP response for base64 signatures
     *
     * @param msg
     * @param id
     * @param source unused
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (log.isDebugEnabled()) log.debug("Checking message " + msg + " for Base64 encoded data");

        List<Base64Data> possibleBase64Patterns = extractPossibleBase64String(msg);

        List<Base64Data> base64Patterns =
                filterBase64StringByLikelihood(
                        possibleBase64Patterns, PROBABILITY_THRESHOLD.get(getAlertThreshold()));


        for (Base64Data haystack : base64Patterns) {
                // so it's valid Base64.  Is it valid .NET ViewState data?
                // This will be true for both __VIEWSTATE and __EVENTVALIDATION data, although
                // currently, we can only interpret/decode __VIEWSTATE.
                boolean validviewstate = false;
                boolean macless = false;
                String viewstatexml = null;
                if (haystack.decodedData[0] == -1 || haystack.decodedData[1] == 0x01) {
                    // TODO: decode __EVENTVALIDATION data
                    ViewStateDecoder viewstatedecoded = new ViewStateDecoder();
                    try {
                        if (log.isDebugEnabled())
                            log.debug(
                                    "The following Base64 string has a ViewState preamble: ["
                                            + haystack.originalData
                                            + "]");
                        viewstatexml = ViewStateDecoder.decodeAsXML(Base64.decode(haystack.originalData.getBytes()));
                        if (log.isDebugEnabled())
                            log.debug(
                                    "The data was successfully decoded as ViewState data of length "
                                            + viewstatexml.length()
                                            + ": "
                                            + viewstatexml);
                        validviewstate = true;

                        // is the ViewState protected by a MAC?
                        Matcher hmaclessmatcher =
                                PATTERN_NO_HMAC.matcher(viewstatexml);
                        macless = hmaclessmatcher.find();

                        if (log.isDebugEnabled()) log.debug("MAC-less??? " + macless);
                    } catch (Exception e) {
                        // no need to do anything here.. just don't set "validviewstate" to true
                        // :)
                        // e.printStackTrace();
                        if (log.isDebugEnabled())
                            log.debug(
                                    "The Base64 value ["
                                            + haystack.originalData
                                            + "] has a valid ViewState pre-amble, but is not a valid viewstate. It may be an EVENTVALIDATION value, is not yet decodable.");
                    }
                }

                if (validviewstate == true) {
                    if (log.isDebugEnabled())
                        log.debug("Raising a ViewState informational alert");

                    // raise an (informational) Alert with the human readable ViewState data
                    Alert alert =
                            new Alert(
                                    getPluginId(),
                                    Alert.RISK_INFO,
                                    Alert.CONFIDENCE_MEDIUM,
                                    Constant.messages.getString(
                                            "pscanalpha.base64disclosure.viewstate.name"));
                    alert.setDetail(
                            Constant.messages.getString(
                                    "pscanalpha.base64disclosure.viewstate.desc"),
                            msg.getRequestHeader().getURI().toString(),
                            "", // param
                            "", // attack
                            Constant.messages.getString(
                                    "pscanalpha.base64disclosure.viewstate.extrainfo",
                                    viewstatexml), // other info
                            Constant.messages.getString(
                                    "pscanalpha.base64disclosure.viewstate.soln"),
                            Constant.messages.getString(
                                    "pscanalpha.base64disclosure.viewstate.refs"),
                            viewstatexml, // evidence
                            200, // Information Exposure,
                            13, // Information Leakage
                            msg);
                    parent.raiseAlert(id, alert);
                    // do NOT break at this point.. we need to find *all* the issues

                    // if the ViewState is not protected by a MAC, alert it as a High, cos we
                    // can mess with the parameters for sure..
                    if (macless) {
                        Alert alertmacless =
                                new Alert(
                                        getPluginId(),
                                        Alert.RISK_HIGH,
                                        Alert.CONFIDENCE_MEDIUM,
                                        Constant.messages.getString(
                                                "pscanalpha.base64disclosure.viewstatewithoutmac.name"));
                        alertmacless.setDetail(
                                Constant.messages.getString(
                                        "pscanalpha.base64disclosure.viewstatewithoutmac.desc"),
                                msg.getRequestHeader().getURI().toString(),
                                "", // param
                                "", // attack
                                Constant.messages.getString(
                                        "pscanalpha.base64disclosure.viewstatewithoutmac.extrainfo",
                                        viewstatexml), // other info
                                Constant.messages.getString(
                                        "pscanalpha.base64disclosure.viewstatewithoutmac.soln"),
                                Constant.messages.getString(
                                        "pscanalpha.base64disclosure.viewstatewithoutmac.refs"),
                                viewstatexml,
                                642, // CWE-642 = External Control of Critical State Data
                                13, // Information Leakage
                                msg);
                        parent.raiseAlert(id, alertmacless);
                        // do NOT break at this point.. we need to find *all* the issues
                    }
                    // TODO: if the ViewState contains sensitive data, alert it (particularly if
                    // running over HTTP)
                } else {
                    if (log.isDebugEnabled()) log.debug("Raising a Base64 informational alert");

                    // the Base64 decoded data is not a valid ViewState (even though it may have
                    // a valid ViewStatet pre-amble)
                    // so treat it as normal Base64 data, and raise an informational alert.
                    if (haystack.originalData.length() > 0) {
                        Alert alert =
                                new Alert(
                                        getPluginId(),
                                        Alert.RISK_INFO,
                                        Alert.CONFIDENCE_MEDIUM,
                                        getName());
                        alert.setDetail(
                                getDescription(),
                                msg.getRequestHeader().getURI().toString(),
                                "", // param
                                null,
                                getExtraInfo(msg, haystack.originalData, haystack.decodedData), // other info
                                getSolution(),
                                getReference(),
                                haystack.originalData,
                                200, // Information Exposure,
                                13, // Information Leakage
                                msg);
                        parent.raiseAlert(id, alert);
                        // do NOT break at this point.. we need to find *all* the potential
                        // Base64 encoded data in the response..
                    }
                }
            }
    }

    private static List<Base64Data> extractPossibleBase64String(HttpMessage msg) {
        // get the body contents as a String, so we can match against it
        String responseheader = msg.getResponseHeader().getHeadersAsString();
        String responsebody = msg.getResponseBody().toString();
        String[] responseparts = {responseheader, responsebody};

        if (log.isDebugEnabled()) log.debug("Trying Base64 Pattern: " + BASE64_PATTERN);
        List<Base64Data> possibleBase64Patterns = new ArrayList<>();
        for (String haystack : responseparts) {
            Matcher matcher = BASE64_PATTERN.matcher(haystack);
            while (matcher.find()) {
                String base64evidence = matcher.group();
                String tempbase64evidence = base64evidence;
                byte[] decodeddata;
                try {
                    // if the string had the "-_" alphabet, replace the - and _ with + and /
                    // respectively
                    tempbase64evidence = tempbase64evidence.replace('-', '+');
                    tempbase64evidence = tempbase64evidence.replace('_', '/');

                    // decode the data
                    decodeddata = Base64.decode(tempbase64evidence);
                    possibleBase64Patterns.add(
                            new Base64Data(base64evidence, tempbase64evidence, decodeddata));

                } catch (IOException e) {
                    // it's not actually Base64. so skip it.
                    if (log.isDebugEnabled())
                        log.debug(
                                "["
                                        + tempbase64evidence
                                        + "] (modified from ["
                                        + base64evidence
                                        + "]) could not be decoded as Base64 data");
                }
            }
        }
        return possibleBase64Patterns;
    }

    private static List<Base64Data> filterBase64StringByLikelihood(
            List<Base64Data> possibleBase64Patterns, float probabilityThreshold) {
        List<Base64Data> base64Patterns = new ArrayList<>();

        for (Base64Data data : possibleBase64Patterns) {
            String base64evidenceString = data.transformData;
            // set the threshold percentage based on what threshold was set by the user
            Set<Base64CharProbability> charClasses =
                    Stream.of(Base64CharProbability.values())
                            .filter(
                                    x ->
                                            x.isUnlikelyToBeBase64(
                                                    base64evidenceString, probabilityThreshold))
                            .collect(toSet());
            if (!charClasses.isEmpty()) {
                if (log.isTraceEnabled()) {
                    log.trace(
                            "The following candidate Base64 has been excluded on probabilistic grounds: ["
                                    + base64evidenceString
                                    + "] ");
                    for (Base64CharProbability charClass : charClasses) {
                        log.trace(
                                "The candidate Base64 has no "
                                        + charClass.name().toLowerCase()
                                        + " characters, and the the probability of this occurring for a string of this length is "
                                        + (charClass.calculateProbabilityOfNotContainingCharClass(
                                        base64evidenceString)
                                        * 100)
                                        + "%. The threshold is "
                                        + (probabilityThreshold * 100)
                                        + "%");
                    }
                }
                continue;
            }
            base64Patterns.add(data);
            if (log.isDebugEnabled())
                log.debug(
                        "Found a match for Base64, of length "
                                + data.originalData.length()
                                + ":"
                                + data.originalData);
        }
        return base64Patterns;
    }


    /**
     * sets the parent
     *
     * @param parent
     */
    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    /**
     * get the id of the scanner
     *
     * @return
     */
    @Override
    public int getPluginId() {
        return 10094;
    }

    /**
     * get the description of the alert
     *
     * @return
     */
    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    /**
     * get the solution for the alert
     *
     * @return
     */
    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    /**
     * gets references for the alert
     *
     * @return
     */
    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    /**
     * gets extra information associated with the alert
     *
     * @param msg
     * @return
     */
    private String getExtraInfo(HttpMessage msg, String evidence, byte[] decodeddata) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + "extrainfo", evidence, new String(decodeddata));
    }
}
