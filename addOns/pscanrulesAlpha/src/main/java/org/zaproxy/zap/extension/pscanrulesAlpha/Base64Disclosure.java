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

import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A class to passively scan responses for Base64 encoded data, including ASP ViewState data, which
 * is Base64 encoded.
 *
 * @author 70pointer@gmail.com
 */
public class Base64Disclosure extends PluginPassiveScanner {

    /**
     * a set of patterns used to identify Base64 encoded data. Set a minimum length to reduce false
     * positives. Note that because we only look for patterns ending in at least one "=", we will
     * have false negatives (ie, we will not detect ALL Base64 references). If we do not include
     * this condition, however, we will have a very large number of false positives. TODO: find a
     * different way to reduce false positives without causing false negatives.
     */
    // static Pattern base64Pattern = Pattern.compile("[a-zA-Z0-9\\+\\\\/]{30,}={1,2}");
    // static Pattern base64Pattern = Pattern.compile("[a-zA-Z0-9\\+\\\\/]{30,}={0,2}");
    static Set<Pattern> base64Patterns =
            new LinkedHashSet<>(); // the order of patterns is important. most specific first

    static {
        // base64Patterns.add(Pattern.compile("[a-zA-Z0-9\\+\\\\/]{30,}={0,2}"));
        // base64Patterns.add(Pattern.compile("[a-zA-Z0-9\\-_]{30,}={0,2}"));  //used in JWT - file
        // and URL safe variant of Base64 alphabet
        base64Patterns.add(Pattern.compile("[a-zA-Z0-9\\+\\\\/\\-_]{30,}={0,2}"));
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
    private static Logger log = LogManager.getLogger(Base64Disclosure.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.base64disclosure.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED);
    private static final List<String> IGNORED_HEADERS =
            Arrays.asList("ETag", "Authorization", "X-ChromeLogger-Data", "X-ChromePhp-Data");

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
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

        log.debug("Checking message {} for Base64 encoded data", msg);

        HttpResponseHeader responseHdr;
        try {
            responseHdr = new HttpResponseHeader(msg.getResponseHeader().toString());
            for (String hdr : IGNORED_HEADERS) {
                responseHdr.setHeader(hdr, null);
            }
        } catch (HttpMalformedHeaderException e1) {
            log.debug("Failed to copy response header", e1);
            // Set a placeholder so that the body is still analyzed
            responseHdr = new HttpResponseHeader();
        }

        // get the contents as a String, so we can match against it
        String responseheader = responseHdr.getHeadersAsString();
        String responsebody = msg.getResponseBody().toString();
        String[] responseparts = {responseheader, responsebody};

        // for each pattern..
        for (Pattern pattern : base64Patterns) {
            log.debug("Trying Base64 Pattern: {}", pattern);
            for (String haystack : responseparts) {
                Matcher matcher = pattern.matcher(haystack);
                while (matcher.find()) {
                    String base64evidence = matcher.group();
                    String tempbase64evidence = base64evidence;
                    byte[] decodeddata = null;
                    try {
                        // if the string had the "-_" alphabet, replace the - and _ with + and /
                        // respectively
                        tempbase64evidence = tempbase64evidence.replace('-', '+');
                        tempbase64evidence = tempbase64evidence.replace('_', '/');

                        // decode the data
                        decodeddata = Base64.getDecoder().decode(tempbase64evidence);
                    } catch (IllegalArgumentException e) {
                        // it's not actually Base64. so skip it.
                        log.debug(
                                "[{}] (modified from [{}]) could not be decoded as Base64 data",
                                tempbase64evidence,
                                base64evidence);
                        continue;
                    }

                    // does the base 64 encoded string actually contain the various characters that
                    // we might expect?
                    // (note: we may not care, depending on the threshold set by the user)
                    String base64evidenceString = new String(tempbase64evidence);
                    boolean noDigitInString = !digitPattern.matcher(base64evidenceString).find();
                    boolean noAlphaInString = !alphaPattern.matcher(base64evidenceString).find();
                    // boolean noOtherInString = !
                    // otherPattern.matcher(base64evidenceString).find();
                    boolean noLowerInString =
                            !lowercasePattern.matcher(base64evidenceString).find();
                    boolean noUpperInString =
                            !uppercasePattern.matcher(base64evidenceString).find();

                    // calculate the actual probability of a Base64 string of this length *not*
                    // containing a given character class (digit/alphabetic/other Base64 character)
                    // right about now, I expect to get flamed by the statistics geeks in our
                    // midst.. wait for it! :)
                    float probabilityOfNoDigitInString =
                            (float) Math.pow(((float) 64 - 10) / 64, base64evidence.length());
                    float probabilityOfNoAlphaInString =
                            (float) Math.pow(((float) 64 - 52) / 64, base64evidence.length());
                    // float probabilityOfNoOtherInString = (float)Math.pow(((float)64-2)/64,
                    // base64evidence.length());
                    float probabilityOfNoLowerInString =
                            (float) Math.pow(((float) 64 - 26) / 64, base64evidence.length());
                    float probabilityOfNoUpperInString = probabilityOfNoLowerInString;

                    // set the threshold percentage based on what threshold was set by the user
                    float probabilityThreshold = 0.0F; // 0% probability threshold
                    switch (this.getAlertThreshold()) {
                            // 50% probability threshold (ie, "on balance of probability")
                        case HIGH:
                            probabilityThreshold = 0.50F;
                            break;
                            // 25% probability threshold
                        case MEDIUM:
                            probabilityThreshold = 0.25F;
                            break;
                            // 10% probability threshold
                        case LOW:
                            probabilityThreshold = 0.10F;
                            break;
                            // 0% probability threshold (all structurally valid Base64 data is
                            // considered, regardless of how improbable  it is given character
                            // frequencies, etc.)
                        default:
                    }

                    // if the String is unlikely to be Base64, given the distribution of the
                    // characters
                    // ie, less probable than the threshold probability controlled by the user, then
                    // do not process it.
                    if ((noDigitInString && probabilityOfNoDigitInString < probabilityThreshold)
                            || (noAlphaInString
                                    && probabilityOfNoAlphaInString < probabilityThreshold)
                            ||
                            // (noOtherInString && probabilityOfNoOtherInString <
                            // probabilityThreshold) ||
                            (noLowerInString && probabilityOfNoLowerInString < probabilityThreshold)
                            || (noUpperInString
                                    && probabilityOfNoUpperInString < probabilityThreshold)) {

                        log.trace(
                                "The following candidate Base64 has been excluded on probabilistic grounds: [{}] ",
                                base64evidence);
                        if (noDigitInString)
                            log.trace(
                                    "The candidate Base64 has no digit characters, and the the probability of this occurring for a string of this length is {}%. The threshold is {}%",
                                    probabilityOfNoDigitInString * 100, probabilityThreshold * 100);
                        if (noAlphaInString)
                            log.trace(
                                    "The candidate Base64 has no alphabetic characters, and the the probability of this occurring for a string of this length is {}%. The threshold is {}%",
                                    probabilityOfNoAlphaInString * 100, probabilityThreshold * 100);
                        // if (noOtherInString)
                        // log.trace("The candidate Base64 has no 'other' characters, and the
                        // probability of this occurring for a string of this length is {}%. The
                        // threshold is {}%",probabilityOfNoOtherInString *
                        // 100,probabilityThreshold *100);
                        if (noLowerInString)
                            log.trace(
                                    "The candidate Base64 has no lowercase characters, and the the probability of this occurring for a string of this length is {}%. The threshold is {}%",
                                    probabilityOfNoLowerInString * 100, probabilityThreshold * 100);

                        if (noUpperInString)
                            log.trace(
                                    "The candidate Base64 has no uppercase characters, and the the probability of this occurring for a string of this length is {}%. The threshold is {}%",
                                    probabilityOfNoUpperInString * 100, probabilityThreshold * 100);

                        continue;
                    }

                    log.debug(
                            "Found a match for Base64, of length {}:{}",
                            base64evidence.length(),
                            base64evidence);

                    // so it's valid Base64.  Is it valid .NET ViewState data?
                    // This will be true for both __VIEWSTATE and __EVENTVALIDATION data, although
                    // currently, we can only interpret/decode __VIEWSTATE.
                    boolean validviewstate = false;
                    boolean macless = false;
                    String viewstatexml = null;
                    if (decodeddata[0] == -1 || decodeddata[1] == 0x01) {
                        // TODO: decode __EVENTVALIDATION data
                        ViewStateDecoder viewstatedecoded = new ViewStateDecoder();
                        try {

                            log.debug(
                                    "The following Base64 string has a ViewState preamble: [{}]",
                                    base64evidence);
                            viewstatexml = viewstatedecoded.decodeAsXML(base64evidence.getBytes());

                            log.debug(
                                    "The data was successfully decoded as ViewState data of length {}: {}",
                                    viewstatexml.length(),
                                    viewstatexml);
                            validviewstate = true;

                            // is the ViewState protected by a MAC?
                            Matcher hmaclessmatcher =
                                    ViewStateDecoder.PATTERN_NO_HMAC.matcher(viewstatexml);
                            macless = hmaclessmatcher.find();

                            log.debug("MAC-less??? {}", macless);
                        } catch (Exception e) {
                            // no need to do anything here.. just don't set "validviewstate" to true
                            // :)
                            log.debug(
                                    "The Base64 value [{}] has a valid ViewState pre-amble, but is not a valid viewstate. It may be an EVENTVALIDATION value, is not yet decodable.",
                                    base64evidence);
                        }
                    }

                    if (validviewstate == true) {
                        log.debug("Raising a ViewState informational alert");

                        // raise an (informational) Alert with the human readable ViewState data
                        newAlert()
                                .setName(
                                        Constant.messages.getString(
                                                "pscanalpha.base64disclosure.viewstate.name"))
                                .setRisk(Alert.RISK_INFO)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setDescription(
                                        Constant.messages.getString(
                                                "pscanalpha.base64disclosure.viewstate.desc"))
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                "pscanalpha.base64disclosure.viewstate.extrainfo",
                                                viewstatexml))
                                .setSolution(
                                        Constant.messages.getString(
                                                "pscanalpha.base64disclosure.viewstate.soln"))
                                .setReference(
                                        Constant.messages.getString(
                                                "pscanalpha.base64disclosure.viewstate.refs"))
                                .setEvidence(viewstatexml)
                                .setCweId(200) // Information Exposure,
                                .setWascId(13) // Information Leakage
                                .raise();
                        if (!macless && !AlertThreshold.LOW.equals(getAlertThreshold())) {
                            return;
                        }

                        // if the ViewState is not protected by a MAC, alert it as a High, cos we
                        // can mess with the parameters for sure..
                        if (macless) {
                            newAlert()
                                    .setName(
                                            Constant.messages.getString(
                                                    "pscanalpha.base64disclosure.viewstatewithoutmac.name"))
                                    .setRisk(Alert.RISK_HIGH)
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setDescription(
                                            Constant.messages.getString(
                                                    "pscanalpha.base64disclosure.viewstatewithoutmac.desc"))
                                    .setOtherInfo(
                                            Constant.messages.getString(
                                                    "pscanalpha.base64disclosure.viewstatewithoutmac.extrainfo",
                                                    viewstatexml))
                                    .setSolution(
                                            Constant.messages.getString(
                                                    "pscanalpha.base64disclosure.viewstatewithoutmac.soln"))
                                    .setReference(
                                            Constant.messages.getString(
                                                    "pscanalpha.base64disclosure.viewstatewithoutmac.refs"))
                                    .setEvidence(viewstatexml)
                                    .setCweId(642) // CWE-642 = External Control of Critical State
                                    // Data
                                    .setWascId(13) // Information Leakage
                                    .raise();
                            if (!AlertThreshold.LOW.equals(getAlertThreshold())) {
                                return;
                            }
                        }
                        // TODO: if the ViewState contains sensitive data, alert it (particularly if
                        // running over HTTP)
                    } else {
                        log.debug("Raising a Base64 informational alert");

                        // the Base64 decoded data is not a valid ViewState (even though it may have
                        // a valid ViewStatet pre-amble)
                        // so treat it as normal Base64 data, and raise an informational alert.
                        if (base64evidence.length() > 0) {
                            newAlert()
                                    .setRisk(Alert.RISK_INFO)
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setDescription(getDescription())
                                    .setOtherInfo(getExtraInfo(msg, base64evidence, decodeddata))
                                    .setSolution(getSolution())
                                    .setReference(getReference())
                                    .setEvidence(base64evidence)
                                    .setCweId(200) // CWE-200 = Information Exposure
                                    .setWascId(13) // Information Leakage
                                    .raise();
                            if (!AlertThreshold.LOW.equals(getAlertThreshold())) {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public int getPluginId() {
        return 10094;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private String getExtraInfo(HttpMessage msg, String evidence, byte[] decodeddata) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + "extrainfo", evidence, new String(decodeddata));
    }
}
