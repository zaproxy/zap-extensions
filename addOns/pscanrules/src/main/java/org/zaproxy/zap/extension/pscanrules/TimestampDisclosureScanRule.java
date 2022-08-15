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
package org.zaproxy.zap.extension.pscanrules;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A class to passively scan responses for Timestamps, since these *may* be interesting from a
 * security standpoint
 *
 * @author 70pointer@gmail.com
 */
public class TimestampDisclosureScanRule extends PluginPassiveScanner {

    // We are only interested in events within a 10 year span
    private static final long EPOCH_Y2038 = 2147483647L;
    private static final ZonedDateTime ZONED_NOW = ZonedDateTime.now();

    private static final Date RANGE_START = Date.from(ZONED_NOW.minusYears(10).toInstant());
    private static final Date RANGE_STOP =
            new Date(
                    TimeUnit.SECONDS.toMillis(
                            Math.min(
                                    EPOCH_Y2038,
                                    ZONED_NOW.plusYears(10).toInstant().getEpochSecond())));
    private static final Instant ONE_YEAR_AGO = ZONED_NOW.minusYears(1).toInstant();
    private static final Instant ONE_YEAR_FROM_NOW = ZONED_NOW.plusYears(1).toInstant();
    /** a map of a regular expression pattern to details of the timestamp type found */
    static Map<Pattern, String> timestampPatterns = new HashMap<>();

    static {
        // 8 digits match CSS RGBA colors and with a very high false positive rate.
        // They also only match up to March 3, 1973 which is not worth considering.
        //
        // 9 digits match up to September 9, 2001 which is also really below any
        // interesting scope (it's more than 20 years ago).
        // As such, it's only worth looking at 10 digits.
        //
        // 2,000,000,000 is May 18, 2033 which is really beyond any interesting scope
        // at this time. At the time of this comment, it was more than 10 years in the
        // future. But it isn't a lot past 10 years, so we'll select 10 years as the
        // range.
        //
        // As such, we'll consider 2 billion series, but stop at:
        // 2147483647 which is posix time clock rollover.
        timestampPatterns.put(Pattern.compile("\\b(?:1\\d|2[0-2])\\d{8}\\b(?!%)"), "Unix");
    }

    private static Logger log = LogManager.getLogger(TimestampDisclosureScanRule.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.timestampdisclosure.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED);

    /**
     * ignore the following response headers for the purposes of the comparison, since they cause
     * false positives
     */
    public static final String[] RESPONSE_HEADERS_TO_IGNORE = {
        HttpHeader._KEEP_ALIVE,
        HttpHeader.CACHE_CONTROL,
        "ETag",
        "Age",
        "Strict-Transport-Security",
        "Report-To",
        "NEL",
        "Expect-CT"
    };

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
     * scans the HTTP response for timestamp signatures
     *
     * @param msg
     * @param id
     * @param source unused
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (ResourceIdentificationUtils.isFont(msg)) {
            return;
        }
        log.debug("Checking message {} for timestamps", msg.getRequestHeader().getURI());

        List<HttpHeaderField> responseheaders = msg.getResponseHeader().getHeaders();
        StringBuffer filteredResponseheaders = new StringBuffer();
        for (HttpHeaderField responseheader : responseheaders) {
            boolean ignoreHeader = false;
            for (String headerToIgnore : RESPONSE_HEADERS_TO_IGNORE) {
                if (responseheader.getName().equalsIgnoreCase(headerToIgnore)) {
                    log.debug("Ignoring header {}", responseheader.getName());
                    ignoreHeader = true;
                    break; // out of inner loop
                }
            }
            if (!ignoreHeader) {
                filteredResponseheaders.append("\n");
                filteredResponseheaders.append(
                        responseheader.getName() + ": " + responseheader.getValue());
            }
        }

        String responsebody = msg.getResponseBody().toString();
        String[] responseparts = {filteredResponseheaders.toString(), responsebody};

        // try each of the patterns in turn against the response.
        String timestampType = null;
        Iterator<Pattern> patternIterator = timestampPatterns.keySet().iterator();
        AlertThreshold threshold = this.getAlertThreshold();

        while (patternIterator.hasNext()) {
            Pattern timestampPattern = patternIterator.next();
            timestampType = timestampPatterns.get(timestampPattern);
            log.debug(
                    "Trying Timestamp Pattern: {} for timestamp type {}",
                    timestampPattern,
                    timestampType);
            for (String haystack : responseparts) {
                Matcher matcher = timestampPattern.matcher(haystack);
                while (matcher.find()) {
                    String evidence = matcher.group();
                    Date timestamp = null;
                    try {
                        // parse the number as a Unix timestamp
                        timestamp = new Date(TimeUnit.SECONDS.toMillis(Integer.parseInt(evidence)));
                    } catch (NumberFormatException nfe) {
                        // the number is not formatted correctly to be a timestamp. Skip it.
                        continue;
                    }
                    if (!AlertThreshold.LOW.equals(threshold)) {
                        if (RANGE_START.after(timestamp) || RANGE_STOP.before(timestamp)) {
                            continue;
                        }
                    }
                    log.debug("Found a match for timestamp type {}:{}", timestampType, evidence);

                    if (evidence != null && evidence.length() > 0) {
                        // we found something.. potentially
                        if (AlertThreshold.HIGH.equals(threshold)) {
                            Instant foundInstant = Instant.ofEpochSecond(Long.parseLong(evidence));
                            if (!(foundInstant.isAfter(ONE_YEAR_AGO)
                                    && foundInstant.isBefore(ONE_YEAR_FROM_NOW))) {
                                continue;
                            }
                        }
                        newAlert()
                                .setName(getName() + " - " + timestampType)
                                .setRisk(getRisk())
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setDescription(getDescription() + " - " + timestampType)
                                .setOtherInfo(getExtraInfo(msg, evidence, timestamp))
                                .setSolution(getSolution())
                                .setReference(getReference())
                                .setEvidence(evidence)
                                .setCweId(getCweId())
                                .setWascId(getWascId())
                                .raise();
                        // do NOT break at this point.. we need to find *all* the potential
                        // timestamps in the response..
                    }
                }
            }
        }
    }

    /**
     * get the id of the scan rule
     *
     * @return
     */
    @Override
    public int getPluginId() {
        return 10096;
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }

    /**
     * get the description of the alert
     *
     * @return
     */
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    /**
     * get the solution for the alert
     *
     * @return
     */
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    /**
     * gets references for the alert
     *
     * @return
     */
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    /**
     * gets extra information associated with the alert
     *
     * @param msg
     * @param arg0
     * @return
     */
    private String getExtraInfo(HttpMessage msg, String evidence, Date timestamp) {
        String formattedDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(timestamp);
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", evidence, formattedDate);
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 200; // CWE Id 200 - Information Exposure
    }

    public int getWascId() {
        return 13; // WASC Id - Info leakage
    }
}
