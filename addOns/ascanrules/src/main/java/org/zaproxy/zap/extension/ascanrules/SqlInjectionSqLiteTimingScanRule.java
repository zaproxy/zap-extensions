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
package org.zaproxy.zap.extension.ascanrules;

import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * The SqlInjectionSqLiteScanRule identifies SQLite specific SQL Injection vulnerabilities using
 * SQLite specific syntax. If it doesn't use SQLite specific syntax, it belongs in the generic
 * SQLInjection class!
 *
 * @author 70pointer
 */
public class SqlInjectionSqLiteTimingScanRule extends AbstractAppParamPlugin {

    // Some relevant notes about SQLite's support for various functions, which will affect what SQL
    // is valid,
    // and can be used to exploit each particular version :)
    // some of the functions noted here are *very* useful in exploiting the system hosting the
    // SQLite instance,
    // but I won't give the game away too easily. Go have a play!
    // 3.8.6       (2014-08-15) - hex integer literals supported, likely(X) supported, readfile(X)
    // and writefile(X,Y) supported (if extension loading enabled)
    // 3.8.3       (2014-02-03) - common table subexpressions supported ("WITH" keyword), printf
    // function supported
    // 3.8.1       (2013-10-17) - unlikely() and likelihood() functions supported
    // 3.8.0       (2013-08-26) - percentile() function added as loadable extension
    // 3.7.17      (2013-05-20) - new loadable extensions: including amatch, closure, fuzzer,
    // ieee754, nextchar, regexp, spellfix, and wholenumber
    // 3.7.16      (2013-03-18) - unicode(A) and char(X1,...,XN) supported
    // 3.7.15      (2012-12-12) - instr() supported
    // 3.6.8       (2009-01-12) - nested transactions supported
    // 3.5.7       (2008-03-17) - ALTER TABLE uses double-quotes instead of single-quotes for
    // quoting filenames (why filenames????).
    // 3.3.13      (2007-02-13) - randomBlob() and hex() supported
    // 3.3.8       (2006-10-09) - IF EXISTS on CREATE/DROP TRIGGER/VIEW
    // 3.3.7       (2006-08-12) - virtual tables, dynamically loaded extensions, MATCH operator
    // supported
    // 3.2.6       (2005-09-17) - COUNT(DISTINCT expr) supported
    // 3.2.3       (2005-08-21) - CAST operator, grave-accent quoting supported
    // 3.2.0       (2005-03-21) - ALTER TABLE ADD COLUMN supported
    // 3.1.0 ALPHA (2005-01-21) - ALTER TABLE ... RENAME TABLE, CURRENT_TIME, CURRENT_DATE, and
    // CURRENT_TIMESTAMP, EXISTS clause, correlated subqueries supported
    // 3.0.0 alpha (2004-06-18) - dropped support for COPY function, possibly added
    // sqlite_source_id(), replace() (which were not in 2.8.17)
    // 2.8.6       (2003-08-21) - date functions added
    // 2.8.5       (2003-07-22) - supports LIMIT on a compound SELECT statement
    // 2.8.1       (2003-05-16) - ATTACH and DETACH commands supported
    // 2.5.0       (2002-06-17) - Double-quoted strings interpreted as column names not text
    // literals,
    //                           SQL-92 compliant handling of NULLs, full SQL-92 join syntax and
    // LEFT OUTER JOINs supported
    // 2.4.7       (2002-04-06) - "select TABLE.*", last_insert_rowid() supported
    // 2.4.4       (2002-03-24) - CASE expressions supported
    // 2.4.0       (2002-03-10) - coalesce(), lower(), upper(), and random() supported
    // 2.3.3       (2002-02-18) - Allow identifiers to be quoted in square brackets, "CREATE TABLE
    // AS SELECT" supported
    // 2.2.0       (2001-12-22) - "SELECT rowid, * FROM table1" supported
    // 2.0.3       (2001-10-13) - &, |,~,<<,>>,round() and abs() supported
    // 2.0.1       (2001-10-02) - "expr NOT NULL", "expr NOTNULL" supported
    // 1.0.32      (2001-07-23) - quoted strings supported as table and column names in expressions
    // 1.0.28      (2001-04-04) - special column names ROWID, OID, and _ROWID_ supported (with
    // random values)
    // 1.0.4       (2000-08-28) - length() and substr() supported
    // 1.0         (2000-08-17) - covers lots of unversioned releases.  ||, fcnt(), UNION, UNION
    // ALL, INTERSECT, and EXCEPT, LIKE, GLOB, COPY supported

    private int expectedDelayInMs = 5000;

    private boolean doTimeBased = false;

    private int doTimeMaxRequests = 0;

    /** SQLite one-line comment */
    public static final String SQL_ONE_LINE_COMMENT = "--";

    /**
     * SQLite specific time based injection strings, where each tries to cause a measurable delay
     */

    // Note: <<<<ORIGINALVALUE>>>> is replaced with the original parameter value at runtime in these
    // examples below
    // TODO: maybe add support for ')' after the original value, before the sleeps
    // Note: randomblob is supported from SQLite 3.3.13 (2007-02-13)
    //		case statement is supported from SQLite 2.4.4 (2002-03-24)
    private static String[] SQL_SQLITE_TIME_REPLACEMENTS = {
        // omitting original param
        "case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end ", // integer
        "' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | '", // character/string (single quote)
        "\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | \"", // character/string (double quote)
        "case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end "
                + SQL_ONE_LINE_COMMENT, // integer
        "' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end "
                + SQL_ONE_LINE_COMMENT, // character/string (single quote)
        "\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end "
                + SQL_ONE_LINE_COMMENT, // character/string (double quote)

        // with the original parameter
        "<<<<ORIGINALVALUE>>>> * case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end ", // integer
        "<<<<ORIGINALVALUE>>>>' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | '", // character/string (single quote)
        "<<<<ORIGINALVALUE>>>>\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | \"", // character/string (double quote)
        "<<<<ORIGINALVALUE>>>> * case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end "
                + SQL_ONE_LINE_COMMENT, // integer
        "<<<<ORIGINALVALUE>>>>' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end "
                + SQL_ONE_LINE_COMMENT, // character/string (single quote)
        "<<<<ORIGINALVALUE>>>>\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end "
                + SQL_ONE_LINE_COMMENT, // character/string (double quote)
    };

    /** if the following errors occur during the attack, it's a SQL injection vuln */
    private Pattern errorMessagePatterns[] = {
        Pattern.compile(
                "no such function: randomblob",
                Pattern.CASE_INSENSITIVE) // this one is specific to the time-based attack
        // attempted here, and is indicative of SQLite versions <
        // 3.3.13, and >= 2.4.4 (because the CASE statement is
        // used)
        ,
        Pattern.compile("near \\\".+\\\": syntax error", Pattern.CASE_INSENSITIVE)
    };

    /** set depending on the attack strength / threshold */
    private long maxBlobBytes = 0;

    private long minBlobBytes = 100000;
    private long parseDelayDifference = 0;
    private long incrementalDelayIncreasesForAlert = 0;

    private char[] RANDOM_PARAMETER_CHARS = "abcdefghijklmnopqrstuvwyxz0123456789".toCharArray();
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);

    /** for logging. */
    private static final Logger LOGGER =
            LogManager.getLogger(SqlInjectionSqLiteTimingScanRule.class);

    @Override
    public int getId() {
        return 90038;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sqlinjection.sqlite.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.SQLite);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanrules.sqlinjection.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanrules.sqlinjection.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanrules.sqlinjection.refs");
    }

    @Override
    public void init() {
        LOGGER.debug("Initialising");

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == Plugin.AttackStrength.LOW) {
            doTimeBased = true;
            doTimeMaxRequests = 0;
            this.maxBlobBytes = 1000000000;
        } else if (this.getAttackStrength() == Plugin.AttackStrength.MEDIUM) {
            doTimeBased = true;
            doTimeMaxRequests = 4;
            this.maxBlobBytes = 1000000000;
        } else if (this.getAttackStrength() == Plugin.AttackStrength.HIGH) {
            doTimeBased = true;
            doTimeMaxRequests = 20;
            this.maxBlobBytes = 1000000000;
        } else if (this.getAttackStrength() == Plugin.AttackStrength.INSANE) {
            doTimeBased = true;
            doTimeMaxRequests = 100;
            this.maxBlobBytes = 1000000000;
        }

        // the allowable difference between a parse delay and an attack delay is controlled by the
        // threshold
        if (this.getAlertThreshold() == Plugin.AlertThreshold.LOW) {
            parseDelayDifference = 100;
            incrementalDelayIncreasesForAlert = 1;
        } else if (this.getAlertThreshold() == Plugin.AlertThreshold.MEDIUM) {
            parseDelayDifference = 200;
            incrementalDelayIncreasesForAlert = 2;
        } else if (this.getAlertThreshold() == Plugin.AlertThreshold.HIGH) {
            parseDelayDifference = 400;
            incrementalDelayIncreasesForAlert = 3;
        }
    }

    /**
     * scans for SQL Injection vulnerabilities, using SQLite specific syntax. If it doesn't use
     * specifically SQLite syntax, it does not belong in here, but in TestSQLInjection
     */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String originalParamValue) {

        try {
            // the original message passed to us never has the response populated. fix that by
            // re-retrieving it..
            sendAndReceive(originalMessage, false); // do not follow redirects

            // Do time based SQL injection checks..
            // Timing Baseline check: we need to get the time that it took the original query, to
            // know if the time based check is working correctly..
            HttpMessage msgTimeBaseline = getNewMsg();
            try {
                sendAndReceive(msgTimeBaseline);
            } catch (SocketTimeoutException e) {
                // to be expected occasionally, if the base query was one that contains some
                // parameters exploiting time based SQL injection?
                LOGGER.debug(
                        "The Base Time Check timed out on [{}] URL [{}]",
                        msgTimeBaseline.getRequestHeader().getMethod(),
                        msgTimeBaseline.getRequestHeader().getURI());
            }
            long originalTimeUsed = msgTimeBaseline.getTimeElapsedMillis();
            // if the time was very slow (because JSP was being compiled on first call, for
            // instance)
            // then the rest of the time based logic will fail.  Lets double-check for that scenario
            // by requesting the url again.
            // If it comes back in a more reasonable time, we will use that time instead as our
            // baseline.  If it come out in a slow fashion again,
            // we will abort the check on this URL, since we will only spend lots of time trying
            // request, when we will (very likely) not get positive results.
            if (originalTimeUsed > expectedDelayInMs) {
                try {
                    sendAndReceive(msgTimeBaseline);
                } catch (SocketTimeoutException e) {
                    // to be expected occasionally, if the base query was one that contains some
                    // parameters exploiting time based SQL injection?
                    LOGGER.debug(
                            "Base Time Check 2 timed out on [{}] URL [{}]",
                            msgTimeBaseline.getRequestHeader().getMethod(),
                            msgTimeBaseline.getRequestHeader().getURI());
                }
                long originalTimeUsed2 = msgTimeBaseline.getTimeElapsedMillis();
                if (originalTimeUsed2 > expectedDelayInMs) {
                    // no better the second time around.  we need to bale out.
                    LOGGER.debug(
                            "Both base time checks 1 and 2 for [{}] URL [{}] are way too slow to be usable for the purposes of checking for time based SQL Injection checking.  We are aborting the check on this particular url.",
                            msgTimeBaseline.getRequestHeader().getMethod(),
                            msgTimeBaseline.getRequestHeader().getURI());
                    return;
                } else {
                    // phew.  the second time came in within the limits. use the later timing
                    // details as the base time for the checks.
                    originalTimeUsed = originalTimeUsed2;
                }
            }
            // end of timing baseline check

            int countTimeBasedRequests = 0;
            LOGGER.debug(
                    "Scanning URL [{}] [{}], [{}] with value [{}] for SQL Injection",
                    getBaseMsg().getRequestHeader().getMethod(),
                    getBaseMsg().getRequestHeader().getURI(),
                    paramName,
                    originalParamValue);

            // SQLite specific time-based SQL injection checks
            boolean foundTimeBased = false;
            for (int timeBasedSQLindex = 0;
                    timeBasedSQLindex < SQL_SQLITE_TIME_REPLACEMENTS.length
                            && doTimeBased
                            && countTimeBasedRequests < doTimeMaxRequests;
                    timeBasedSQLindex++) {
                // since we have no means to create a deterministic delay in SQLite, we need to take
                // a different approach:
                // in each iteration, increase the number of random blobs for SQLite to create.  If
                // we can detect an increasing delay, we know
                // that the payload has been successfully injected.
                int numberOfSequentialIncreases = 0;
                String detectableDelayParameter = null;
                long detectableDelay = 0;
                String maxDelayParameter = null;
                long maxDelay = 0;
                HttpMessage detectableDelayMessage = null;
                long previousDelay = originalTimeUsed;
                boolean potentialTimeBasedSQLInjection = false;
                boolean timeExceeded = false;

                for (long numBlobsToCreate = minBlobBytes;
                        numBlobsToCreate <= this.maxBlobBytes
                                && !timeExceeded
                                && numberOfSequentialIncreases < incrementalDelayIncreasesForAlert;
                        numBlobsToCreate *= 10) {

                    HttpMessage msgDelay = getNewMsg();
                    String newTimeBasedInjectionValue =
                            SQL_SQLITE_TIME_REPLACEMENTS[timeBasedSQLindex].replace(
                                    "<<<<ORIGINALVALUE>>>>", originalParamValue);
                    newTimeBasedInjectionValue =
                            newTimeBasedInjectionValue.replace(
                                    "<<<<NUMBLOBBYTES>>>>", Long.toString(numBlobsToCreate));
                    setParameter(msgDelay, paramName, newTimeBasedInjectionValue);

                    LOGGER.debug(
                            "\nTrying '{}'. The number of Sequential Increases already is {}",
                            newTimeBasedInjectionValue,
                            numberOfSequentialIncreases);

                    // send it.
                    try {
                        sendAndReceive(msgDelay);
                        countTimeBasedRequests++;
                    } catch (SocketTimeoutException e) {
                        // to be expected occasionally, if the contains some parameters exploiting
                        // time based SQL injection
                        LOGGER.debug(
                                "The time check query timed out on [{}] URL [{}] on field: [{}]",
                                msgTimeBaseline.getRequestHeader().getMethod(),
                                msgTimeBaseline.getRequestHeader().getURI(),
                                paramName);
                    }
                    long modifiedTimeUsed = msgDelay.getTimeElapsedMillis();

                    // before we do the time based checking, first check for a known error message
                    // from the attack, indicating a SQL injection vuln
                    for (Pattern errorMessagePattern : errorMessagePatterns) {
                        Matcher matcher =
                                errorMessagePattern.matcher(msgDelay.getResponseBody().toString());
                        boolean errorFound = matcher.find();
                        if (errorFound) {
                            // Likely an error based SQL Injection. Raise it
                            String extraInfo =
                                    Constant.messages.getString(
                                            "ascanrules.sqlinjection.sqlite.alert.errorbased.extrainfo",
                                            errorMessagePattern);
                            // raise the alert
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                                    .setParam(paramName)
                                    .setAttack(newTimeBasedInjectionValue)
                                    .setOtherInfo(extraInfo)
                                    .setEvidence(matcher.group())
                                    .setMessage(msgDelay)
                                    .raise();

                            LOGGER.debug(
                                    "A likely Error Based SQL Injection Vulnerability has been found with [{}] URL [{}] on field: [{}], by matching for pattern [{}]",
                                    msgDelay.getRequestHeader().getMethod(),
                                    msgDelay.getRequestHeader().getURI(),
                                    paramName,
                                    errorMessagePattern);
                            foundTimeBased =
                                    true; // yeah, I know. we found an error based, while looking
                            // for a time based. bale out anyways.
                            break; // out of the loop
                        }
                    }
                    // outta the time based loop..
                    if (foundTimeBased) break;

                    // no error message detected from the time based attack.. continue looking for
                    // time based injection point.

                    // cap the time we will delay by to 10 seconds
                    if (modifiedTimeUsed > 10000) timeExceeded = true;

                    boolean parseTimeEquivalent = false;
                    if (modifiedTimeUsed > previousDelay) {
                        LOGGER.debug(
                                "The response time {} is > the previous response time {}",
                                modifiedTimeUsed,
                                previousDelay);
                        // in order to rule out false positives due to the increasing SQL parse time
                        // for longer parameter values
                        // we send a random (alphanumeric only) string value of the same length as
                        // the attack parameter
                        // we expect the response time for the SQLi attack to be greater than or
                        // equal to the response time for
                        // the random alphanumeric string parameter
                        // if this is not the case, then we assume that the attack parameter is not
                        // a potential SQL injection causing payload.
                        HttpMessage msgParseDelay = getNewMsg();
                        String parseDelayCheckParameter =
                                RandomStringUtils.random(
                                        newTimeBasedInjectionValue.length(),
                                        RANDOM_PARAMETER_CHARS);
                        setParameter(msgParseDelay, paramName, parseDelayCheckParameter);
                        sendAndReceive(msgParseDelay);
                        countTimeBasedRequests++;
                        long parseDelayTimeUsed = msgParseDelay.getTimeElapsedMillis();

                        // figure out if the attack delay and the (non-sql-injection) parse delay
                        // are within X ms of each other..
                        parseTimeEquivalent =
                                (Math.abs(modifiedTimeUsed - parseDelayTimeUsed)
                                        < this.parseDelayDifference);
                        LOGGER.debug(
                                "The parse time a random parameter of the same length is {}, so the attack and random parameter are {} equivalent (given the user defined attack threshold)",
                                parseDelayTimeUsed,
                                parseTimeEquivalent ? "" : "NOT ");
                    }

                    if (modifiedTimeUsed > previousDelay && !parseTimeEquivalent) {

                        maxDelayParameter = newTimeBasedInjectionValue;
                        maxDelay = modifiedTimeUsed;

                        // potential for SQL injection, detectable with "numBlobsToCreate" random
                        // blobs being created..
                        numberOfSequentialIncreases++;
                        if (!potentialTimeBasedSQLInjection) {
                            LOGGER.debug(
                                    "Setting the Detectable Delay parameter to '{}'",
                                    newTimeBasedInjectionValue);
                            detectableDelayParameter = newTimeBasedInjectionValue;
                            detectableDelay = modifiedTimeUsed;
                            detectableDelayMessage = msgDelay;
                        }
                        potentialTimeBasedSQLInjection = true;
                    } else {
                        // either no SQL injection, invalid SQL syntax, or timing difference is not
                        // detectable with "numBlobsToCreate" random blobs being created.
                        // keep trying with larger numbers of "numBlobsToCreate", since that's the
                        // thing we can most easily control and verify
                        // note also: if for some reason, an earlier attack with a smaller number of
                        // blobs indicated there might be a vulnerability
                        // then this case will rule that out if it was a fluke...
                        // the timing delay must keep increasing, as the number of blobs is
                        // increased.
                        potentialTimeBasedSQLInjection = false;
                        numberOfSequentialIncreases = 0;
                        detectableDelayParameter = null;
                        detectableDelay = 0;
                        detectableDelayMessage = null;
                        maxDelayParameter = null;
                        maxDelay = 0;
                        // do not break at this point, since we may simply need to keep increasing
                        // numBlobsToCreate to
                        // a point where we can detect the resulting delay
                    }
                    LOGGER.debug(
                            "Time Based SQL Injection test for {} random blob bytes: [{}] on field: [{}] with value [{}] took {}ms, where the original took {}ms.",
                            numBlobsToCreate,
                            newTimeBasedInjectionValue,
                            paramName,
                            newTimeBasedInjectionValue,
                            modifiedTimeUsed,
                            originalTimeUsed);
                    previousDelay = modifiedTimeUsed;

                    // bale out if we were asked nicely
                    if (isStop()) {
                        LOGGER.debug("Stopping the scan due to a user request");
                        return;
                    }
                } // end of for loop to increase the number of random blob bytes to create

                // the number of times that we could sequentially increase the delay by increasing
                // the "number of random blob bytes to create"
                // is the basis for the threshold of the alert.  In some cases, the user may want to
                // see a solid increase in delay
                // for say 4 or 5 iterations, in order to be confident the vulnerability exists.  In
                // other cases, the user may be happy with just 2 sequential increases...
                LOGGER.debug("Number of sequential increases: {}", numberOfSequentialIncreases);
                if (numberOfSequentialIncreases >= this.incrementalDelayIncreasesForAlert) {
                    // Likely a SQL Injection. Raise it
                    String extraInfo =
                            Constant.messages.getString(
                                    "ascanrules.sqlinjection.sqlite.alert.timebased.extrainfo",
                                    detectableDelayParameter,
                                    detectableDelay,
                                    maxDelayParameter,
                                    maxDelay,
                                    originalParamValue,
                                    originalTimeUsed);

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                            .setParam(paramName)
                            .setAttack(detectableDelayParameter)
                            .setOtherInfo(extraInfo)
                            .setEvidence(extraInfo)
                            .setMessage(detectableDelayMessage)
                            .raise();

                    if (detectableDelayMessage != null)
                        LOGGER.debug(
                                "A likely Time Based SQL Injection Vulnerability has been found with [{}] URL [{}] on field: [{}]",
                                detectableDelayMessage.getRequestHeader().getMethod(),
                                detectableDelayMessage.getRequestHeader().getURI(),
                                paramName);

                    // outta the time based loop..
                    break;
                } // the user-define threshold has been exceeded. raise it.

                // outta the time based loop..
                if (foundTimeBased) break;

                // bale out if we were asked nicely
                if (isStop()) {
                    LOGGER.debug("Stopping the scan due to a user request");
                    return;
                }
            } // for each time based SQL index
            // end of check for SQLite time based SQL Injection
        } catch (UnknownHostException | URIException e) {
            LOGGER.debug("Failed to send HTTP message, cause: {}", e.getMessage());
        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            LOGGER.error(
                    "An error occurred checking a url for SQLite SQL Injection vulnerabilities", e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 89;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
