/*
 * Derivative Work based upon SQLMap source code implementation
 *
 * Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
 * Bernardo Damele Assumpcao Guimaraes, Miroslav Stampar.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.zaproxy.zap.extension.sqliplugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.RedirectException;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule for SQL injection testing and verification.
 *
 * @author yhawke (2013)
 */
public class SQLInjectionScanRule extends AbstractAppParamPlugin {

    private static final String SCANNER_MESSAGE_PREFIX = "sqliplugin.";
    private static final String ALERT_MESSAGE_PREFIX = SCANNER_MESSAGE_PREFIX + "alert.";

    // ------------------------------------------------------------------
    // Plugin Constants
    // ------------------------------------------------------------------
    // Coefficient used for a time-based query delay checking (must be >= 7)
    public static final int TIME_STDEV_COEFF = 7;
    // Standard deviation after which a warning message should be displayed about connection lags
    // original value was in seconds, but in java time is measured in milliseconds
    public static final double WARN_TIME_STDEV = 0.5 * 1000;
    // Minimum time response set needed for time-comparison based on standard deviation
    public static final int MIN_TIME_RESPONSES = 10;
    // Payload used for checking of existence of IDS/WAF (dummier the better)
    // IDS_WAF_CHECK_PAYLOAD = "AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM
    // information_schema.tables"

    // ------------------------------------------------------------------
    // Configuration properties
    // ------------------------------------------------------------------
    // --union-char=UCHAR  Character to use for bruteforcing number of columns
    private String unionChar = null;
    // --union-cols=UCOLS  Range of columns to test for UNION preparePrefix SQL injection
    private String unionCols = null;
    // --technique=TECH    SQL injection SQLI_TECHNIQUES to use (default "BEUSTQ")
    private List<Integer> techniques = null;
    // --risk=RISK         Risk of tests to perform (0-3, default 1)
    private int risk = 1;
    // --level=LEVEL       Level of tests to perform (1-5, default 1)
    private int level = 1;
    // --prefix=PREFIX     Injection payload prefix string
    private String prefix = null;
    // --suffix=SUFFIX     Injection payload suffix string
    private String suffix = null;
    // --invalid-bignum    Use big numbers for invalidating values
    private boolean invalidBignum = false;
    // --invalid-logical   Use logical operations for invalidating values
    private boolean invalidLogical = false;
    // --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)
    private int timeSec = 5;
    // --keep-alive Use persistent HTTP(s) connections
    // By default set connection behavior to close
    // to avoid troubles related to WAF or lagging
    // which can make things very slow...
    private boolean keepAlive = false;

    // ---------------------------------------------------------
    // Plugin internal properties
    // ---------------------------------------------------------
    // Logger instance
    private static final Logger log = Logger.getLogger(SQLInjectionScanRule.class);

    // Generic SQL error pattern (used for boolean based checks)
    private static final Pattern errorPattern =
            Pattern.compile("SQL (warning|error|syntax)", Pattern.CASE_INSENSITIVE);

    // Generic pattern for RandNum tag retrieval
    private static final Pattern randnumPattern = Pattern.compile("\\[RANDNUM(?:\\d+)?\\]");

    // Generic pattern for RandStr tag retrieval
    private static final Pattern randstrPattern = Pattern.compile("\\[RANDSTR(?:\\d+)?\\]");

    // Internal dynamic properties
    private final ResponseMatcher responseMatcher;
    private final List<Long> responseTimes;

    private int lastRequestUID;
    private int lastErrorPageUID;
    private long lastResponseTime;
    private int uColsStart;
    private int uColsStop;
    private DBMSHelper currentDbms;
    private String uChars;

    /**
     * Create an empty plugin for SQLinjection active testing. Should be called by each constructor
     * for initial parameter setting.
     */
    public SQLInjectionScanRule() {
        responseTimes = new ArrayList<>();
        responseMatcher = new ResponseMatcher();
        lastRequestUID = 0;
        lastErrorPageUID = -1;
    }

    /**
     * Get the unique identifier of this plugin
     *
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return 90018;
    }

    /**
     * Get the name of this plugin
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString(SCANNER_MESSAGE_PREFIX + "name");
    }

    /**
     * Get the description of the vulnerbaility when found
     *
     * @return the vulnerability description
     */
    @Override
    public String getDescription() {
        return Constant.messages.getString(ALERT_MESSAGE_PREFIX + "desc");
    }

    /**
     * Give back a general solution for the found vulnerability
     *
     * @return the solution that can be put in place
     */
    @Override
    public String getSolution() {
        return Constant.messages.getString(ALERT_MESSAGE_PREFIX + "soln");
    }

    /**
     * Reports all links and documentation which refers to this vulnerability
     *
     * @return a string based list of references
     */
    @Override
    public String getReference() {
        return Constant.messages.getString(ALERT_MESSAGE_PREFIX + "refs");
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Db)) {
            return true;
        }

        for (SQLiTest test : SQLiPayloadManager.getInstance().getTests()) {
            if (test.getDetails() == null) {
                continue;
            }

            for (DBMSHelper dbms : test.getDetails().getDbms()) {
                if (technologies.includes(dbms.getTech())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Give back the categorization of the vulnerability checked by this plugin (it's an injection
     * category for SQLi)
     *
     * @return a category from the Category enum list
     */
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    /**
     * Give back the CWE (Common Weakness Enumeration) id for the SQL Injection vulnerability as
     * described in http://cwe.mitre.org/data/definitions/89.html
     *
     * @return the official CWE id for SQLi
     */
    @Override
    public int getCweId() {
        return 89;
    }

    /**
     * Give back the WASC (Web Application Security Consortium) threat id for SQL Injection as
     * described in http://projects.webappsec.org/w/page/13246963/SQL%20Injection
     *
     * @return the official WASC id for SQLi
     */
    @Override
    public int getWascId() {
        return 19;
    }

    /**
     * Give back the risk associated to this vulnerability (high)
     *
     * @return the risk according to the Alert enum
     */
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    /**
     * Initialise the plugin according to general configuration settings. Note that this method gets
     * called each time the rule is called. TODO: set all parameters through interface plugin or a
     * configuration file e.g. prefixes/suffixes or forced DBMS, etc.
     */
    @Override
    public void init() {
        unionChar = null;
        unionCols = null;
        techniques = null;
        prefix = null;
        suffix = null;
        invalidBignum = false;
        invalidLogical = false;
        timeSec = 5;

        // Set level according to general plugin environment
        // --------------------------
        // 1: Always (<100 requests)
        // 2: Try a bit harder (100-200 requests)
        // 3: Good number of requests (200-500 requests)
        // 4: Extensive test (500-1000 requests)
        // 5: You have plenty of time (>1000 requests)
        switch (this.getAttackStrength()) {
            case LOW:
                level = 1;
                break;

            case MEDIUM:
                // Default setting
                level = 1;
                break;

            case HIGH:
                level = 2;
                break;

            case INSANE:
                level = 3;
                break;
        }

        // Set plugin risk constraint:
        // it's an active scan rule so set it to the safest one
        // --------------------------
        // 0: No risk
        // 1: Low risk
        // 2: Medium risk
        // 3: High risk
        risk = 1;
    }

    /**
     * Scans for SQL Injection vulnerabilities according to SQLMap payload definitions. Current
     * implemented tests are: Boolean-Based, Error-Based, Union-query, OrderBy-query, Stacked-Query
     * and Time-based. This plugin only test for the existence of a SQLi according to these
     * injection methods and exploit it generating less effects as possible. All revealed
     * vulnerabilities are then without false positives, and the detected payload could be used for
     * further attacks. After this detection we suggest to use exploiting tools like SQLmap itself
     * or SQLNinja, Havij, etc. for this vulnerability usage and control.
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param parameter the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String parameter, String value) {

        // First of all get the SQLi payloads list
        // using the embedded configuration file
        SQLiPayloadManager manager = SQLiPayloadManager.getInstance();

        // Internal engine variable definition
        HttpMessage origMsg;
        HttpMessage tempMsg;
        String currentPrefix;
        String currentSuffix;
        String currentComment;
        String payloadValue;
        String reqPayload;
        String cmpPayload;
        String content;
        String title;

        boolean injectable;
        int injectableTechniques = 0;

        // Maybe could be a good idea to sort tests
        // according to the behavior and the heaviness
        // TODO: define a compare logic and sort it according to that
        for (SQLiTest test : manager.getTests()) {

            title = test.getTitle();
            // unionExtended = false;

            // If it's a union based query test
            // first prepare all the needed elements
            if (test.getStype() == SQLiPayloadManager.TECHNIQUE_UNION) {

                // Set the string that need to be used
                // for the union query construction
                // ----------------------------------------------------
                if (title.contains("[CHAR]")) {
                    if (unionChar == null) {
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "skipping test '"
                                            + title
                                            + "' because the user didn't provide a custom charset");
                        }

                        continue;

                    } else {
                        title = title.replace("[CHAR]", unionChar);
                        if (StringUtils.isNumeric(unionChar)) {
                            uChars = unionChar;

                        } else {
                            // maybe the user set apics inside the chars string
                            uChars = "'" + StringUtils.strip(unionChar, "'") + "'";
                        }
                    }

                } else {
                    // Set union chars to the one specified
                    // inside the global payload definition
                    uChars = test.getRequest().getChars();
                }

                // Check if there's a random element to be set
                // ----------------------------------------------------
                if (title.contains("[RANDNUM]") || title.contains("(NULL)")) {
                    title = title.replace("[RANDNUM]", "random number");
                }

                // Set the union column range according to the specific
                // payload definition (custom based or constrained)
                // ----------------------------------------------------
                if (test.getRequest().getColumns().equals("[COLSTART]-[COLSTOP]")) {
                    if (unionCols == null) {
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "skipping test '"
                                            + title
                                            + "' because the user didn't provide a column range");
                        }

                        continue;

                    } else {
                        setUnionRange(unionCols);
                        title = title.replace("[COLSTART]", Integer.toString(uColsStart));
                        title = title.replace("[COLSTOP]", Integer.toString(uColsStop));
                    }

                } else {
                    // Set column range (the range set on the payload definition
                    // take precedence respect to the one set by the user)
                    setUnionRange(test.getRequest().getColumns());
                }

                /*
                // Seems useless (double the starting and ending column number value)
                match = re.search(r"(\d+)-(\d+)", test.request.columns)
                if injection.data and match:
                lower, upper = int(match.group(1)), int(match.group(2))
                for _ in (lower, upper):
                if _ > 1:
                unionExtended = True
                test.request.columns = re.sub(r"\b%d\b" % _, str(2 * _), test.request.columns)
                title = re.sub(r"\b%d\b" % _, str(2 * _), title)
                test.title = re.sub(r"\b%d\b" % _, str(2 * _), test.title)
                */
            }

            // Skip test if the user's wants to test only
            // for a specific technique
            if ((techniques != null) && !techniques.contains(test.getStype())) {
                if (log.isDebugEnabled()) {
                    StringBuilder message = new StringBuilder();
                    message.append("skipping test '");
                    message.append(title);
                    message.append("' because the user specified to test only for ");

                    for (int i : techniques) {
                        message.append(" & ");
                        message.append(SQLiPayloadManager.SQLI_TECHNIQUES.get(i));
                    }

                    message.append(" techniques");
                    log.debug(message);
                }

                continue;
            }

            // Skip test if it is the same SQL injection type already
            // identified by another test
            if ((injectableTechniques & (1 << test.getStype())) != 0) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "skipping test '"
                                    + title
                                    + "' because the payload for "
                                    + SQLiPayloadManager.SQLI_TECHNIQUES.get(test.getStype())
                                    + " has already been identified");
                }

                continue;
            }

            // Skip test if the risk is higher than the provided (or default) value
            // Parse test's <risk>
            if (test.getRisk() > risk) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "skipping test '"
                                    + title
                                    + "' because the risk ("
                                    + test.getRisk()
                                    + ") is higher than the provided ("
                                    + risk
                                    + ")");
                }

                continue;
            }

            // Skip test if the level is higher than the provided (or default) value
            // Parse test's <level>
            if (test.getLevel() > level) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "skipping test '"
                                    + title
                                    + "' because the level ("
                                    + test.getLevel()
                                    + ") is higher than the provided ("
                                    + level
                                    + ")");
                }

                continue;
            }

            // Skip DBMS-specific test if it does not match either the
            // previously identified or the user's provided DBMS (either
            // from program switch or from parsed error message(s))
            // ------------------------------------------------------------
            // Initially set the current Tech value to null
            currentDbms = null;

            if ((test.getDetails() != null) && !(test.getDetails().getDbms().isEmpty())) {

                // If the global techset hasn't been populated this
                // mean that all technologies should be scanned...
                if (getTechSet() == null) {
                    currentDbms = test.getDetails().getDbms().get(0);

                } else {
                    // Check if DBMS scope has been restricted
                    // using the Tech tab inside the scanner
                    // --------------------------
                    for (DBMSHelper dbms : test.getDetails().getDbms()) {

                        if (getTechSet().includes(dbms.getTech())) {
                            // Force back-end DBMS according to the current
                            // test value for proper payload unescaping
                            currentDbms = dbms;
                            break;
                        }
                    }
                }

                // Skip this test if the specific Dbms is not include
                // inside the list of the allowed one
                if (currentDbms == null) {
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "skipping test '"
                                        + title
                                        + "' because the db is not included in the Technology list");
                    }

                    continue;
                }

                /* Check if the KB knows what's the current DB
                * I escaped it because there's no user interaction and
                * all tests should be performed... to be verified if
                * there should exists a specific configuration for this
                *
                if len(Backend.getErrorParsedDBMSes()) > 0 and not intersect(dbms, Backend.getErrorParsedDBMSes()) and kb.skipOthersDbms is None:
                msg = "parsed error message(s) showed that the "
                msg += "back-end DBMS could be %s. " % Format.getErrorParsedDBMSes()
                msg += "Do you want to skip test payloads specific for other DBMSes? [Y/n]"

                if readInput(msg, default="Y") in ("y", "Y"):
                kb.skipOthersDbms = Backend.getErrorParsedDBMSes()
                else:
                kb.skipOthersDbms = []

                if kb.skipOthersDbms and not intersect(dbms, kb.skipOthersDbms):
                debugMsg = "skipping test '%s' because " % title
                debugMsg += "the parsed error message(s) showed "
                debugMsg += "that the back-end DBMS could be "
                debugMsg += "%s" % Format.getErrorParsedDBMSes()
                logger.debug(debugMsg)
                continue
                */
            }

            // Skip test if the user provided custom character
            if ((unionChar != null)
                    && (title.contains("random number") || title.contains("(NULL)"))) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "skipping test '"
                                    + title
                                    + "' because the user provided a specific character, "
                                    + unionChar);
                }

                continue;
            }

            // This check is suitable to the current configuration
            // Start logging the current execution (only in debugging)
            if (log.isDebugEnabled()) {
                log.debug("testing '" + title + "'");
            }

            // Parse test's <request>
            currentComment =
                    (manager.getBoundaries().size() > 1) ? test.getRequest().getComment() : null;

            // Start iterating through applicable boundaries
            for (SQLiBoundary boundary : manager.getBoundaries()) {

                // First set to false the injectable param
                injectable = false;

                // Skip boundary if the level is higher than the provided (or
                // default) value
                // Parse boundary's <level>
                if (boundary.getLevel() > level) {
                    continue;
                }

                // Skip boundary if it does not match against test's <clause>
                // Parse test's <clause> and boundary's <clause>
                if (!test.matchClause(boundary)) {
                    continue;
                }

                // Skip boundary if it does not match against test's <where>
                // Parse test's <where> and boundary's <where>
                if (!test.matchWhere(boundary)) {
                    continue;
                }

                // Parse boundary's <prefix>, <suffix>
                // Options --prefix/--suffix have a higher priority (if set by user)
                currentPrefix = (prefix == null) ? boundary.getPrefix() : prefix;
                currentSuffix = (suffix == null) ? boundary.getSuffix() : suffix;
                currentComment = (suffix == null) ? currentComment : null;

                // For each test's <where>
                for (int where : test.getWhere()) {

                    // Get the complete original message
                    // including previously retrieved content
                    // that could be considered trusted also after
                    // other plugins execution thanks to the removal
                    // of reflective values from the content...
                    // But if we decide to rerun sendAndReceive()
                    // each plugin execution, then we have to work
                    // with message copies and use getNewMsg()
                    origMsg = getBaseMsg();

                    // Threat the parameter original value according to the
                    // test's <where> tag
                    switch (where) {
                        case SQLiPayloadManager.WHERE_ORIGINAL:
                            payloadValue = value;
                            break;

                        case SQLiPayloadManager.WHERE_NEGATIVE:
                            // Use different page template than the original
                            // one as we are changing parameters value, which
                            // will likely result in a different content
                            if (invalidLogical) {
                                payloadValue =
                                        value
                                                + " AND "
                                                + SQLiPayloadManager.randomInt()
                                                + "="
                                                + SQLiPayloadManager.randomInt();

                            } else if (invalidBignum) {
                                payloadValue =
                                        SQLiPayloadManager.randomInt(6)
                                                + "."
                                                + SQLiPayloadManager.randomInt(1);

                            } else {
                                payloadValue = "-" + SQLiPayloadManager.randomInt();
                            }

                            // Launch again a simple payload with the changed value
                            // then take it as the original one for boolean base checkings
                            origMsg = sendPayload(parameter, payloadValue, true);
                            if (origMsg == null) {
                                // Probably a Circular Exception occurred
                                // exit the plugin
                                return;
                            }

                            break;

                        case SQLiPayloadManager.WHERE_REPLACE:
                            payloadValue = "";
                            break;

                        default:
                            // Act as original value need to be set
                            payloadValue = value;
                    }

                    // Hint from ZAP TestSQLInjection active plugin:
                    // Since the previous checks are attempting SQL injection,
                    // and may have actually succeeded in modifying the database (ask me how I
                    // know?!)
                    // then we cannot rely on the database contents being the same as when the
                    // original
                    // query was last run (could be hours ago)
                    // so re-run the query again now at this point.
                    // Here is the best place to do it...
                    // sendAndReceive(origMsg);

                    // Forge request payload by prepending with boundary's
                    // prefix and appending the boundary's suffix to the
                    // test's ' <payload><comment> ' string
                    reqPayload = prepareCleanPayload(test.getRequest().getPayload(), payloadValue);
                    reqPayload = preparePrefix(reqPayload, currentPrefix, where, test);
                    reqPayload = prepareSuffix(reqPayload, currentComment, currentSuffix, where);
                    // Now prefix the parameter value
                    reqPayload = payloadValue + reqPayload;

                    // Perform the test's request and check whether or not the
                    // payload was successful
                    // Parse test's <response>
                    if (test.getResponse() != null) {

                        // prepare string diff matcher
                        // cleaned by reflective values
                        // and according to the replacement
                        // logic set by the plugin
                        content = origMsg.getResponseBody().toString();
                        content = SQLiPayloadManager.removeReflectiveValues(content, payloadValue);
                        responseMatcher.setOriginalResponse(content);
                        responseMatcher.setLogic(where);

                        // -----------------------------------------------
                        // Check 1: Boolean-based blind SQL injection
                        // -----------------------------------------------
                        // use diffs ratio between true/false page content
                        // results against the original page or extract
                        // elements to check differences into
                        // -----------------------------------------------
                        if (test.getResponse().getComparison() != null) {

                            // Generate payload used for comparison
                            cmpPayload =
                                    prepareCleanPayload(
                                            test.getResponse().getComparison(), payloadValue);

                            // Forge response payload by prepending with
                            // boundary's prefix and appending the boundary's
                            // suffix to the test's ' <payload><comment> '
                            // string
                            cmpPayload = preparePrefix(cmpPayload, currentPrefix, where, test);
                            cmpPayload =
                                    prepareSuffix(cmpPayload, currentComment, currentSuffix, where);
                            // Now prefix the parameter value
                            cmpPayload = payloadValue + cmpPayload;

                            // Send False payload
                            // Useful to set first matchRatio on
                            // the False response content
                            tempMsg = sendPayload(parameter, cmpPayload, true);
                            if (tempMsg == null) {
                                // Probably a Circular Exception occurred
                                // exit the plugin
                                return;
                            }

                            content = tempMsg.getResponseBody().toString();
                            content =
                                    SQLiPayloadManager.removeReflectiveValues(content, cmpPayload);
                            responseMatcher.setInjectedResponse(content);
                            // set initial matchRatio
                            responseMatcher.isComparable();

                            // Perform the test's True request
                            tempMsg = sendPayload(parameter, reqPayload, true);
                            if (tempMsg == null) {
                                // Probably a Circular Exception occurred
                                // exit the plugin
                                return;
                            }

                            content = tempMsg.getResponseBody().toString();
                            content =
                                    SQLiPayloadManager.removeReflectiveValues(content, reqPayload);
                            responseMatcher.setInjectedResponse(content);

                            // Check if the TRUE response is equal or
                            // at less strongly comparable respect to
                            // the Original response value
                            if (responseMatcher.isComparable()) {

                                // Perform again the test's False request
                                tempMsg = sendPayload(parameter, cmpPayload, true);
                                if (tempMsg == null) {
                                    // Probably a Circular Exception occurred
                                    // exit the plugin
                                    return;
                                }

                                content = tempMsg.getResponseBody().toString();
                                content =
                                        SQLiPayloadManager.removeReflectiveValues(
                                                content, cmpPayload);
                                responseMatcher.setInjectedResponse(content);

                                // Now check if the FALSE response is
                                // completely different from the
                                // Original response according to the
                                // responseMatcher ratio criteria
                                if (!responseMatcher.isComparable()) {
                                    // We Found IT!
                                    // Now create the alert message
                                    String info =
                                            Constant.messages.getString(
                                                    ALERT_MESSAGE_PREFIX + "info.booleanbased",
                                                    reqPayload,
                                                    cmpPayload);

                                    // Do logging
                                    if (log.isDebugEnabled()) {
                                        log.debug(
                                                "[BOOLEAN-BASED Injection Found] "
                                                        + title
                                                        + " with payload ["
                                                        + reqPayload
                                                        + "] on parameter '"
                                                        + parameter
                                                        + "'");
                                    }

                                    // Alert the vulnerability to the main core
                                    raiseAlert(title, parameter, reqPayload, info, tempMsg);

                                    // Close the boundary/where iteration
                                    injectable = true;
                                }

                                /*
                                if not injectable and not any((conf.string, conf.notString, conf.regexp)) and kb.pageStable:
                                trueSet = set(extractTextTagContent(truePage))
                                falseSet = set(extractTextTagContent(falsePage))
                                candidates = filter(None, (_.strip() if _.strip() in (kb.pageTemplate or "") and _.strip() not in falsePage else None for _ in (trueSet - falseSet)))
                                if candidates:
                                conf.string = random.sample(candidates, 1)[0]
                                infoMsg = "%s parameter '%s' seems to be '%s' injectable (with --string=\"%s\")" % (place, parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                logger.info(infoMsg)
                                */
                            }

                            // -----------------------------------------------
                            // Check 2: Error-based SQL injection
                            // -----------------------------------------------
                            // try error based check sending a specific payload
                            // and verifying if it should return back inside
                            // the response content
                            // -----------------------------------------------
                        } else if (test.getResponse().getGrep() != null) {
                            // Perform the test's request and grep the response
                            // body for the test's <grep> regular expression
                            tempMsg = sendPayload(parameter, reqPayload, true);
                            if (tempMsg == null) {
                                // Probably a Circular Exception occurred
                                // exit the plugin
                                return;
                            }

                            // Get the payload that need to be checked
                            // inside the response content
                            String checkString =
                                    prepareCleanPayload(test.getResponse().getGrep(), payloadValue);
                            Pattern checkPattern =
                                    Pattern.compile(
                                            checkString, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
                            String output = null;

                            // Remove reflective values to avoid false positives
                            content = tempMsg.getResponseBody().toString();
                            content =
                                    SQLiPayloadManager.removeReflectiveValues(content, reqPayload);

                            // Find the checkString inside page and headers
                            Matcher matcher = checkPattern.matcher(content);
                            if (matcher.find()) {
                                output = matcher.group("result");

                            } else {
                                matcher =
                                        checkPattern.matcher(
                                                tempMsg.getResponseHeader().toString());
                                if (matcher.find()) {
                                    output = matcher.group("result");
                                }
                            }

                            // Useless because we follow redirects!!!
                            // --
                            // extractRegexResult(check, threadData.lastRedirectMsg[1] \
                            // if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == \
                            // threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

                            // Verify if the response extracted content
                            // contains the evaluated expression
                            // (which should be the value "1")
                            if ((output != null) && output.equals("1")) {
                                // We Found IT!
                                // Now create the alert message
                                String info =
                                        Constant.messages.getString(
                                                ALERT_MESSAGE_PREFIX + "info.errorbased",
                                                currentDbms.getName(),
                                                checkString);

                                // Do logging
                                if (log.isDebugEnabled()) {
                                    log.debug(
                                            "[ERROR-BASED Injection Found] "
                                                    + title
                                                    + " with payload ["
                                                    + reqPayload
                                                    + "] on parameter '"
                                                    + parameter
                                                    + "'");
                                }

                                raiseAlert(title, parameter, reqPayload, info, tempMsg);

                                // Close the boundary/where iteration
                                injectable = true;
                            }

                            // -----------------------------------------------
                            // Check 3: Time-based Blind or Stacked Queries
                            // -----------------------------------------------
                            // Check for the sleep() execution according to
                            // a collection of MIN_TIME_RESPONSES requestTime
                            // It uses deviations and average for the real
                            // delay checking.
                            // 99.9999999997440% of all non time-based SQL injection affected
                            // response times should be inside +-7*stdev([normal response times])
                            // Math reference: http://www.answers.com/topic/standard-deviation
                            // -----------------------------------------------
                        } else if (test.getResponse().getTime() != null) {
                            // First check if we have enough sample for the test
                            if (responseTimes.size() < MIN_TIME_RESPONSES) {
                                // We need some dummy requests to have a correct
                                // deviation model for this page
                                log.warn(
                                        "Time-based comparison needs larger statistical model: "
                                                + "making a few dummy requests");

                                do {
                                    tempMsg = sendPayload(null, null, true);
                                    if (tempMsg == null) {
                                        // Probably a Circular Exception occurred
                                        // exit the plugin
                                        return;
                                    }

                                } while (responseTimes.size() < MIN_TIME_RESPONSES);
                            }

                            // OK now we can get the deviation of the
                            // request computation time for this page
                            double lowerLimit = timeSec * 1000;
                            double deviation = getResponseTimeDeviation();

                            // Minimum response time that can be even considered as delayed
                            // MIN_VALID_DELAYED_RESPONSE = 0.5secs
                            // lowerLimit = Math.max(MIN_VALID_DELAYED_RESPONSE, lowerLimit);

                            // Get the maximum value to avoid false positives related
                            // to slow pages that can take an average time
                            // worse than the timeSec waiting period
                            if (deviation >= 0) {
                                lowerLimit =
                                        Math.max(
                                                lowerLimit,
                                                getResponseTimeAverage()
                                                        + TIME_STDEV_COEFF * deviation);
                            }

                            // Perform the test's request
                            reqPayload = setDelayValue(reqPayload);
                            tempMsg = sendPayload(parameter, reqPayload, false);
                            if (tempMsg == null) {
                                // Probably a Circular Exception occurred
                                // exit the plugin
                                return;
                            }

                            // Check if enough time has passed
                            if (lastResponseTime >= lowerLimit) {

                                // Confirm again test's results
                                tempMsg = sendPayload(parameter, reqPayload, false);
                                if (tempMsg == null) {
                                    // Probably a Circular Exception occurred
                                    // exit the plugin
                                    return;
                                }

                                // Check if enough time has passed
                                if (lastResponseTime >= lowerLimit) {
                                    // We Found IT!
                                    // Now create the alert message
                                    String info =
                                            Constant.messages.getString(
                                                    ALERT_MESSAGE_PREFIX + "info.timebased",
                                                    reqPayload,
                                                    lastResponseTime,
                                                    payloadValue,
                                                    getResponseTimeAverage());

                                    // Do logging
                                    if (log.isDebugEnabled()) {
                                        log.debug(
                                                "[TIME-BASED Injection Found] "
                                                        + title
                                                        + " with payload ["
                                                        + reqPayload
                                                        + "] on parameter '"
                                                        + parameter
                                                        + "'");
                                    }

                                    raiseAlert(title, parameter, reqPayload, info, tempMsg);

                                    // Close the boundary/where iteration
                                    injectable = true;
                                }
                            }

                            // -----------------------------------------------
                            // Check 4: UNION preparePrefix SQL injection
                            // -----------------------------------------------
                            // Test for UNION injection and set the sample
                            // payload as well as the vector.
                            // NOTE: vector is set to a tuple with 6 elements,
                            // used afterwards by Agent.forgeUnionQuery()
                            // method to forge the UNION preparePrefix payload
                            // -----------------------------------------------
                        } else if (test.getResponse().isUnion()) {

                            /*
                            if not Backend.getIdentifiedDbms():
                                warnMsg = "using unescaped version of the test "
                                warnMsg += "because of zero knowledge of the "
                                warnMsg += "back-end DBMS. You can try to "
                               warnMsg += "explicitly set it using option '--dbms'"
                               singleTimeWarnMessage(warnMsg)

                            if unionExtended:
                                infoMsg = "automatically extending ranges "
                                infoMsg += "for UNION query injection technique tests as "
                                infoMsg += "there is at least one other potential "
                                infoMsg += "injection technique found"
                                singleTimeLogMessage(infoMsg)
                            */

                            // Test for UNION query SQL injection
                            // use a specific engine containing
                            // all specific query constructors
                            SQLiUnionEngine engine = new SQLiUnionEngine(this);
                            engine.setTest(test);
                            engine.setUnionChars(uChars);
                            engine.setUnionColsStart(uColsStart);
                            engine.setUnionColsStop(uColsStop);
                            engine.setPrefix(currentPrefix);
                            engine.setSuffix(currentSuffix);
                            engine.setComment(currentComment);
                            engine.setDbms(currentDbms);
                            engine.setParamName(parameter);
                            engine.setParamValue(payloadValue);

                            // Use the engine to search for
                            // Union-based and OrderBy-based SQli
                            if (engine.isUnionPayloadExploitable()) {
                                // We Found IT!
                                // Now create the alert message
                                String info =
                                        Constant.messages.getString(
                                                ALERT_MESSAGE_PREFIX + "info.unionbased",
                                                currentDbms.getName(),
                                                engine.getExploitColumnsCount());

                                // Do logging
                                if (log.isDebugEnabled()) {
                                    log.debug(
                                            "[UNION-BASED Injection Found] "
                                                    + title
                                                    + " with payload ["
                                                    + reqPayload
                                                    + "] on parameter '"
                                                    + parameter
                                                    + "'");
                                }

                                // Alert the vulnerability to the main core
                                raiseAlert(
                                        title,
                                        parameter,
                                        engine.getExploitPayload(),
                                        info,
                                        engine.getExploitMessage());

                                // Close the boundary/where iteration
                                injectable = true;
                            }
                        }
                    }

                    // If the injection test was successful feed the injection
                    // object with the test's details
                    // if injection:
                    //  injection = checkFalsePositives(injection)
                    // if injection:
                    //  checkSuhoshinPatch(injection)

                    // There is no need to perform this test for other
                    // <where> tags
                    if (injectable) {
                        break;
                    }

                    // Check if the scan has been stopped
                    // if yes dispose resources and exit
                    if (isStop()) {
                        // Dispose all resources
                        // Exit the plugin
                        return;
                    }
                }

                // If injectable skip other boundary checks
                if (injectable) {
                    injectableTechniques |= 1 << test.getStype();
                    break;
                }
            }
        }

        // check if the parameter is not injectable
        if (injectableTechniques == 0 && log.isDebugEnabled()) {
            log.debug("Parameter '" + parameter + "' is not injectable");
        }
    }

    private void raiseAlert(
            String subTitle,
            String parameter,
            String payload,
            String otherInfo,
            HttpMessage message) {
        newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setName(Constant.messages.getString(ALERT_MESSAGE_PREFIX + "name", subTitle))
                .setParam(parameter)
                .setAttack(payload)
                .setOtherInfo(otherInfo)
                .setMessage(message)
                .raise();
    }

    /**
     * Launch the requested payload. If null values sent in paramName or payload launch again the
     * original message
     *
     * @param paramName
     * @param payload
     * @param recordResponseTime
     * @return
     */
    public HttpMessage sendPayload(String paramName, String payload, boolean recordResponseTime) {
        if (isStop()) {
            return null;
        }

        HttpMessage tempMsg;

        // Get the HTTP request
        if ((paramName != null) && (payload != null)) {
            tempMsg = getNewMsg();
            // --
            // TO BE IMPLEMENTED
            // Here we can tamper content for WAF evasion
            // a good idea could be to use a generic class
            // and instantiate one choosen SQLiTamper or more than one
            // who should set it? Acccording to SQLMap it's something
            // that depends by the pentester...
            // Maybe create a metalanguage for this?
            // At last it's only a find and replace schema
            // --

            // REMOVED - encoding should be done by Variants -
            // payload = AbstractPlugin.getURLEncode(payload);

            setParameter(tempMsg, paramName, payload);
            tempMsg.getRequestHeader()
                    .setHeader(
                            HttpHeader.CONNECTION,
                            keepAlive ? HttpHeader._KEEP_ALIVE : HttpHeader._CLOSE);

        } else {
            tempMsg = getBaseMsg();
        }

        // Get next page UID (incremental)
        lastRequestUID++;
        // Set initial time for request timing calculation
        lastResponseTime = System.currentTimeMillis();

        // Launch the requested query (followRedirect set to false?)
        try {
            sendAndReceive(tempMsg, true);
            lastResponseTime = System.currentTimeMillis() - lastResponseTime;

            // If debug is enabled log the entire request sent to the target
            if (log.isDebugEnabled()) {
                log.debug(
                        tempMsg.getRequestHeader().toString()
                                + "\n"
                                + tempMsg.getRequestBody().toString());
            }

            // generic SQL warning/error messages
            if (errorPattern.matcher(tempMsg.getResponseBody().toString()).find()) {
                lastErrorPageUID = lastRequestUID;
            }

        } catch (RedirectException | URIException e) {
            if (log.isDebugEnabled()) {
                StringBuilder strBuilder = new StringBuilder(150);
                strBuilder
                        .append("SQL Injection vulnerability check failed for parameter [")
                        .append(paramName)
                        .append("] and payload [")
                        .append(payload)
                        .append("] due to: ")
                        .append(e.getClass().getCanonicalName());
                log.debug(strBuilder.toString(), e);
            }
            return null;

        } catch (IOException ex) {
            // Ok we got an error, but take in care always the given response
            // Previously this could cause a deadlock because the requests
            // went in exception and the minimum amount of requests should never be reached
            lastResponseTime = System.currentTimeMillis() - lastResponseTime;

            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.warn(
                    "SQL Injection vulnerability check failed for parameter ["
                            + paramName
                            + "] and payload ["
                            + payload
                            + "] due to an I/O error",
                    ex);
        }

        // record the response time if needed
        if (recordResponseTime) {
            responseTimes.add(lastResponseTime);
        }

        return tempMsg;
    }

    /**
     * Returns True if the last web request resulted in a (recognized) DBMS error page
     *
     * @return true if the last request raised a DBMS explicit error
     */
    public boolean wasLastRequestDBMSError() {
        return (lastErrorPageUID == lastRequestUID);
    }

    // --------------------------------------------------------------------
    /**
     * Get page comparison against the original content
     *
     * @param pageContent the content that need to be compared
     * @return true if similar, false otherwise
     */
    protected boolean isComparableToOriginal(String pageContent) {
        responseMatcher.setInjectedResponse(pageContent);
        return responseMatcher.isComparable();
    }

    /**
     * Get the page comparison ration against the original content
     *
     * @param pageContent the content that need to be compared
     * @return a ratio value for this comparison
     */
    protected double compareToOriginal(String pageContent) {
        responseMatcher.setInjectedResponse(pageContent);
        return responseMatcher.getQuickRatio();
    }

    /**
     * Computes standard deviation of the responseTimes Reference:
     * http://www.goldb.org/corestats.html
     *
     * @return the current responseTimes deviation
     */
    private double getResponseTimeDeviation() {
        // Cannot calculate a deviation with less than
        // two response time values
        if (responseTimes.size() < 2) {
            return -1;
        }

        double avg = getResponseTimeAverage();
        double result = 0;
        for (long value : responseTimes) {
            result += Math.pow(value - avg, 2);
        }

        result = Math.sqrt(result / (responseTimes.size() - 1));

        // Check if there is too much deviation
        if (result > WARN_TIME_STDEV) {
            log.warn(
                    "There is considerable lagging "
                            + "in connection response(s) which gives a standard deviation of "
                            + result
                            + "ms on the sample set which is more than "
                            + WARN_TIME_STDEV
                            + "ms");
        }

        return result;
    }

    /**
     * Computes the arithmetic mean of the responseTimes
     *
     * @return the current responseTimes mean
     */
    private double getResponseTimeAverage() {
        double result = 0;
        for (long value : responseTimes) {
            result += value;
        }

        return result / responseTimes.size();
    }

    /**
     * Returns payload with a replaced late tags (e.g. SLEEPTIME)
     *
     * @param payload
     * @return
     */
    private String setDelayValue(String payload) {
        if (payload != null) {
            return payload.replace("[SLEEPTIME]", String.valueOf(timeSec));
        }

        return null;
    }

    /**
     * Prepare a clean attack payload setting all variables and customizing contents according to
     * the specific environment
     *
     * @param payload the payload that need to be prepared
     * @param paramValue the value that need to be set for the original parameter
     * @return a prepared payload that need to be prefixed and suffixed
     */
    private String prepareCleanPayload(String payload, String paramValue) {
        if (payload == null) {
            return null;
        }

        String result = payload.replace("[DELIMITER_START]", SQLiPayloadManager.charsStart);
        result = result.replace("[DELIMITER_STOP]", SQLiPayloadManager.charsStop);
        result = result.replace("[AT_REPLACE]", SQLiPayloadManager.charsAt);
        result = result.replace("[SPACE_REPLACE]", SQLiPayloadManager.charsSpace);
        result = result.replace("[DOLLAR_REPLACE]", SQLiPayloadManager.charsDollar);
        result = result.replace("[HASH_REPLACE]", SQLiPayloadManager.charsHash);

        // Set random integers
        // ------------------------
        Matcher matcher = randnumPattern.matcher(result);
        Set<String> elements = new HashSet<>();
        while (matcher.find()) {
            elements.add(matcher.group());
        }

        for (String el : elements) {
            result = result.replace(el, SQLiPayloadManager.randomInt());
        }

        // Set random strings
        // ------------------------
        matcher = randstrPattern.matcher(result);
        elements.clear();
        while (matcher.find()) {
            elements.add(matcher.group());
        }

        for (String el : elements) {
            result = result.replace(el, SQLiPayloadManager.randomString());
        }

        // Set original Value
        // ------------------------
        if (paramValue != null) {
            try {
                Integer.parseInt(paramValue);
                result = result.replace("[ORIGVALUE]", paramValue);

            } catch (NumberFormatException nfe) {
                result = result.replace("[ORIGVALUE]", "'" + paramValue + "'");
            }
        }

        // Inferenced payload seems used only to exploit
        // the vulnerability, not to test it.
        // So we skip this replacement
        // if (result.contains("[INFERENCE]")) {
        /*
        if Backend.getIdentifiedDbms() is not None:
        inference = queries[Backend.getIdentifiedDbms()].inference

        if "dbms_version" in inference:
        if isDBMSVersionAtLeast(inference.dbms_version):
        inferenceQuery = inference.query
        else:
        inferenceQuery = inference.query2
        else:
        inferenceQuery = inference.query

        payload = payload.replace("[INFERENCE]", inferenceQuery)
        else:
        errMsg = "invalid usage of inference payload without "
        errMsg += "knowledge of underlying DBMS"
        raise SqlmapNoneDataException, errMsg
        */
        // }

        return result;
    }

    /**
     * Prepare the Payload prepending the choosen prefix element according to the used injection
     * model
     *
     * @param payload
     * @param prefix
     * @param where
     * @param test
     * @return
     */
    protected String preparePrefix(String payload, String prefix, int where, SQLiTest test) {
        String prefixQuery;
        // payload = prepareCleanPayload(payload, null);
        if (currentDbms != null) {
            payload = currentDbms.encodeStrings(payload);
        }

        // If we are replacing (<where>) the parameter original value with
        // our payload do not prepend with the prefix
        if (where == SQLiPayloadManager.WHERE_REPLACE) {
            prefixQuery = "";

            // If the technique is stacked queries (<stype>) do not put a space
            // after the prefix or it is in GROUP BY / ORDER BY (<clause>)
        } else if (test.matchClauseList(new int[] {2, 3})) {
            prefixQuery = prefix;

            // In any other case prepend with the full prefix
        } else {
            prefixQuery = (prefix != null) ? prefix : "";

            if (payload.isEmpty() || (payload.charAt(0) != ';')) {
                prefixQuery += " ";
            }
        }

        return prepareCleanPayload(prefixQuery + payload, null);
    }

    /**
     * Prepare the payload attaching the suffix element according to the used injection scheme
     *
     * @param payload
     * @param comment
     * @param suffix
     * @param where
     * @return
     */
    protected String prepareSuffix(String payload, String comment, String suffix, int where) {

        // Set correct comment if it's revealed as an Access database
        if ((currentDbms == DBMSHelper.ACCESS) && DBMSHelper.GENERIC_SQL_COMMENT.equals(comment)) {
            comment = "%00";
        }

        if (comment != null) {
            payload += comment;
        }

        // If we are replacing (<where>) the parameter original value with
        // our payload do not append the suffix
        if (where == SQLiPayloadManager.WHERE_REPLACE) {
            // Do Nothing
        } else if ((suffix != null) && (comment == null)) {
            payload += suffix;
        }

        return prepareCleanPayload(payload.replaceAll("(?s);\\W*;", ";"), null);
    }

    /**
     * @param columns
     * @return
     */
    private void setUnionRange(String columns) {

        if (columns != null) {

            String[] values =
                    (columns.contains("-")) ? columns.split("-") : new String[] {columns, columns};
            this.uColsStart = Integer.parseInt(values[0]);
            this.uColsStop = Integer.parseInt(values[1]);

            if (uColsStart > uColsStop) {
                log.warn(
                        "Columns range has to be from lower to higher number of cols. "
                                + "Process will continue inverting the values from "
                                + values[1]
                                + " to "
                                + values[0]);

                int tmp = uColsStart;
                uColsStart = uColsStop;
                uColsStop = tmp;
            }
        }
    }

    /**
     * Set the character sequence to use for bruteforcing number of columns
     *
     * @param charSequence a sequence of characters
     */
    public void setUnionChar(String charSequence) {
        this.unionChar = charSequence;
    }

    /**
     * Set the range of columns to test for UNION preparePrefix SQL injection (using the form
     * [START]-[END])
     *
     * @param columnRange the range of columns that need to be iterated
     */
    public void setUnionCols(String columnRange) {
        this.unionCols = columnRange;
    }

    /**
     * Set the Risk of tests to perform (0-3, default 1)
     *
     * @param risk a risk value from 0 to 3 (0 means no risk, 3 high risk)
     */
    public void setRisk(int risk) {
        this.risk = risk;
    }

    /**
     * Set the Level of tests to perform (1-5, default 1):<br>
     * 1: Always (&lt;100 requests)<br>
     * 2: Try a bit harder (100-200 requests)<br>
     * 3: Good number of requests (200-500 requests)<br>
     * 4: Extensive test (500-1000 requests)<br>
     * 5: You have plenty of time (>1000 requests)<br>
     *
     * @param level a level value from 1 to 5
     */
    public void setLevel(int level) {
        this.level = level;
    }

    /**
     * Set the injection payload prefix string that will be put before each SQLi payload
     *
     * @param prefix the prefix string
     */
    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    /**
     * Set the injection payload suffix string that will be put at the end of each SQLi payload
     *
     * @param suffix
     */
    public void setSuffix(String suffix) {
        this.suffix = suffix;
    }

    /**
     * Use big numbers for invalidating values in place of the original parameter value (usually a
     * float based 6 digit value)
     *
     * @param invalidBignum set to true if you want to use a big number replacement
     */
    public void setInvalidBignum(boolean invalidBignum) {
        this.invalidBignum = invalidBignum;
    }

    /**
     * Use logical operations for invalidating values in place of the original parameter value (for
     * example ' AND 45=67')
     *
     * @param invalidLogical set to true if you want to use an invalid logical replacement
     */
    public void setInvalidLogical(boolean invalidLogical) {
        this.invalidLogical = invalidLogical;
    }

    /**
     * Set the Seconds to delay for the DBMS response in case of Time based SQLi (default 5 secs)
     *
     * @param seconds the number of seconds the system should wait for
     */
    public void setTimeSec(int seconds) {
        this.timeSec = seconds;
    }

    /**
     * Set the keepalive directive for all the HTTP Connections. Using it can optimize performances,
     * but can slow down everything if a WAF is in place
     *
     * @param keepAlive true if keep-alive directive should be used
     */
    public void setKeepAlive(boolean keepAlive) {
        this.keepAlive = keepAlive;
    }
}
