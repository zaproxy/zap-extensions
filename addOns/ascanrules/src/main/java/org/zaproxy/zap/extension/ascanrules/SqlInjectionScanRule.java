/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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

import java.io.IOException;
import java.net.SocketException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * TODO: implement stacked query check, since it is actually supported on more RDBMS drivers /
 * frameworks than not (MySQL on PHP/ASP does not by default, but can). PostgreSQL and MSSQL on ASP,
 * ASP.NET, and PHP *do* support it, for instance. It's better to put the code here and try it for
 * all RDBMSs as a result. Use the following variables: doStackedBased, doStackedMaxRequests,
 * countStackedBasedRequests TODO: change the Alert Titles. TODO: implement mode checks
 * (Mode.standard, Mode.safe, Mode.protected) for 2.* using "implements SessionChangedListener"
 *
 * <p>The SQLInjection scan rule identifies SQL Injection vulnerabilities. Note the ordering of
 * checks, for efficiency is : 1) Error based 2) Boolean Based 3) UNION based 4) Stacked (TODO:
 * implement stacked based) 5) Blind/Time Based (RDBMS specific, so not done here right now)
 *
 * @author 70pointer
 */
public class SqlInjectionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "ascanrules.sqlinjection.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_05_SQLI,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.API.getTag(), "");
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

    private boolean sqlInjectionFoundForUrl = false;

    private String sqlInjectionAttack = null;
    private HttpMessage refreshedmessage = null;

    private boolean doSpecificErrorBased = false;
    private boolean doGenericErrorBased = false;
    private boolean doBooleanBased = false;
    private boolean doUnionBased = false;
    private boolean doExpressionBased = false;
    private boolean doOrderByBased = false;

    private int doErrorMaxRequests = 0;
    private int doBooleanMaxRequests = 0;
    private int doUnionMaxRequests = 0;
    private int doExpressionMaxRequests = 0;
    private int doOrderByMaxRequests = 0;

    private int countErrorBasedRequests = 0;
    private int countExpressionBasedRequests = 0;
    private int countBooleanBasedRequests = 0;
    private int countOrderByBasedRequests = 0;

    /**
     * generic one-line comment. Various RDBMS Documentation suggests that this syntax works with
     * almost every single RDBMS considered here
     */
    public static final String SQL_ONE_LINE_COMMENT = " -- ";

    public static final String SQL_SINGLE_QUOTE = "'";

    /**
     * used to inject to check for SQL errors: some basic SQL metacharacters ordered so as to
     * maximise SQL errors Note that we do separate runs for each family of characters, in case one
     * family are filtered out, the others might still get past
     */
    static final String[] SQL_CHECK_ERR = {
        SQL_SINGLE_QUOTE, "\"", ";", "'(", ")", "(", "NULL", "'\""
    };

    /**
     * A collection of RDBMS with its error message fragments and {@code Tech}.
     *
     * <p>The error messages are in order they should be checked to allow the more (subjectively
     * judged) common cases to be tested first.
     *
     * <p><strong>Note:</strong> the messages should represent actual (driver level) error messages
     * for things like syntax error, otherwise we are simply guessing that the string should/might
     * occur.
     *
     * @see Tech
     */
    protected enum RDBMS {
        // TODO: add other specific UNION based error messages for Union here: PostgreSQL, Sybase,
        // DB2, Informix, etc

        MYSQL(
                "MySQL",
                Tech.MySQL,
                List.of(
                        "\\QYou have an error in your SQL syntax\\E",
                        "\\Qcom.mysql.jdbc.exceptions\\E",
                        "\\Qorg.gjt.mm.mysql\\E",
                        "\\QODBC driver does not support\\E",
                        "\\QThe used SELECT statements have a different number of columns\\E"),
                List.of(
                        "\\QYou have an error in your SQL syntax\\E",
                        "\\QThe used SELECT statements have a different number of columns\\E")),
        MSSQL(
                "Microsoft SQL Server",
                Tech.MsSQL,
                List.of(
                        "\\Qcom.microsoft.sqlserver.jdbc\\E",
                        "\\Qcom.microsoft.jdbc\\E",
                        "\\Qcom.inet.tds\\E",
                        "\\Qcom.ashna.jturbo\\E",
                        "\\Qweblogic.jdbc.mssqlserver\\E",
                        "\\Q[Microsoft]\\E",
                        "\\Q[SQLServer]\\E",
                        "\\Q[SQLServer 2000 Driver for JDBC]\\E",
                        // see also be Sybase. could be either!
                        "\\Qnet.sourceforge.jtds.jdbc\\E",
                        "\\Q80040e14\\E",
                        "\\Q800a0bcd\\E",
                        "\\Q80040e57\\E",
                        "\\QODBC driver does not support\\E",
                        "\\QAll queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists\\E",
                        "\\QAll queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists\\E"),
                List.of(
                        "\\QAll queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists\\E",
                        "\\QAll queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists\\E")),
        ORACLE(
                "Oracle",
                Tech.Oracle,
                List.of(
                        "\\Qoracle.jdbc\\E",
                        "\\QSQLSTATE[HY\\E",
                        "\\QORA-00933\\E",
                        "\\QORA-06512\\E", // indicates the line number of an error
                        "\\QSQL command not properly ended\\E",
                        "\\QORA-00942\\E", // table or view does not exist
                        "\\QORA-29257\\E", // host unknown
                        "\\QORA-00932\\E", // inconsistent datatypes
                        "\\Qquery block has incorrect number of result columns\\E",
                        "\\QORA-01789\\E"),
                List.of(
                        "\\Qquery block has incorrect number of result columns\\E",
                        "\\QORA-01789\\E")),
        DB2("IBM DB2", Tech.Db2, List.of("\\Qcom.ibm.db2.jcc\\E", "\\QCOM.ibm.db2.jdbc\\E")),
        POSTGRESQL(
                "PostgreSQL",
                Tech.PostgreSQL,
                List.of(
                        "\\Qorg.postgresql.util.PSQLException\\E",
                        "\\Qorg.postgresql\\E",
                        "\\Qeach UNION query must have the same number of columns\\E",
                        "\\Qunterminated quoted string at or near\\E",
                        "\\Qsyntax error at or near\\E"),
                List.of("\\Qeach UNION query must have the same number of columns\\E")),
        SYBASE(
                "Sybase",
                Tech.Sybase,
                List.of(
                        "\\Qcom.sybase.jdbc\\E",
                        // see also Microsoft SQL Server. could be either!
                        "\\Qnet.sourceforge.jtds.jdbc\\E")),
        INFORMIX("Informix", Tech.Db, List.of("\\Qcom.informix.jdbc\\E")),
        FIREBIRD("Firebird", Tech.Firebird, List.of("\\Qorg.firebirdsql.jdbc\\E")),
        IDSSERVER("IDS Server", Tech.Db, List.of("\\Qids.sql\\E")),
        INSTANTDB(
                "InstantDB",
                Tech.Db,
                List.of("\\Qorg.enhydra.instantdb.jdbc\\E", "\\Qjdbc.idb\\E")),
        INTERBASE("Interbase", Tech.Db, List.of("\\Qinterbase.interclient\\E")),
        HYPERSONIC(
                "Hypersonic SQL",
                Tech.HypersonicSQL,
                List.of(
                        "\\Qorg.hsql\\E",
                        "\\QhSql.\\E",
                        "\\QUnexpected token , requires FROM in statement\\E",
                        "\\QUnexpected end of command in statement\\E",
                        // TODO: too generic to leave in???
                        "\\QColumn count does not match in statement\\E",
                        // TODO: too generic to leave in???
                        "\\QTable not found in statement\\E",
                        // TODO: too generic to leave in???
                        // Works very nicely in Hypersonic cases, however
                        "\\QUnexpected token:\\E"),
                List.of(
                        // needs a table name in a UNION query. Like Oracle?
                        "\\QUnexpected end of command in statement\\E",
                        "\\QColumn count does not match in statement\\E")),
        SYBASE_ANY("Sybase SQL Anywhere", Tech.Sybase, List.of("\\Qsybase.jdbc.sqlanywhere\\E")),
        POINTBASE("Pointbase", Tech.Db, List.of("\\Qcom.pointbase.jdbc\\E")),
        CLOUDSCAPE(
                "Cloudscape",
                Tech.Db,
                List.of("\\Qdb2j.\\E", "\\QCOM.cloudscape\\E", "\\QRmiJdbc.RJDriver\\E")),
        INGRES("Ingres", Tech.Db, List.of("\\Qcom.ingres.jdbc\\E")),
        SQLITE(
                "SQLite",
                Tech.SQLite,
                List.of(
                        "near \".+\": syntax error", // uses a regular expression..
                        "SQLITE_ERROR",
                        "\\QSELECTs to the left and right of UNION do not have the same number of result columns\\E"),
                List.of(
                        "\\QSELECTs to the left and right of UNION do not have the same number of result columns\\E")),
        // generic error message fragments that do not fingerprint the RDBMS, but that may indicate
        // SQL Injection, nonetheless
        GENERIC(
                "Generic SQL RDBMS",
                Tech.Db,
                List.of(
                        "\\Qcom.ibatis.common.jdbc\\E",
                        "\\Qorg.hibernate\\E",
                        "\\Qsun.jdbc.odbc\\E",
                        "\\Q[ODBC Driver Manager]\\E",
                        "\\QODBC driver does not support\\E",
                        "\\QSystem.Data.OleDb\\E", // System.Data.OleDb.OleDbException
                        "\\Qjava.sql.SQLException\\E" // in case more specific messages were not
                        // detected!
                        ));

        private final String name;
        private final Tech tech;
        private final List<Pattern> errorPatterns;
        private final List<Pattern> unionErrorPatterns;

        private RDBMS(String name, Tech tech, List<String> errorRegexes) {
            this(name, tech, errorRegexes, List.of());
        }

        private RDBMS(
                String name, Tech tech, List<String> errorRegexes, List<String> unionErrorRegexes) {
            this.name = name;
            this.tech = tech;

            if (errorRegexes.isEmpty()) {
                errorPatterns = Collections.emptyList();
            } else {
                errorPatterns = new ArrayList<>(errorRegexes.size());
                for (String regex : errorRegexes) {
                    errorPatterns.add(Pattern.compile(regex, AbstractPlugin.PATTERN_PARAM));
                }
            }

            if (unionErrorRegexes.isEmpty()) {
                unionErrorPatterns = Collections.emptyList();
            } else {
                unionErrorPatterns = new ArrayList<>(unionErrorRegexes.size());
                for (String regex : unionErrorRegexes) {
                    unionErrorPatterns.add(Pattern.compile(regex, AbstractPlugin.PATTERN_PARAM));
                }
            }
        }

        public String getName() {
            return name;
        }

        public Tech getTech() {
            return tech;
        }

        public boolean isGeneric() {
            return this == GENERIC;
        }

        public List<Pattern> getErrorPatterns() {
            return errorPatterns;
        }

        public List<Pattern> getUnionErrorPatterns() {
            return unionErrorPatterns;
        }
    }

    static final String SQL_LIKE = "%";
    static final String SQL_LIKE_SAFE = "XYZABCDEFGHIJ";

    /**
     * always true statement for comparison in boolean based SQL injection check try the commented
     * versions first, because the law of averages says that the column being queried is more likely
     * *not* in the last where clause in a SQL query so as a result, the rest of the query needs to
     * be closed off with the comment.
     */
    static final String[] SQL_LOGIC_AND_TRUE = {
        " AND 1=1" + SQL_ONE_LINE_COMMENT,
        "' AND '1'='1'" + SQL_ONE_LINE_COMMENT,
        "\" AND \"1\"=\"1\"" + SQL_ONE_LINE_COMMENT,
        " AND 1=1",
        "' AND '1'='1",
        "\" AND \"1\"=\"1",
        SQL_LIKE, // attack for SQL LIKE statements
        SQL_LIKE + "' " + SQL_ONE_LINE_COMMENT, // attack for SQL LIKE statements
        SQL_LIKE + "\" " + SQL_ONE_LINE_COMMENT, // attack for SQL LIKE statements
    };

    /** always false statement for comparison in boolean based SQL injection check */
    static final String[] SQL_LOGIC_AND_FALSE = {
        " AND 1=2" + SQL_ONE_LINE_COMMENT,
        "' AND '1'='2'" + SQL_ONE_LINE_COMMENT,
        "\" AND \"1\"=\"2\"" + SQL_ONE_LINE_COMMENT,
        " AND 1=2",
        "' AND '1'='2",
        "\" AND \"1\"=\"2",
        SQL_LIKE_SAFE, // attack for SQL LIKE statements
        SQL_LIKE_SAFE + "' " + SQL_ONE_LINE_COMMENT, // attack for SQL LIKE statements
        SQL_LIKE_SAFE + "\" " + SQL_ONE_LINE_COMMENT, // attack for SQL LIKE statements
    };

    /**
     * always true statement for comparison if no output is returned from AND in boolean based SQL
     * injection check Note that, if necessary, the code also tries a variant with the one-line
     * comment " -- " appended to the end.
     */
    static final String[] SQL_LOGIC_OR_TRUE = {
        " OR 1=1" + SQL_ONE_LINE_COMMENT,
        "' OR '1'='1'" + SQL_ONE_LINE_COMMENT,
        "\" OR \"1\"=\"1\"" + SQL_ONE_LINE_COMMENT,
        " OR 1=1",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "%", // attack for SQL LIKE statements
        "%' " + SQL_ONE_LINE_COMMENT, // attack for SQL LIKE statements
        "%\" " + SQL_ONE_LINE_COMMENT, // attack for SQL LIKE statements
    };

    static final String SQL_UNION_SELECT = " UNION ALL select NULL";

    /**
     * generic UNION statements. Hoping these will cause a specific error message that we will
     * recognise
     */
    static String[] SQL_UNION_APPENDAGES = {
        SQL_UNION_SELECT + SQL_ONE_LINE_COMMENT,
        "'" + SQL_UNION_SELECT + SQL_ONE_LINE_COMMENT,
        "\"" + SQL_UNION_SELECT + SQL_ONE_LINE_COMMENT,
        ")" + SQL_UNION_SELECT + SQL_ONE_LINE_COMMENT,
        "')" + SQL_UNION_SELECT + SQL_ONE_LINE_COMMENT,
        "\")" + SQL_UNION_SELECT + SQL_ONE_LINE_COMMENT,
    };

    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionScanRule.class);

    private boolean debugEnabled = LOGGER.isDebugEnabled();

    @Override
    public int getId() {
        return 40018;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private static String getName(String rdbms) {
        return Constant.messages.getString(MESSAGE_PREFIX + "name.rdbms", rdbms);
    }

    /**
     * Returns true if the tech is a child of Tech.Db
     *
     * @param tech
     * @return true if the tech is a child of Tech.Db
     */
    private static boolean isDb(Tech tech) {
        Tech parent = tech.getParent();
        if (parent == null) {
            return false;
        }
        if (Tech.Db.equals(parent)) {
            return true;
        }
        return isDb(parent);
    }

    /**
     * Returns true if the tech is an SQL related tech. This method explicitly excludes known no-sql
     * techs, so will need to be updated with any new no-sql techs or we'll need to add SQL / NoSQL
     * structure.
     *
     * @param tech
     * @return true if the supplied tech is SQL related
     */
    private static boolean isSqlDb(Tech tech) {
        if (Tech.MongoDB.equals(tech) || Tech.CouchDB.equals(tech)) {
            return false;
        }
        return isDb(tech);
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Db)) {
            return true;
        }

        for (Tech tech : technologies.getIncludeTech()) {
            if (isSqlDb(tech)) {
                return true;
            }
        }
        return false;
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
    public void init() {
        LOGGER.debug("Initialising");

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == AttackStrength.LOW) {
            // do error based (if Threshold allows), and some expression based
            doErrorMaxRequests = 4;
            doExpressionBased = true;
            doExpressionMaxRequests = 4;
            doBooleanBased = false;
            doBooleanMaxRequests = 0;
            doUnionBased = false;
            doUnionMaxRequests = 0;
            doOrderByBased = false;
            doOrderByMaxRequests = 0;

        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            // do some more error based (if Threshold allows), some more expression based, some
            // boolean based, and some Union based
            doErrorMaxRequests = 8;
            doExpressionBased = true;
            doExpressionMaxRequests = 8;
            doBooleanBased = true;
            doBooleanMaxRequests = 6; // will not run all the LIKE attacks.. these are done at high
            doUnionBased = true;
            doUnionMaxRequests = 5;
            doOrderByBased = false;
            doOrderByMaxRequests = 0;

        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            // do some more error based (if Threshold allows), some more expression based, some more
            // boolean based, some union based, and some order by based
            doErrorMaxRequests = 16;
            doExpressionBased = true;
            doExpressionMaxRequests = 16;
            doBooleanBased = true;
            doBooleanMaxRequests = 20;
            doUnionBased = true;
            doUnionMaxRequests = 10;
            doOrderByBased = true;
            doOrderByMaxRequests = 5;

        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            // do some more error based (if Threshold allows), some more expression based, some more
            // boolean based, some more union based, and some more order by based
            doErrorMaxRequests = 100;
            doExpressionBased = true;
            doExpressionMaxRequests = 100;
            doBooleanBased = true;
            doBooleanMaxRequests = 100;
            doUnionBased = true;
            doUnionMaxRequests = 100;
            doOrderByBased = true;
            doOrderByMaxRequests = 100;
        }

        // if a high threshold is in place, turn off the error based, which are more prone to false
        // positives
        doSpecificErrorBased = true;
        doGenericErrorBased = true;

        if (this.getAlertThreshold() == AlertThreshold.MEDIUM) {
            doSpecificErrorBased = true;
            doGenericErrorBased = false;
        } else if (this.getAlertThreshold() == AlertThreshold.HIGH) {
            LOGGER.debug(
                    "Disabling the Error Based checking, since the Alert Threshold is set to High or Medium, and this type of check is notably prone to false positives");
            doSpecificErrorBased = false;
            doGenericErrorBased = false;
            doErrorMaxRequests = 0;
        }

        // Only check for generic errors if not targeting a specific DB
        doGenericErrorBased &= getTechSet().includes(Tech.Db);

        LOGGER.debug("Doing RDBMS specific error based? {}", doSpecificErrorBased);
        LOGGER.debug("Doing generic RDBMS error based? {}", doGenericErrorBased);
        LOGGER.debug("Using a max of {} requests", doErrorMaxRequests);
        LOGGER.debug("Doing expression based? {}", doExpressionBased);
        LOGGER.debug("Using a max of {} requests", doExpressionMaxRequests);
        LOGGER.debug("Using boolean based? {}", doBooleanBased);
        LOGGER.debug("Using a max of {} requests", doBooleanMaxRequests);
        LOGGER.debug("Doing UNION based? {}", doUnionBased);
        LOGGER.debug("Using a max of {} requests", doUnionMaxRequests);
        LOGGER.debug("Doing ORDER BY based? {}", doOrderByBased);
        LOGGER.debug("Using a max of {} requests", doOrderByMaxRequests);
    }

    @Override
    public void scan(HttpMessage msg, String param, String origParamValue) {
        // Note: the "value" we are passed here is escaped. we need to unescape it before handling
        // it.
        // as soon as we find a single SQL injection on the url, skip out. Do not look for SQL
        // injection on a subsequent parameter on the same URL
        // for performance reasons.
        // reinitialise each parameter.
        sqlInjectionFoundForUrl = false;
        sqlInjectionAttack = null;
        refreshedmessage = null;

        try {
            // reinitialise the count for each type of request, for each parameter.  We will be
            // sticking to limits defined in the attach strength logic
            countErrorBasedRequests = 0;
            countExpressionBasedRequests = 0;
            countBooleanBasedRequests = 0;
            countOrderByBasedRequests = 0;

            List<SqlInjectionTestCase> testCases =
                    List.of(
                            this::testErrorBasedSqlInjection,
                            this::testExpressionBasedSqlInjection,
                            this::testBooleanBasedSqlInjection,
                            this::testBooleanBasedNoDataSqlInjection,
                            this::testUnionBasedSqlInjection,
                            this::testOrderBySqlInjection);

            for (SqlInjectionTestCase testCase : testCases) {
                if (isStop() || sqlInjectionFoundForUrl) {
                    break;
                }
                testCase.run(param, origParamValue);
            }

            // if a sql injection was found, we should check if the page is flagged as a login page
            // in any of the contexts.  if it is, raise an "SQL Injection - Authentication Bypass"
            // alert in addition to the alerts already raised
            if (sqlInjectionFoundForUrl) {
                boolean loginUrl = false;

                // are we dealing with a login url in any of the contexts?
                ExtensionAuthentication extAuth =
                        (ExtensionAuthentication)
                                Control.getSingleton()
                                        .getExtensionLoader()
                                        .getExtension(ExtensionAuthentication.NAME);
                if (extAuth != null) {
                    URI requestUri = getBaseMsg().getRequestHeader().getURI();

                    // using the session, get the list of contexts for the url
                    List<Context> contextList =
                            extAuth.getModel()
                                    .getSession()
                                    .getContextsForUrl(requestUri.toString());

                    // now loop, and see if the url is a login url in each of the contexts in turn..
                    for (Context context : contextList) {
                        URI loginUri = extAuth.getLoginRequestURIForContext(context);
                        if (loginUri != null
                                && (requestUri.getScheme().equals(loginUri.getScheme())
                                        && requestUri.getHost().equals(loginUri.getHost())
                                        && requestUri.getPort() == loginUri.getPort()
                                        && requestUri.getPath().equals(loginUri.getPath()))) {
                            // we got this far.. only the method (GET/POST), user details, query
                            // params, fragment, and POST params
                            // are possibly different from the login page.
                            loginUrl = true;
                            break;
                        }
                    }
                }
                if (loginUrl) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setName(
                                    Constant.messages.getString(MESSAGE_PREFIX + "authbypass.name"))
                            .setDescription(
                                    Constant.messages.getString(MESSAGE_PREFIX + "authbypass.desc"))
                            .setUri(refreshedmessage.getRequestHeader().getURI().toString())
                            .setParam(param)
                            .setAttack(sqlInjectionAttack)
                            .setMessage(getBaseMsg())
                            .raise();
                }
            }

        } catch (Exception e) {
            LOGGER.warn("An error occurred checking a URL for SQL Injection vulnerabilities", e);
        }
    }

    @FunctionalInterface
    interface SqlInjectionTestCase {
        void run(String para, String origParamValue) throws IOException;
    }

    private void testErrorBasedSqlInjection(String param, String origParamValue)
            throws IOException {
        // Check 1: Check for Error Based SQL Injection (actual error messages).
        // for each SQL metacharacter combination to try
        for (int sqlErrorStringIndex = 0;
                sqlErrorStringIndex < SQL_CHECK_ERR.length
                        && !sqlInjectionFoundForUrl
                        && doSpecificErrorBased
                        && countErrorBasedRequests < doErrorMaxRequests;
                sqlErrorStringIndex++) {

            // work through the attack using each of the following strings as a prefix: the
            // empty string, and the original value
            // Note: this doubles the amount of work done by the scanner, but is necessary in
            // some cases
            String[] prefixStrings;
            if (origParamValue != null) {
                prefixStrings = new String[] {"", origParamValue};
            } else {
                prefixStrings = new String[] {""};
            }
            for (int prefixIndex = 0;
                    prefixIndex < prefixStrings.length && !sqlInjectionFoundForUrl;
                    prefixIndex++) {
                if (isStop()) {
                    return;
                }

                HttpMessage msg1 = getNewMsg();
                String sqlErrValue =
                        prefixStrings[prefixIndex] + SQL_CHECK_ERR[sqlErrorStringIndex];
                setParameter(msg1, param, sqlErrValue);

                // send the message with the modified parameters
                try {
                    sendAndReceive(msg1, false); // do not follow redirects
                } catch (SocketException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg1.getRequestHeader().getURI());
                    continue; // Continue to the next prefixString
                }
                countErrorBasedRequests++;

                if (msg1.getResponseHeader().getStatusCode() == 500
                        && this.getBaseMsg().getResponseHeader().getStatusCode() != 500) {
                    // Double check that the service doesn't respond with a 500 for all invalid
                    // values
                    HttpMessage msgSafe = getNewMsg();
                    setParameter(msgSafe, param, "S4feV4lu3");

                    try {
                        sendAndReceive(msgSafe, false);
                    } catch (SocketException ex) {
                        LOGGER.debug(
                                "Caught {} {} when accessing: {}",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                msgSafe.getRequestHeader().getURI());
                    }
                    if (msgSafe.isResponseFromTargetHost()
                            && msgSafe.getResponseHeader().getStatusCode() != 500) {
                        // Internal Server Error only when its an SQLi attack, a good enough
                        // indication in this case
                        sqlInjectionFoundForUrl = true;
                        sqlInjectionAttack = sqlErrValue;

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setName(getName())
                                .setParam(param)
                                .setAttack(sqlInjectionAttack)
                                .setEvidence(msg1.getResponseHeader().getPrimeHeader())
                                .setMessage(msg1)
                                .raise();
                        continue;
                    }
                }

                // now check the results against each pattern in turn, to try to identify a
                // database, or even better: a specific database.
                // Note: do NOT check the HTTP error code just yet, as the result could come
                // back with one of various codes.
                for (RDBMS rdbms : RDBMS.values()) {
                    if (isStop()) {
                        return;
                    }

                    if (getTechSet().includes(rdbms.getTech())
                            && checkSpecificErrors(rdbms, msg1, param, sqlErrValue)) {
                        sqlInjectionFoundForUrl = true;
                        // Save the attack string for the "Authentication Bypass" alert, if
                        // necessary
                        sqlInjectionAttack = sqlErrValue;
                        break;
                    }
                }

                if (this.doGenericErrorBased && !sqlInjectionFoundForUrl) {
                    Iterator<Pattern> errorPatternIterator =
                            RDBMS.GENERIC.getErrorPatterns().iterator();

                    while (errorPatternIterator.hasNext() && !sqlInjectionFoundForUrl) {
                        if (isStop()) {
                            return;
                        }

                        Pattern errorPattern = errorPatternIterator.next();
                        String errorPatternRDBMS = RDBMS.GENERIC.getName();

                        // if the "error message" occurs in the result of sending the modified
                        // query, but did NOT occur in the original result of the original query
                        // then we may have a SQL Injection vulnerability
                        StringBuilder sb = new StringBuilder();
                        if (!matchBodyPattern(getBaseMsg(), errorPattern, null)
                                && matchBodyPattern(msg1, errorPattern, sb)) {
                            String extraInfo =
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "alert.errorbased.extrainfo",
                                            errorPatternRDBMS,
                                            errorPattern.toString());
                            // raise the alert, and save the attack string for the
                            // "Authentication Bypass" alert, if necessary
                            sqlInjectionAttack = sqlErrValue;
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setName(getName(errorPatternRDBMS))
                                    .setParam(param)
                                    .setAttack(sqlInjectionAttack)
                                    .setOtherInfo(extraInfo)
                                    .setEvidence(sb.toString())
                                    .setMessage(msg1)
                                    .raise();

                            // log it, as the RDBMS may be useful to know later (in subsequent
                            // checks, when we need to determine RDBMS specific behaviour, for
                            // instance)
                            getKb().add(
                                            getBaseMsg().getRequestHeader().getURI(),
                                            "sql/" + errorPatternRDBMS,
                                            Boolean.TRUE);

                            sqlInjectionFoundForUrl = true;
                        }
                    }
                }
            }
        }
    }

    private void testExpressionBasedSqlInjection(String param, String origParamValue)
            throws IOException {
        // Check 4
        // New!  I haven't seen this technique documented anywhere else, but it's dead simple.
        // Let me explain.
        // See if the parameter value can simply be changed to one that *evaluates* to be the
        // same value,
        // if evaluated on a database
        // the simple check is to see if parameter "1" gives the same results as for param
        // "2-1", and different results for param "2-2"
        // for now, we try this for integer values only.
        // ###############################
        // Since the previous checks are attempting SQL injection, and may have actually
        // succeeded in modifying the database (ask me how I know?!)
        // then we cannot rely on the database contents being the same as when the original
        // query was last run (could be hours ago)
        // so to work around this, simply re-run the query again now at this point.
        // Note that we are not counting this request in our max number of requests to be issued
        refreshedmessage = getNewMsg();
        try {
            sendAndReceive(refreshedmessage, false); // do not follow redirects
        } catch (SocketException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    refreshedmessage.getRequestHeader().getURI());
            return;
        }

        ComparableResponse normalResponse =
                new ComparableResponse(refreshedmessage, origParamValue);

        if (!sqlInjectionFoundForUrl
                && doExpressionBased
                && countExpressionBasedRequests < doExpressionMaxRequests) {

            // first figure out the type of the parameter..
            try {
                // is it an integer type?
                int paramAsInt = Integer.parseInt(origParamValue);

                LOGGER.debug("The parameter value [{}] is of type Integer", origParamValue);
                // This check is implemented using two variant PLUS(+) and MULT(*)
                try {
                    // PLUS variant check the param value "3-2" gives same result as original
                    // request and param value "4-2" gives different result if original param
                    // value is 1
                    // set the parameter value to a string value like "3-2", if the original
                    // parameter value was "1"
                    int paramPlusTwo = Math.addExact(paramAsInt, 2);
                    String modifiedParamValueForAdd = String.valueOf(paramPlusTwo) + "-2";
                    // set the parameter value to a string value like "4-2", if the original
                    // parameter value was "1"
                    int paramPlusThree = Math.addExact(paramAsInt, 3);
                    String modifiedParamValueConfirmForAdd = String.valueOf(paramPlusThree) + "-2";
                    // Do the attack for ADD variant
                    expressionBasedAttack(
                            normalResponse,
                            param,
                            modifiedParamValueForAdd,
                            modifiedParamValueConfirmForAdd);
                    if (isStop()) {
                        return;
                    }
                    // MULT variant check the param value "2/2" gives same result as original
                    // request and param value "4/2" gives different result if original param
                    // value is 1
                    if (!sqlInjectionFoundForUrl
                            && countExpressionBasedRequests < doExpressionMaxRequests) {
                        // set the parameter value to a string value like "2/2", if the original
                        // parameter value was "1"
                        int paramMultTwo = Math.multiplyExact(paramAsInt, 2);
                        String modifiedParamValueForMult = String.valueOf(paramMultTwo) + "/2";
                        // set the parameter value to a string value like "4/2", if the original
                        // parameter value was "1"
                        int paramMultFour = Math.multiplyExact(paramAsInt, 4);
                        String modifiedParamValueConfirmForMult =
                                String.valueOf(paramMultFour) + "/2";
                        // Do the attack for MULT variant
                        expressionBasedAttack(
                                normalResponse,
                                param,
                                modifiedParamValueForMult,
                                modifiedParamValueConfirmForMult);
                        if (isStop()) {
                            return;
                        }
                    }
                } catch (ArithmeticException ex) {
                    LOGGER.debug(
                            "Caught {} {}. When performing integer math with the parameter value [{}]",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            origParamValue);
                }
            } catch (Exception e) {
                LOGGER.debug("The parameter value [{}] is NOT of type Integer", origParamValue);
                // TODO: implement a similar check for string types?  This probably needs to be
                // RDBMS specific (ie, it should not live in this scanner)
            }
        }
    }

    private void testBooleanBasedSqlInjection(String param, String origParamValue)
            throws IOException {
        // Check 2: boolean based checks.
        // the check goes like so:
        // append " and 1 = 1" to the param.  Send the query.  Check the results. Hopefully they
        // match the original results from the unmodified query,
        // *suggesting* (but not yet definitely) that we have successfully modified the query,
        // (hopefully not gotten an error message),
        // and have gotten the same results back, which is what you would expect if you added
        // the constraint " and 1 = 1" to most (but not every) SQL query.
        // So was it a fluke that we got the same results back from the modified query? Perhaps
        // the original query returned 0 rows, so adding any number of
        // constraints would change nothing?  It is still a possibility!
        // check to see if we can change the original parameter again to *restrict* the scope of
        // the query using an AND with an always false condition (AND_ERR)
        // (decreasing the results back to nothing), or to *broaden* the scope of the query
        // using an OR with an always true condition (AND_OR)
        // (increasing the results).
        // If we can successfully alter the results to our requirements, by one means or
        // another, we have found a SQL Injection vulnerability.
        // Some additional complications: assume there are 2 HTML parameters: username and
        // password, and the SQL constructed is like so:
        // select * from username where user = "$user" and password = "$password"
        // and lets assume we successfully know the type of the user field, via SQL_OR_TRUE
        // value '" OR "1"="1' (single quotes not part of the value)
        // we still have the problem that the actual SQL executed would look like so:
        // select * from username where user = "" OR "1"="1" and password = "whateveritis"
        // Since the password field is still taken into account (by virtue of the AND condition
        // on the password column), and we only inject one parameter at a time,
        // we are still not in control.
        // the solution is simple: add an end-of-line comment to the field added in (in this
        // example: the user field), so that the SQL becomes:
        // select * from username where user = "" OR "1"="1" -- and password = "whateveritis"
        // the result is that any additional constraints are commented out, and the last
        // condition to have any effect is the one whose
        // HTTP param we are manipulating.
        // Note also that because this comment only needs to be added to the "SQL_OR_TRUE" and
        // not to the equivalent SQL_AND_FALSE, because of the nature of the OR
        // and AND conditions in SQL.
        // Corollary: If a particular RDBMS does not offer the ability to comment out the
        // remainder of a line, we will not attempt to comment out anything in the query
        //            and we will simply hope that the *last* constraint in the SQL query is
        // constructed from a HTTP parameter under our control.

        LOGGER.debug(
                "Doing Check 2, since check 1 did not match for {}",
                getBaseMsg().getRequestHeader().getURI());

        // Since the previous checks are attempting SQL injection, and may have actually
        // succeeded in modifying the database (ask me how I know?!)
        // then we cannot rely on the database contents being the same as when the original
        // query was last run (could be hours ago)
        // so to work around this, simply re-run the query again now at this point.
        // Note that we are not counting this request in our max number of requests to be issued
        refreshedmessage = getNewMsg();
        try {
            sendAndReceive(refreshedmessage, false); // do not follow redirects
        } catch (SocketException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    refreshedmessage.getRequestHeader().getURI());
            return;
        }

        ComparableResponse normalResponse =
                new ComparableResponse(refreshedmessage, origParamValue);

        // try each of the AND syntax values in turn.
        // Which one is successful will depend on the column type of the table/view column into
        // which we are injecting the SQL.
        for (int i = 0;
                i < SQL_LOGIC_AND_TRUE.length
                        && !sqlInjectionFoundForUrl
                        && doBooleanBased
                        && countBooleanBasedRequests < doBooleanMaxRequests;
                i++) {
            if (isStop()) {
                return;
            }

            // needs a new message for each type of AND to be issued
            HttpMessage msg2 = getNewMsg();
            String sqlBooleanAndTrueValue = origParamValue + SQL_LOGIC_AND_TRUE[i];
            String sqlBooleanAndFalseValue = origParamValue + SQL_LOGIC_AND_FALSE[i];

            setParameter(msg2, param, sqlBooleanAndTrueValue);

            // send the AND with an additional TRUE statement tacked onto the end. Hopefully it
            // will return the same results as the original (to find a vulnerability)
            try {
                sendAndReceive(msg2, false); // do not follow redirects
            } catch (SocketException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg2.getRequestHeader().getURI());
                continue;
            }
            countBooleanBasedRequests++;

            ComparableResponse andTrueResponse =
                    new ComparableResponse(msg2, sqlBooleanAndTrueValue);

            if (isStop()) {
                return;
            }

            // if the results of the "AND 1=1" match the original query, we may be onto something.
            if (compareResponses(normalResponse, andTrueResponse) == 1) {
                LOGGER.debug(
                        "Check 2, response for AND TRUE condition [{}] matched (refreshed) original results for {}",
                        sqlBooleanAndTrueValue,
                        refreshedmessage.getRequestHeader().getURI());
                // so they match. Was it a fluke? See if we get the same result by tacking on "AND 1
                // = 2" to the original
                HttpMessage msg2AndFalse = getNewMsg();

                setParameter(msg2AndFalse, param, sqlBooleanAndFalseValue);

                try {
                    sendAndReceive(msg2AndFalse, false); // do not follow redirects
                } catch (SocketException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg2AndFalse.getRequestHeader().getURI());
                    continue;
                }
                countBooleanBasedRequests++;

                ComparableResponse andFalseResponse =
                        new ComparableResponse(msg2AndFalse, sqlBooleanAndFalseValue);

                if (compareResponses(normalResponse, andFalseResponse) < 1) {
                    LOGGER.debug(
                            "Check 2, response output for AND FALSE condition [{}] differed from (refreshed) original results for {}",
                            sqlBooleanAndFalseValue,
                            refreshedmessage.getRequestHeader().getURI());

                    // it's different (suggesting that the "AND 1 = 2" appended on gave
                    // different results because it restricted the data set to nothing
                    // Likely a SQL Injection. Raise it
                    // raise the alert, and save the attack string for the "Authentication
                    // Bypass" alert, if necessary
                    sqlInjectionAttack = sqlBooleanAndTrueValue;
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(sqlInjectionAttack)
                            .setOtherInfo(
                                    Constant.messages.getString(
                                                    MESSAGE_PREFIX + "alert.booleanbased.extrainfo",
                                                    sqlBooleanAndTrueValue,
                                                    sqlBooleanAndFalseValue,
                                                    "")
                                            + "\n"
                                            + Constant.messages.getString(
                                                    MESSAGE_PREFIX
                                                            + "alert.booleanbased.extrainfo.dataexists"))
                            .setMessage(msg2)
                            .raise();

                    sqlInjectionFoundForUrl = true;

                    break; // No further need to loop through SQL_AND

                } else {
                    // the results of the always false condition are the same as for the
                    // original unmodified parameter
                    // this could be because there was *no* data returned for the original
                    // unmodified parameter
                    // so consider the effect of adding comments to both the always true
                    // condition, and the always false condition
                    // the first value to try..
                    String orValue = origParamValue + SQL_LOGIC_OR_TRUE[i];

                    // this is where that comment comes in handy: if the RDBMS supports
                    // one-line comments, add one in to attempt to ensure that the
                    // condition becomes one that is effectively always true, returning ALL
                    // data (or as much as possible), allowing us to pinpoint the SQL
                    // Injection
                    LOGGER.debug(
                            "Check 2 , response for AND FALSE condition [{}] SAME as (refreshed) original results for {} ### (forcing OR TRUE check)",
                            sqlBooleanAndFalseValue,
                            refreshedmessage.getRequestHeader().getURI());
                    HttpMessage msg2OrTrue = getNewMsg();
                    setParameter(msg2OrTrue, param, orValue);
                    try {
                        sendAndReceive(msg2OrTrue, false); // do not follow redirects
                    } catch (SocketException ex) {
                        LOGGER.debug(
                                "Caught {} {} when accessing: {}",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                msg2OrTrue.getRequestHeader().getURI());
                        continue;
                    }
                    countBooleanBasedRequests++;

                    ComparableResponse orTrueResponse = new ComparableResponse(msg2OrTrue, orValue);

                    if (compareResponses(normalResponse, orTrueResponse) < 1) {
                        LOGGER.debug(
                                "Check 2, response for OR TRUE condition [{}] different to (refreshed) original results for {}",
                                orValue,
                                refreshedmessage.getRequestHeader().getURI());

                        // it's different (suggesting that the "OR 1 = 1" appended on gave
                        // different results because it broadened the data set from nothing
                        // to something
                        // raise the alert, and save the attack string for the
                        // "Authentication Bypass" alert, if necessary
                        sqlInjectionAttack = orValue;
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(param)
                                .setAttack(sqlInjectionAttack)
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                        MESSAGE_PREFIX
                                                                + "alert.booleanbased.extrainfo",
                                                        sqlBooleanAndTrueValue,
                                                        orValue,
                                                        "")
                                                + "\n"
                                                + Constant.messages.getString(
                                                        MESSAGE_PREFIX
                                                                + "alert.booleanbased.extrainfo.datanotexists"))
                                .setMessage(msg2)
                                .raise();

                        sqlInjectionFoundForUrl = true;
                        // booleanBasedSqlInjectionFoundForParam = true;  //causes us to
                        // skip past the other entries in SQL_AND.  Only one will expose a
                        // vuln for a given param, since the database column is of only 1
                        // type

                        break;
                    }
                }
            } // if the results of the "AND 1=1" match the original query, we may be onto
            // something.
            else {
                // the results of the "AND 1=1" do NOT match the original query, for
                // whatever reason (no sql injection, or the web page is not stable)
                if (this.debugEnabled) {
                    LOGGER.debug(
                            "Check 2, response for AND condition [{}] does NOT match the (refreshed) original results for {}",
                            sqlBooleanAndTrueValue,
                            refreshedmessage.getRequestHeader().getURI());
                }
            }
        }
    }

    private void testBooleanBasedNoDataSqlInjection(String param, String origParamValue)
            throws IOException {
        // check 2a: boolean based logic, where the original query returned *no* data. Here we
        // append " OR 1=1" in an attempt to extract *more* data
        // and then verify the results by attempting to reproduce the original results by
        // appending an " AND 1=2" condition (i.e. "open up first, then restrict to verify")
        // this differs from the previous logic based check since the previous check assumes
        // that the original query produced data, and tries first to restrict that data
        // (ie, it uses "restrict first, open up to verify" ).
        for (int i = 0;
                i < SQL_LOGIC_OR_TRUE.length
                        && !sqlInjectionFoundForUrl
                        && doBooleanBased
                        && countBooleanBasedRequests < doBooleanMaxRequests;
                i++) {
            if (isStop()) {
                return;
            }

            HttpMessage msg2 = getNewMsg();
            String sqlBooleanOrTrueValue = origParamValue + SQL_LOGIC_OR_TRUE[i];
            String sqlBooleanAndFalseValue = origParamValue + SQL_LOGIC_AND_FALSE[i];

            setParameter(msg2, param, sqlBooleanOrTrueValue);
            try {
                sendAndReceive(msg2, false); // do not follow redirects
            } catch (SocketException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg2.getRequestHeader().getURI());
                continue;
            }
            countBooleanBasedRequests++;

            String resBodyORTrueUnstripped = msg2.getResponseBody().toString();
            String mResBodyNormalUnstripped = refreshedmessage.getResponseBody().toString();
            String mResBodyNormalStripped = this.stripOff(mResBodyNormalUnstripped, origParamValue);

            // if the results of the "OR 1=1" exceed the original query (unstripped, by more
            // than a 20% size difference, say), we may be onto something.
            // TODO: change the percentage difference threshold based on the alert threshold
            if ((resBodyORTrueUnstripped.length() > (mResBodyNormalUnstripped.length() * 1.2))) {
                LOGGER.debug(
                        "Check 2a, unstripped html output for OR TRUE condition [{}] produced sufficiently larger results than the original message",
                        sqlBooleanOrTrueValue);
                // if we can also restrict it back to the original results by appending a " and
                // 1=2", then "Winner Winner, Chicken Dinner".
                HttpMessage msg2AndFalse = getNewMsg();
                setParameter(msg2AndFalse, param, sqlBooleanAndFalseValue);
                try {
                    sendAndReceive(msg2AndFalse, false); // do not follow redirects
                } catch (SocketException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg2AndFalse.getRequestHeader().getURI());
                    continue;
                }
                countBooleanBasedRequests++;

                String resBodyANDFalseUnstripped = msg2AndFalse.getResponseBody().toString();
                String resBodyANDFalseStripped =
                        stripOffOriginalAndAttackParam(
                                resBodyANDFalseUnstripped, origParamValue, sqlBooleanAndFalseValue);

                // does the "AND 1=2" version produce the same as the original (for
                // stripped/unstripped versions)
                boolean verificationUsingUnstripped =
                        resBodyANDFalseUnstripped.compareTo(mResBodyNormalUnstripped) == 0;
                boolean verificationUsingStripped =
                        resBodyANDFalseStripped.compareTo(mResBodyNormalStripped) == 0;
                if (verificationUsingUnstripped || verificationUsingStripped) {
                    LOGGER.debug(
                            "Check 2, {} html output for AND FALSE condition [{}] matches the (refreshed) original results",
                            (verificationUsingStripped ? "STRIPPED" : "UNSTRIPPED"),
                            sqlBooleanAndFalseValue);
                    // raise the alert, and save the attack string for the "Authentication
                    // Bypass" alert, if necessary
                    sqlInjectionAttack = sqlBooleanOrTrueValue;
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(sqlInjectionAttack)
                            .setOtherInfo(
                                    assembleBooleanBasedExtraInfo(
                                            sqlBooleanOrTrueValue,
                                            sqlBooleanAndFalseValue,
                                            verificationUsingStripped))
                            .setMessage(msg2)
                            .raise();

                    sqlInjectionFoundForUrl = true;

                    break;
                }
            }
        }
    }

    private static String assembleBooleanBasedExtraInfo(
            String sqlBooleanOrTrueValue,
            String sqlBooleanAndFalseValue,
            boolean verificationUsingStripped) {
        String extraInfo;
        if (verificationUsingStripped) {
            extraInfo =
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "alert.booleanbased.extrainfo",
                            sqlBooleanOrTrueValue,
                            sqlBooleanAndFalseValue,
                            "");
        } else {
            extraInfo =
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "alert.booleanbased.extrainfo",
                            sqlBooleanOrTrueValue,
                            sqlBooleanAndFalseValue,
                            "NOT ");
        }
        return extraInfo
                + "\n"
                + Constant.messages.getString(
                        MESSAGE_PREFIX + "alert.booleanbased.extrainfo.datanotexists");
    }

    private void testUnionBasedSqlInjection(String param, String origParamValue)
            throws IOException {
        // Check 3: UNION based
        // for each SQL UNION combination to try
        for (int sqlUnionStringIndex = 0, countUnionBasedRequests = 0;
                sqlUnionStringIndex < SQL_UNION_APPENDAGES.length
                        && !sqlInjectionFoundForUrl
                        && doUnionBased
                        && countUnionBasedRequests < doUnionMaxRequests;
                sqlUnionStringIndex++, countUnionBasedRequests++) {
            if (isStop()) {
                return;
            }

            HttpMessage msg3 = getNewMsg();
            String sqlUnionValue = origParamValue + SQL_UNION_APPENDAGES[sqlUnionStringIndex];
            setParameter(msg3, param, sqlUnionValue);
            try {
                sendAndReceive(msg3, false); // do not follow redirects
            } catch (SocketException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg3.getRequestHeader().getURI());
                continue;
            }

            String mResBodyNormalUnstripped = refreshedmessage.getResponseBody().toString();
            String mResBodyNormalStripped = this.stripOff(mResBodyNormalUnstripped, origParamValue);

            // now check the results.. look first for UNION specific error messages in the
            // output that were not there in the original output
            // and failing that, look for generic RDBMS specific error messages
            // TODO: maybe also try looking at a differentiation based approach?? Prone to false
            // positives though.
            for (RDBMS rdbms : RDBMS.values()) {
                if (isStop()) {
                    return;
                }

                if (getTechSet().includes(rdbms.getTech())
                        && checkUnionErrors(
                                rdbms,
                                msg3,
                                mResBodyNormalStripped,
                                refreshedmessage.getRequestHeader().getURI(),
                                param,
                                origParamValue,
                                sqlUnionValue)) {
                    sqlInjectionFoundForUrl = true;
                    // Save the attack string for the "Authentication Bypass" alert, if
                    // necessary
                    sqlInjectionAttack = sqlUnionValue;
                    break;
                }
            }
        }
    }

    private void testOrderBySqlInjection(String param, String origParamValue) throws IOException {
        // check for columns used in the "order by" clause of a SQL statement. earlier tests
        // will likely not catch these

        // append on " ASC -- " to the end of the original parameter. Grab the results.
        // if the results are different to the original (unmodified parameter) results, then
        // bale
        // if the results are the same as for the original parameter value, then the parameter
        // *might* be influencing the order by
        //	try again for "DESC": append on " DESC -- " to the end of the original parameter.
        // Grab the results.
        //	if the results are the same as the original (unmodified parameter) results, then bale
        //	(the results are not under our control, or there is no difference in the ordering,
        // for some reason: 0 or 1 rows only, or ordering
        //	by the first column alone is not sufficient to change the ordering of the data.)
        //	if the results were different to the original (unmodified parameter) results, then
        //		SQL injection!!

        // Since the previous checks are attempting SQL injection, and may have actually
        // succeeded in modifying the database (ask me how I know?!)
        // then we cannot rely on the database contents being the same as when the original
        // query was last run (could be hours ago)
        // so to work around this, simply re-run the query again now at this point.
        // Note that we are not counting this request in our max number of requests to be issued
        refreshedmessage = getNewMsg();
        try {
            sendAndReceive(refreshedmessage, false); // do not follow redirects
        } catch (SocketException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    refreshedmessage.getRequestHeader().getURI());
            return;
        }

        String mResBodyNormalUnstripped = refreshedmessage.getResponseBody().toString();
        String mResBodyNormalStripped = this.stripOff(mResBodyNormalUnstripped, origParamValue);

        if (!sqlInjectionFoundForUrl
                && doOrderByBased
                && countOrderByBasedRequests < doOrderByMaxRequests) {

            String modifiedParamValue = origParamValue + " ASC " + SQL_ONE_LINE_COMMENT;

            HttpMessage msg5 = getNewMsg();
            setParameter(msg5, param, modifiedParamValue);

            try {
                sendAndReceive(msg5, false); // do not follow redirects
            } catch (SocketException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg5.getRequestHeader().getURI());
                return;
            }
            countOrderByBasedRequests++;

            String modifiedAscendingOutputUnstripped = msg5.getResponseBody().toString();
            String modifiedAscendingOutputStripped =
                    stripOffOriginalAndAttackParam(
                            modifiedAscendingOutputUnstripped, origParamValue, modifiedParamValue);

            // set up two little arrays to ease the work of checking the unstripped output, and
            // then the stripped output
            String[] normalBodyOutput = {mResBodyNormalUnstripped, mResBodyNormalStripped};
            String[] ascendingBodyOutput = {
                modifiedAscendingOutputUnstripped, modifiedAscendingOutputStripped
            };
            boolean[] strippedOutput = {false, true};

            for (int booleanStrippedUnstrippedIndex = 0;
                    booleanStrippedUnstrippedIndex < 2;
                    booleanStrippedUnstrippedIndex++) {
                if (isStop()) {
                    return;
                }

                // if the results of the modified request match the original query, we may be
                // onto something.
                if (ascendingBodyOutput[booleanStrippedUnstrippedIndex].compareTo(
                                normalBodyOutput[booleanStrippedUnstrippedIndex])
                        == 0) {
                    LOGGER.debug(
                            "Check X, {} html output for modified Order By parameter [{}] matched (refreshed) original results for {}",
                            (strippedOutput[booleanStrippedUnstrippedIndex]
                                    ? "STRIPPED"
                                    : "UNSTRIPPED"),
                            modifiedParamValue,
                            refreshedmessage.getRequestHeader().getURI());
                    // confirm that a different parameter value generates different output, to
                    // minimise false positives

                    // use the descending order this time
                    String modifiedParamValueConfirm =
                            origParamValue + " DESC " + SQL_ONE_LINE_COMMENT;

                    HttpMessage msg5Confirm = getNewMsg();
                    setParameter(msg5Confirm, param, modifiedParamValueConfirm);

                    try {
                        sendAndReceive(msg5Confirm, false); // do not follow redirects
                    } catch (SocketException ex) {
                        LOGGER.debug(
                                "Caught {} {} when accessing: {}",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                msg5Confirm.getRequestHeader().getURI());
                        continue;
                    }
                    countOrderByBasedRequests++;

                    String confirmOrderByOutputUnstripped =
                            msg5Confirm.getResponseBody().toString();
                    String confirmOrderByOutputStripped =
                            stripOffOriginalAndAttackParam(
                                    confirmOrderByOutputUnstripped,
                                    origParamValue,
                                    modifiedParamValueConfirm);

                    // set up two little arrays to ease the work of checking the unstripped
                    // output or the stripped output
                    String[] confirmOrderByBodyOutput = {
                        confirmOrderByOutputUnstripped, confirmOrderByOutputStripped
                    };

                    if (confirmOrderByBodyOutput[booleanStrippedUnstrippedIndex].compareTo(
                                    normalBodyOutput[booleanStrippedUnstrippedIndex])
                            != 0) {
                        // the confirm query did not return the same results.  This means that
                        // arbitrary queries are not all producing the same page output.
                        // this means the fact we earlier reproduced the original page output
                        // with a modified parameter was not a coincidence

                        String extraInfo;
                        if (strippedOutput[booleanStrippedUnstrippedIndex]) {
                            extraInfo =
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "alert.orderbybased.extrainfo",
                                            modifiedParamValue,
                                            "");
                        } else {
                            extraInfo =
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "alert.orderbybased.extrainfo",
                                            modifiedParamValue,
                                            "NOT ");
                        }

                        // raise the alert, and save the attack string for the "Authentication
                        // Bypass" alert, if necessary
                        sqlInjectionAttack = modifiedParamValue;
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(param)
                                .setAttack(sqlInjectionAttack)
                                .setOtherInfo(extraInfo)
                                .setMessage(msg5)
                                .raise();

                        sqlInjectionFoundForUrl = true;
                        break;
                    }
                }
            }
        }
    }

    private boolean checkSpecificErrors(
            RDBMS rdbms, HttpMessage msg1, String parameter, String attack) {
        if (rdbms.isGeneric()) {
            return false;
        }

        for (Pattern errorPattern : rdbms.getErrorPatterns()) {
            if (isStop()) {
                return false;
            }

            // if the "error message" occurs in the result of sending the modified query, but did
            // NOT occur in the original result of the original query
            // then we may have a SQL Injection vulnerability
            StringBuilder sb = new StringBuilder();
            if (!matchBodyPattern(getBaseMsg(), errorPattern, null)
                    && matchBodyPattern(msg1, errorPattern, sb)) {

                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName(getName(rdbms.getName()))
                        .setParam(parameter)
                        .setAttack(attack)
                        .setOtherInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "alert.errorbased.extrainfo",
                                        rdbms.getName(),
                                        errorPattern.toString()))
                        .setEvidence(sb.toString())
                        .setMessage(msg1)
                        .raise();

                // log it, as the RDBMS may be useful to know later (in subsequent checks, when we
                // need to determine RDBMS specific behaviour, for instance)
                getKb().add(
                                getBaseMsg().getRequestHeader().getURI(),
                                "sql/" + rdbms.getName(),
                                Boolean.TRUE);

                return true;
            }
        }

        return false;
    }

    private boolean checkUnionErrors(
            RDBMS rdbms,
            HttpMessage msg,
            String response,
            URI uri,
            String parameter,
            String originalParam,
            String attack) {
        for (Pattern errorPattern : rdbms.getUnionErrorPatterns()) {
            if (isStop()) {
                return false;
            }

            // if the "error message" occurs in the result of sending the modified query, but did
            // NOT occur in the original result of the original query
            // then we may have a SQL Injection vulnerability
            String sqlUnionBodyUnstripped = msg.getResponseBody().toString();
            String sqlUnionBodyStripped =
                    stripOffOriginalAndAttackParam(sqlUnionBodyUnstripped, originalParam, attack);

            Matcher matcherOrig = errorPattern.matcher(response);
            Matcher matcherSQLUnion = errorPattern.matcher(sqlUnionBodyStripped);
            boolean patternInOrig = matcherOrig.find();
            boolean patternInSQLUnion = matcherSQLUnion.find();

            if (!patternInOrig && patternInSQLUnion) {
                // Likely a UNION Based SQL Injection (by error message). Raise it
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName(getName(rdbms.getName()))
                        .setUri(uri.getEscapedURI())
                        .setParam(parameter)
                        .setAttack(attack)
                        .setOtherInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "alert.unionbased.extrainfo",
                                        rdbms.getName(),
                                        errorPattern.toString()))
                        .setEvidence(matcherSQLUnion.group())
                        .setMessage(msg)
                        .raise();

                // log it, as the RDBMS may be useful to know later (in subsequent checks, when we
                // need to determine RDBMS specific behaviour, for instance)
                getKb().add(uri, "sql/" + rdbms.getName(), Boolean.TRUE);
                return true;
            }
        }

        return false;
    }

    private void expressionBasedAttack(
            ComparableResponse normalResponse,
            String param,
            String modifiedParamValue,
            String modifiedParamValueConfirm)
            throws IOException {
        // those of you still paying attention will note that if handled as expressions (such as by
        // a database), these represent the same value.
        HttpMessage msg = getNewMsg();
        setParameter(msg, param, modifiedParamValue);

        try {
            sendAndReceive(msg, false); // do not follow redirects
        } catch (SocketException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    msg.getRequestHeader().getURI());
            return;
        }
        countExpressionBasedRequests++;

        ComparableResponse modifiedExpressionResponse =
                new ComparableResponse(msg, modifiedParamValue);

        if (!sqlInjectionFoundForUrl && countExpressionBasedRequests < doExpressionMaxRequests) {
            // if the results of the modified request match the original query, we may be onto
            // something.

            if (compareResponses(normalResponse, modifiedExpressionResponse) == 1) {
                LOGGER.debug(
                        "Check 4, response for modified expression parameter [{}] matched (refreshed) original results for {}",
                        modifiedParamValue,
                        refreshedmessage.getRequestHeader().getURI());
                // confirm that a different parameter value generates different output, to minimise
                // false positives
                // this time param value will be different to original value and mismatch is
                // expected in responses of original and this value
                // Note that the two values are NOT equivalent, and the param value is different to
                // the original
                HttpMessage msgConfirm = getNewMsg();
                setParameter(msgConfirm, param, modifiedParamValueConfirm);

                try {
                    sendAndReceive(msgConfirm, false); // do not follow redirects
                } catch (SocketException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msgConfirm.getRequestHeader().getURI());
                    return;
                }
                countExpressionBasedRequests++;

                ComparableResponse confirmExpressionResponse =
                        new ComparableResponse(msgConfirm, modifiedParamValueConfirm);

                if (compareResponses(normalResponse, confirmExpressionResponse) < 1) {
                    // the confirm query did not return the same results.  This means that arbitrary
                    // queries are not all producing the same page output.
                    // this means the fact we earlier reproduced the original page output with a
                    // modified parameter was not a coincidence

                    // raise the alert, and save the attack string for the "Authentication Bypass"
                    // alert, if necessary
                    sqlInjectionAttack = modifiedParamValue;
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setAttack(sqlInjectionAttack)
                            .setOtherInfo(
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "alert.expressionbased.extrainfo",
                                            modifiedParamValue,
                                            ""))
                            .setMessage(msg)
                            .raise();
                    sqlInjectionFoundForUrl = true;
                    return;
                }
            }
            // bale out if we were asked nicely
            if (isStop()) {
                return;
            }
        }
    }

    // At this time the sqli tests just look for 0, 1, or anything in between, so the exact value
    // here doesn't matter. Anything between 0 and 1 works.
    private static final float HEURISTIC_WEIGHT = .99f;

    /**
     * 0 means very different and 1 very similar. Note that this is the opposite from most compareTo
     * implementations but it matches the behavior of the compareWith function and heuristics in
     * {@code ComparableResponse}
     */
    private float compareResponses(ComparableResponse one, ComparableResponse two) {
        float total = 1f;
        total *= locationHeaderHeuristic(one, two) * HEURISTIC_WEIGHT + (1 - HEURISTIC_WEIGHT);
        total *= responseBodyHeuristic(one, two) * HEURISTIC_WEIGHT + (1 - HEURISTIC_WEIGHT);
        return total;
    }

    /**
     * Checks the response bodies of two requests for an exact match after stripping off the input
     * parameters from both requests
     */
    private float responseBodyHeuristic(ComparableResponse one, ComparableResponse two) {
        String stripped1 =
                stripOffOriginalAndAttackParam(
                        one.getBody(), one.getValueSent(), two.getValueSent());
        String stripped2 =
                stripOffOriginalAndAttackParam(
                        two.getBody(), one.getValueSent(), two.getValueSent());
        if (stripped1.compareTo(stripped2) == 0) {
            return 1;
        }

        return 0;
    }

    private static float locationHeaderHeuristic(ComparableResponse one, ComparableResponse two) {
        if (one.getStatusCode() == two.getStatusCode()
                && HttpStatusCode.isRedirection(one.getStatusCode())) {
            if (!Objects.equals(
                    one.getHeaders().get(HttpHeader.LOCATION),
                    two.getHeaders().get(HttpHeader.LOCATION))) {
                return 0;
            }
        }

        return 1;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    /**
     * Replace body by stripping of pattern string. The URLencoded pattern will also be stripped
     * off. The URL decoded pattern will not be stripped off, as this is not necessary for our
     * purposes, and causes issues when attempting to decode parameter values such as '%' (a single
     * percent character) This is mainly used for stripping off a testing string in HTTP response
     * for comparison against the original response. Reference: TestInjectionSQL
     */
    @Override
    protected String stripOff(String body, String pattern) {
        if (pattern == null) {
            return body;
        }

        String urlEncodePattern = getURLEncode(pattern);
        String htmlEncodePattern1 = getHTMLEncode(pattern);
        String htmlEncodePattern2 = getHTMLEncode(urlEncodePattern);
        // escapeXml10 is favored over escapeXml11, since the relevant characters are already
        // addressed there
        String xhtmlEncodePattern = StringEscapeUtils.escapeXml10(pattern);
        String result =
                body.replaceAll("\\Q" + pattern + "\\E", "")
                        .replaceAll("\\Q" + urlEncodePattern + "\\E", "");
        result =
                result.replaceAll("\\Q" + htmlEncodePattern1 + "\\E", "")
                        .replaceAll("\\Q" + htmlEncodePattern2 + "\\E", "")
                        .replaceAll("\\Q" + xhtmlEncodePattern + "\\E", "");
        return result;
    }

    /**
     * Replace body by stripping off pattern strings.
     *
     * <p>Stripping both the originalPattern and attackPattern prevents false negatives when the
     * originalPattern is always part of the response.
     *
     * <p>For example: there is a website about cats and the response body is always "This is a page
     * about cats. You submitted {value}". If the originalPattern is "cats", the stripped response
     * is "This is a page about . You submitted ". When an attack payload is sent, such as "cats AND
     * 1=1" if only the attackPattern is stripped, the stripped response becomes "This is a page
     * about cats. You submitted ". So the original "cats" value needs to be stripped as well.
     */
    protected String stripOffOriginalAndAttackParam(
            String body, String originalPattern, String attackPattern) {
        return this.stripOff(this.stripOff(body, attackPattern), originalPattern);
    }

    /** Decode method that is aware of %, and will decode it as simply %, if it occurs */
    public static String getURLDecode(String msg) {
        String result = "";
        try {
            result = URLDecoder.decode(msg, "UTF8");

        } catch (Exception e) {
            // if it can't decode it, return the original string!
            return msg;
        }
        return result;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
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
    public TechSet getTechSet() {
        TechSet techSet = super.getTechSet();
        if (techSet != null) {
            return techSet;
        }
        return TechSet.getAllTech();
    }
}
