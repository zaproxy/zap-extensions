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
import org.jdom2.Element;

/**
 * Service class used to store a test element parsed from the XML payload configuration file
 *
 * @author yhawke (2013)
 */
class SQLiTest {

    /*
     * Tag: <test>
    SQL injection test definition.

    Sub-tag: <title>
        Title of the test.

    Sub-tag: <stype>
        SQL injection family type.

        Valid values:
            0: Heuristic check to parse response errors
            1: Boolean-based blind SQL injection
            2: Error-based queries SQL injection
            3: UNION query SQL injection
            4: Stacked queries SQL injection
            5: Time-based blind SQL injection
            6: Inline queries SQL injection

    Sub-tag: <level>
        From which level check for this test.

        Valid values:
            1: Always (<100 requests)
            2: Try a bit harder (100-200 requests)
            3: Good number of requests (200-500 requests)
            4: Extensive test (500-1000 requests)
            5: You have plenty of time (>1000 requests)

    Sub-tag: <risk>
        Likelihood of a payload to damage the data integrity.

        Valid values:
            0: No risk
            1: Low risk
            2: Medium risk
            3: High risk

    Sub-tag: <clause>
        In which clauses the payload can work.

        NOTE: for instance, there are some payload that do not have to be
        tested as soon as it has been identified whether or not the
        injection is within a WHERE clauses condition.

        Valid values:
            0: Always
            1: WHERE / HAVING
            2: GROUP BY
            3: ORDER BY
            4: LIMIT
            5: OFFSET
            6: TOP
            7: Table name
            8: Column name

        A comma separated list of these values is also possible.

    Sub-tag: <where>
        Where to add our '<prefix> <payload><comment> <suffix>' string.

        Valid values:
            1: Append the string to the parameter original value
            2: Replace the parameter original value with a negative random
               integer value and append our string
            3: Replace the parameter original value with our string

    Sub-tag: <vector>
        The payload that will be used to exploit the injection point.

    Sub-tag: <request>

    Sub-tag: <response>

    Sub-tag: <details>
     */
    private String title;
    private int stype;
    private int level;
    private int risk;
    private List<Integer> clauses;
    private List<Integer> where;
    private String vector;
    private SQLiTestRequest request;
    private SQLiTestResponse response;
    private SQLiTestDetails details;

    /** */
    public SQLiTest() {
        clauses = new ArrayList<>();
        where = new ArrayList<>();
        level = 0;
        stype = 0;
        risk = 0;
        title = "";
        vector = "";
        request = null;
        response = null;
        details = null;
    }

    /*
     * SQLMap Test list XML syntax
     * --------------------------------------------------------
     */
    private static final String TAG_TEST_TITLE = "title";
    private static final String TAG_TEST_STYPE = "stype";
    private static final String TAG_TEST_LEVEL = "level";
    private static final String TAG_TEST_RISK = "risk";
    private static final String TAG_TEST_CLAUSE = "clause";
    private static final String TAG_TEST_WHERE = "where";
    private static final String TAG_TEST_VECTOR = "vector";
    private static final String TAG_REQUEST = "request";
    private static final String TAG_RESPONSE = "response";
    private static final String TAG_DETAILS = "details";

    /** @param el */
    protected SQLiTest(Element el) {
        this();

        Element value = el.getChild(TAG_TEST_TITLE);
        if (value != null) {
            this.title = value.getText();
        }

        value = el.getChild(TAG_TEST_STYPE);
        if (value != null) {
            try {
                this.stype = Integer.parseInt(value.getText());

            } catch (NumberFormatException nfe) {
            }
        }

        value = el.getChild(TAG_TEST_LEVEL);
        if (value != null) {
            try {
                this.level = Integer.parseInt(value.getText());

            } catch (NumberFormatException nfe) {
            }
        }

        value = el.getChild(TAG_TEST_RISK);
        if (value != null) {
            try {
                this.risk = Integer.parseInt(value.getText());

            } catch (NumberFormatException nfe) {
            }
        }

        value = el.getChild(TAG_TEST_CLAUSE);
        if (value != null) {
            for (String tmp : value.getText().split(",")) {
                try {
                    clauses.add(Integer.parseInt(tmp));

                } catch (NumberFormatException nfe) {
                }
            }
        }

        value = el.getChild(TAG_TEST_WHERE);
        if (value != null) {
            for (String tmp : value.getText().split(",")) {
                try {
                    where.add(Integer.parseInt(tmp));

                } catch (NumberFormatException nfe) {
                }
            }
        }

        value = el.getChild(TAG_TEST_VECTOR);
        if (value != null) {
            this.vector = value.getText();
        }

        value = el.getChild(TAG_REQUEST);
        if (value != null) {
            this.request = new SQLiTestRequest(value);
        }

        value = el.getChild(TAG_RESPONSE);
        if (value != null) {
            this.response = new SQLiTestResponse(value);
        }

        value = el.getChild(TAG_DETAILS);
        if (value != null) {
            this.details = new SQLiTestDetails(value);
        }
    }

    /** @return */
    public int getLevel() {
        return level;
    }

    /**
     * @param clauseList
     * @return
     */
    public boolean matchClauseList(int[] clauseList) {
        if (clauseList.length < clauses.size()) {
            return false;
        }

        boolean result = true;
        int idx = 0;

        while (result && (idx < clauses.size())) {
            result = false;
            for (int j = 0; j < clauseList.length; j++) {
                if (clauses.get(idx) == clauseList[j]) {
                    result = true;
                    break;
                }
            }

            idx++;
        }

        return result;
    }

    /** @return */
    public boolean matchClause(SQLiBoundary boundary) {
        for (int testClause : clauses) {
            if ((testClause == 0) || boundary.matchClause(testClause)) {
                return true;
            }
        }

        return false;
    }

    /** @return */
    public boolean matchWhere(SQLiBoundary boundary) {
        for (int testWhere : where) {
            if (boundary.matchWhere(testWhere)) {
                return true;
            }
        }

        return false;
    }

    /** @return */
    public List<Integer> getWhere() {
        return where;
    }

    /** @return */
    public List<Integer> getClauseList() {
        return clauses;
    }

    /**
     * @param testWhere
     * @return
     */
    public boolean matchWhere(int testWhere) {
        return where.isEmpty() || where.contains(testWhere);
    }

    /** @return */
    public String getTitle() {
        return title;
    }

    /** @return */
    public int getStype() {
        return stype;
    }

    /** @return */
    public int getRisk() {
        return risk;
    }

    /** @return */
    public String getVector() {
        return vector;
    }

    /** @return */
    public SQLiTestRequest getRequest() {
        return request;
    }

    /** @return */
    public SQLiTestResponse getResponse() {
        return response;
    }

    /** @return */
    public SQLiTestDetails getDetails() {
        return details;
    }
}
