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
 * Service class used to store a boundary element parsed from the XML payload configuration file
 *
 * @author yhawke (2013)
 */
public class SQLiBoundary {

    private int level;
    private List<Integer> clause;
    private List<Integer> where;
    private int ptype;
    private String prefix;
    private String suffix;

    /** */
    public SQLiBoundary() {
        clause = new ArrayList<>();
        where = new ArrayList<>();
        level = 0;
        ptype = 0;
        prefix = "";
        suffix = "";
    }

    /*
     * SQLMap Test list XML syntax
     * --------------------------------------------------------
     */
    private static final String TAG_BOUNDARY_LEVEL = "level";
    private static final String TAG_BOUNDARY_CLAUSE = "clause";
    private static final String TAG_BOUNDARY_WHERE = "where";
    private static final String TAG_BOUNDARY_PTYPE = "ptype";
    private static final String TAG_BOUNDARY_PREFIX = "prefix";
    private static final String TAG_BOUNDARY_SUFFIX = "suffix";

    /**
     * Parse an XML boundary element according to the SQLmap Payload syntax:
     *
     * <p>Tag: <boundary> Sub-tag: <level> From which level check for this test.
     *
     * <p>Valid values: 1: Always (&lt;100 requests) 2: Try a bit harder (100-200 requests) 3: Good
     * number of requests (200-500 requests) 4: Extensive test (500-1000 requests) 5: You have
     * plenty of time (>1000 requests)
     *
     * <p>Sub-tag: <clause> In which clause the payload can work.
     *
     * <p>NOTE: for instance, there are some payload that do not have to be tested as soon as it has
     * been identified whether or not the injection is within a WHERE clause condition.
     *
     * <p>Valid values: 0: Always 1: WHERE / HAVING 2: GROUP BY 3: ORDER BY 4: LIMIT 5: OFFSET 6:
     * TOP 7: Table name 8: Column name
     *
     * <p>A comma separated list of these values is also possible.
     *
     * <p>Sub-tag: <where> Where to add our '<prefix> <payload><comment> <suffix>' string.
     *
     * <p>Valid values: 1: When the value of <test>'s <where> is 1. 2: When the value of <test>'s
     * <where> is 2. 3: When the value of <test>'s <where> is 3.
     *
     * <p>A comma separated list of these values is also possible.
     *
     * <p>Sub-tag: <ptype> What is the parameter value type.
     *
     * <p>Valid values: 1: Unescaped numeric 2: Single quoted string 3: LIKE single quoted string 4:
     * Double quoted string 5: LIKE double quoted string
     *
     * <p>Sub-tag: <prefix> A string to prepend to the payload.
     *
     * <p>Sub-tag: <suffix> A string to append to the payload.
     *
     * @param el
     */
    protected SQLiBoundary(Element el) {
        this();

        Element value = el.getChild(TAG_BOUNDARY_LEVEL);
        if (value != null) {
            try {
                this.level = Integer.parseInt(value.getText());

            } catch (NumberFormatException nfe) {
            }
        }

        value = el.getChild(TAG_BOUNDARY_CLAUSE);
        if (value != null) {
            for (String tmp : value.getText().split(",")) {
                try {
                    clause.add(Integer.parseInt(tmp));

                } catch (NumberFormatException nfe) {
                }
            }
        }

        value = el.getChild(TAG_BOUNDARY_WHERE);
        if (value != null) {
            for (String tmp : value.getText().split(",")) {
                try {
                    where.add(Integer.parseInt(tmp));

                } catch (NumberFormatException nfe) {
                }
            }
        }

        value = el.getChild(TAG_BOUNDARY_PTYPE);
        if (value != null) {
            try {
                this.ptype = Integer.parseInt(value.getText());

            } catch (NumberFormatException nfe) {
            }
        }

        value = el.getChild(TAG_BOUNDARY_PREFIX);
        if (value != null) {
            this.prefix = value.getText();
        }

        value = el.getChild(TAG_BOUNDARY_SUFFIX);
        if (value != null) {
            this.suffix = value.getText();
        }
    }

    /** @return */
    public int getLevel() {
        return level;
    }

    /**
     * @param testClause
     * @return
     */
    public boolean matchClause(int testClause) {
        return clause.isEmpty() || clause.contains(0) || clause.contains(testClause);
    }

    /**
     * @param testWhere
     * @return
     */
    public boolean matchWhere(int testWhere) {
        return where.isEmpty() || where.contains(testWhere);
    }

    /** @return */
    public int getPtype() {
        return ptype;
    }

    /** @return */
    public String getPrefix() {
        return prefix;
    }

    /** @return */
    public String getSuffix() {
        return suffix;
    }
}
