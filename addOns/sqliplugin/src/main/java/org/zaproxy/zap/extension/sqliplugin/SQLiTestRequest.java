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

import org.jdom2.Element;

/**
 * Service class used to store test's abstract request payload, and any other elements useful to
 * build the attack string, parsed from the XML payload configuration file
 *
 * @author yhawke (2013)
 */
public class SQLiTestRequest {

    /*  What to inject for this test.

       Sub-tag: <payload>
           The payload to test for.

       Sub-tag: <comment>
           Comment to append to the payload, before the suffix.

       Sub-tag: <char>
           Character to use to bruteforce number of columns in UNION
           query SQL injection tests.

       Sub-tag: <columns>
           Range of columns to test for in UNION query SQL injection
           tests.
    */
    private String payload;
    private String comment;
    private String chars;
    private String columns;

    /** */
    public SQLiTestRequest() {
        payload = null;
        comment = null;
        chars = null;
        columns = null;
    }

    /*
     * SQLMap Test list XML syntax
     * --------------------------------------------------------
     */
    private static final String TAG_REQUEST_PAYLOAD = "payload";
    private static final String TAG_REQUEST_COMMENT = "comment";
    private static final String TAG_REQUEST_CHAR = "char";
    private static final String TAG_REQUEST_COLUMNS = "columns";

    /** @param value */
    protected SQLiTestRequest(Element el) {
        this();

        Element value = el.getChild(TAG_REQUEST_PAYLOAD);
        if (value != null) {
            this.payload = value.getText();
        }

        value = el.getChild(TAG_REQUEST_COMMENT);
        if (value != null) {
            this.comment = value.getText();
        }

        value = el.getChild(TAG_REQUEST_CHAR);
        if (value != null) {
            this.chars = value.getText();
        }

        value = el.getChild(TAG_REQUEST_COLUMNS);
        if (value != null) {
            this.columns = value.getText();
        }
    }

    public String getPayload() {
        return payload;
    }

    public String getComment() {
        return comment;
    }

    public String getChars() {
        return chars;
    }

    public String getColumns() {
        return columns;
    }
}
