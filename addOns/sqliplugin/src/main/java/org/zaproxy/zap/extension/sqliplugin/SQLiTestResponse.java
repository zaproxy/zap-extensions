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
 * Service class used to store test's response detection model parsed from the XML payload
 * configuration file
 *
 * @author yhawke (2013)
 */
public class SQLiTestResponse {

    /*
       How to identify if the injected payload succeeded.

       Sub-tag: <comparison>
           Perform a request with this string as the payload and compare
           the response with the <payload> response. Apply the comparison
           algorithm.

           NOTE: useful to test for boolean-based blind SQL injections.

       Sub-tag: <grep>
           Regular expression to grep for in the response body.

           NOTE: useful to test for error-based SQL injection.

       Sub-tag: <time>
           Time in seconds to wait before the response is returned.

           NOTE: useful to test for time-based blind and stacked queries
           SQL injections.

       Sub-tag: <union>
           Calls unionTest() function.

           NOTE: useful to test for UNION query (inband) SQL injection.

       Sub-tag: <oob>
           # TODO
    */
    private String comparison;
    private String time;
    private String grep;
    private boolean union;

    /** */
    public SQLiTestResponse() {
        comparison = null;
        time = null;
        grep = null;
        union = false;
    }

    /*
     * SQLMap Test list XML syntax
     * --------------------------------------------------------
     */
    private static final String TAG_RESPONSE_COMPARISON = "comparison";
    private static final String TAG_RESPONSE_GREP = "grep";
    private static final String TAG_RESPONSE_TIME = "time";
    private static final String TAG_RESPONSE_UNION = "union";

    /** @param el */
    protected SQLiTestResponse(Element el) {
        this();

        Element value = el.getChild(TAG_RESPONSE_COMPARISON);
        if (value != null) {
            this.comparison = value.getText();
        }

        value = el.getChild(TAG_RESPONSE_GREP);
        if (value != null) {
            this.grep = value.getText();
        }

        value = el.getChild(TAG_RESPONSE_TIME);
        if (value != null) {
            this.time = value.getText();
        }

        value = el.getChild(TAG_RESPONSE_UNION);
        this.union = (value != null);
    }

    public String getComparison() {
        return comparison;
    }

    public String getTime() {
        return time;
    }

    public String getGrep() {
        return grep;
    }

    public boolean isUnion() {
        return union;
    }
}
