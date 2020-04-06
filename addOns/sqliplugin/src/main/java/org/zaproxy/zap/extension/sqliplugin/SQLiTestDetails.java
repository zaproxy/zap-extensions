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
 * Service class used to store test's platform details parsed from the XML payload configuration
 * file
 *
 * @author yhawke (2013)
 */
public class SQLiTestDetails {
    /*
       Which details can be infered if the payload succeed.

       Sub-tags: <dbms>
           What is the database management system (e.g. MySQL).

       Sub-tags: <dbms_version>
           What is the database management system version (e.g. 5.0.51).

       Sub-tags: <os>
           What is the database management system underlying operating
           system.
    */
    private List<DBMSHelper> dbms;
    private String dbmsVersion;
    private String os;

    /** */
    public SQLiTestDetails() {
        dbms = new ArrayList<>();
        dbmsVersion = null;
        os = null;
    }

    /*
     * SQLMap Test list XML syntax
     * --------------------------------------------------------
     */
    private static final String TAG_DETAILS_DBMS = "dbms";
    private static final String TAG_DETAILS_DBMS_VERSION = "dbms_version";
    private static final String TAG_DETAILS_OS = "os";

    /** @param el */
    protected SQLiTestDetails(Element el) {
        this();

        Element value = el.getChild(TAG_DETAILS_DBMS);
        if (value != null) {
            this.dbms.add(DBMSHelper.getByName(value.getText()));
        }

        value = el.getChild(TAG_DETAILS_DBMS_VERSION);
        if (value != null) {
            this.dbmsVersion = value.getText();
        }

        value = el.getChild(TAG_DETAILS_OS);
        if (value != null) {
            this.os = value.getText();
        }
    }

    /** @return */
    public List<DBMSHelper> getDbms() {
        return this.dbms;
    }

    /**
     * @param dbms
     * @return
     */
    public boolean matchDbms(DBMSHelper dbms) {
        return this.dbms.contains(dbms);
    }

    /** @return */
    public String getDbmsVersion() {
        return dbmsVersion;
    }

    /** @return */
    public String getOs() {
        return os;
    }
}
