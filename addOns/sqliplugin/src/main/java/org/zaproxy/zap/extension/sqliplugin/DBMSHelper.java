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
import java.io.UnsupportedEncodingException;
import java.text.MessageFormat;
import org.apache.commons.lang.ArrayUtils;
import org.zaproxy.zap.model.Tech;

/**
 * DBMS's SQL dialect implementation and Service name aliases module. You can use it to setup and
 * use particular SQL particles that are specific according to the SQL dialect implementation (e.g.
 * string concatenation, type casting and null verification), or to detect the DB instance used by
 * the application.
 *
 * @author yhawke (2013)
 */
public enum DBMSHelper {
    // ------------------------------------------------------------------
    // internal mapping for technologies currently not available on ZAP 2.4.0
    // should be reset to Tech list in the future
    // ------------------------------------------------------------------

    MYSQL(
            Tech.MySQL,
            new String[] {"mysql", "my"},
            ",",
            "CAST({0} AS CHAR)",
            "IFNULL({0},''' ''')",
            null) {

        @Override
        protected String doEncode(String value) {
            StringBuilder builder = new StringBuilder("0x");

            // first try with ASCII
            try {
                int c;
                for (int i = 0; i < value.length(); i++) {
                    c = value.charAt(i);
                    if (c > 0xFF) {
                        throw new IOException("Try to convert to hex using an UTF encoded string");
                    }
                    builder.append(Integer.toHexString(c));
                }

            } catch (IOException ex) {
                // then try utf8 encoding
                try {
                    byte[] encoded = value.getBytes("UTF-8");
                    builder = new StringBuilder("CONVERT(0x");
                    for (byte val : encoded) {
                        builder.append(Integer.toHexString(val & 0xFF));
                    }

                    builder.append(" USING utf8)");

                } catch (UnsupportedEncodingException ex1) {
                    return value;
                }
            }

            return builder.toString();
        }
    },

    PGSQL(
            Tech.PostgreSQL,
            new String[] {"postgresql", "postgres", "pgsql", "psql", "pg"},
            "||",
            "CAST({0} AS CHARACTER(10000))",
            "COALESCE({0},''' ''')",
            null) {

        @Override
        public String doEncode(String value) {
            // Note: PostgreSQL has a general problem with concenation operator (||) precedence
            // e.g. SELECT 1 WHERE 'a'!='a'||'b' will trigger error
            // ("argument of WHERE must be type boolean, not type text")
            StringBuilder builder = new StringBuilder("(");
            boolean isFirst = true;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                // Postgres CHR() function already accepts Unicode code point of character(s)
                builder.append("CHR(");
                builder.append((int) value.charAt(i));
                builder.append(')');
            }

            builder.append(')');
            return builder.toString();
        }
    },

    MSSQL(
            Tech.MsSQL,
            new String[] {"microsoft sql server", "mssqlserver", "mssql", "ms"},
            "+",
            "CAST({0} AS NVARCHAR(4000))",
            "ISNULL({0},''' ''')",
            null) {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder();
            boolean isFirst = true;
            int chr;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                chr = (int) value.charAt(i);
                builder.append((chr > 0xFF) ? "NCHAR(" : "CHAR(");
                builder.append(chr);
                builder.append(')');
            }

            return builder.toString();
        }
    },

    ORACLE(
            Tech.Oracle,
            new String[] {"oracle", "orcl", "ora", "or"},
            "||",
            "CAST({0} AS VARCHAR(4000))",
            "NVL({0},''' ''')",
            " FROM DUAL") {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder();
            boolean isFirst = true;
            int chr;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                chr = (int) value.charAt(i);
                builder.append((chr > 0xFF) ? "NCHR(" : "CHR(");
                builder.append(chr);
                builder.append(')');
            }

            return builder.toString();
        }
    },

    SQLITE(
            Tech.SQLite,
            new String[] {"sqlite", "sqlite3"},
            "||",
            "CAST({0} AS VARCHAR(8000))",
            "IFNULL({0},''' ''')",
            null) {

        @Override
        protected String doEncode(String value) {
            StringBuilder builder = new StringBuilder("X'");

            int chr;
            for (int i = 0; i < value.length(); i++) {
                chr = value.charAt(i) & 0xFF;
                builder.append(Integer.toHexString(chr));
            }

            builder.append('\'');
            return builder.toString();
        }
    },

    ACCESS(
            Tech.Access,
            new String[] {"msaccess", "access", "jet", "microsoft access"},
            "&",
            "CVAR({0})",
            "IIF(LEN({0})=0,''' ''',{0})",
            " FROM MSysAccessObjects") {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder();
            boolean isFirst = true;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                builder.append("CHR(");
                builder.append((int) value.charAt(i));
                builder.append(')');
            }

            return builder.toString();
        }
    },

    FIREBIRD(
            Tech.Firebird,
            new String[] {"firebird", "mozilla firebird", "interbase", "ibase", "fb"},
            "",
            "CAST({0} AS VARCHAR(10000))",
            "{0}",
            " FROM RDB$DATABASE") {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder();
            boolean isFirst = true;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append("||");
                }

                builder.append("ASCII_CHAR(");
                builder.append((int) value.charAt(i));
                builder.append(')');
            }

            return builder.toString();
        }
    },

    MAXDB(
            Tech.MaxDB,
            new String[] {"maxdb", "sap maxdb", "sap db"},
            ",",
            "REPLACE(CHR({0}),''' ''','''_''')",
            "VALUE({0},''' ''')",
            " FROM VERSIONS") {

        @Override
        public String doEncode(String value) {
            return value;
        }
    },

    SYBASE(
            Tech.Sybase,
            new String[] {"sybase", "sybase sql server"},
            "+",
            "CONVERT(NVARCHAR(4000),{0})",
            "ISNULL({0},''' ''')",
            null) {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder();
            boolean isFirst = true;
            int chr;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                chr = (int) value.charAt(i);
                builder.append((chr > 0xFF) ? "TO_UNICHAR(" : "CHAR(");
                builder.append(chr);
                builder.append(')');
            }

            return builder.toString();
        }
    },

    DB2(
            Tech.Db2,
            new String[] {"db2", "ibm db2", "ibmdb2"},
            "||",
            "RTRIM(CAST({0} AS CHAR(254)))",
            "COALESCE({0},''' ''')",
            " FROM SYSIBM.SYSDUMMY1") {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder("(");
            boolean isFirst = true;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                builder.append("CHR(");
                builder.append((int) value.charAt(i));
                builder.append(')');
            }

            builder.append(')');
            return builder.toString();
        }
    },

    HSQLDB(
            Tech.HypersonicSQL,
            new String[] {"hsql", "hsqldb", "hs", "hypersql"},
            "||",
            "CAST({0} AS LONGVARCHAR)",
            "IFNULL({0},''' ''')",
            " FROM INFORMATION_SCHEMA.SYSTEM_USERS") {

        @Override
        public String doEncode(String value) {
            StringBuilder builder = new StringBuilder();
            boolean isFirst = true;

            for (int i = 0; i < value.length(); i++) {
                if (isFirst) {
                    isFirst = false;

                } else {
                    builder.append(getDelimiter());
                }

                builder.append("CHAR(");
                builder.append((int) value.charAt(i));
                builder.append(')');
            }

            return builder.toString();
        }
    };

    // ------------------------------------------------------------------

    private final Tech tech;
    private final String[] aliases;
    private final String delimiter;
    private final String castQuery;
    private final String isnullQuery;
    private final String dummyTableFromQuery;

    /**
     * Enum inner constructor
     *
     * @param tech
     * @param aliases
     * @param delimiter
     * @param castQuery
     * @param isnullQuery
     * @param dummyTable
     */
    private DBMSHelper(
            Tech tech,
            String[] aliases,
            String delimiter,
            String castQuery,
            String isnullQuery,
            String dummyTable) {
        this.tech = tech;
        this.aliases = aliases;
        this.delimiter = delimiter;
        this.castQuery = castQuery;
        this.isnullQuery = isnullQuery;
        this.dummyTableFromQuery = dummyTable;
    }

    /**
     * Strings encoding method (depending by the DBMS specific). It takes a SQL query containing
     * strings and ecode them to integers or specific SQL constructs so that no apics is involved
     * inside the request
     *
     * @param payload the payload which strings need to be encoded
     * @return the encoded payload
     */
    public String encodeStrings(String payload) {
        StringBuilder builder = new StringBuilder();
        boolean noescape = false;
        int eidx = 0;
        int sidx;

        // for exclude in EXCLUDE_UNESCAPE:
        //    if exclude in payload:
        //        return payload
        // EXCLUDE_UNESCAPE = ("WAITFOR DELAY ", "CREATE ", " INTO DUMPFILE ", " INTO OUTFILE ",
        // "BULK ", "EXEC ", "RECONFIGURE ", "DECLARE ", "'%c'")

        while ((sidx = payload.indexOf('\'', eidx)) != -1) {
            builder.append(payload.substring(eidx, sidx));
            eidx = payload.indexOf('\'', ++sidx);
            if (eidx < 0) {
                // Unclosed ' literal, give back the original payload
                return payload;
            }

            // Check if the string should be encoded or left as it is
            if (eidx == sidx) {
                // OK it's a '' char so escaping should be skipped
                builder.append('\'');
                noescape = !noescape;
                eidx++;

                continue;
            }

            // Check if this is an unclosed '' literal, if so exit...
            if (noescape) {
                return payload;
            }

            builder.append(doEncode(payload.substring(sidx, eidx++)));
        }

        if (eidx < payload.length()) {
            builder.append(payload.substring(eidx));
        }

        return builder.toString();
    }

    /**
     * Inner encoding implementation (depends by DB)
     *
     * @param value the string value that need to be encoded
     * @return the encoded value
     */
    protected abstract String doEncode(String value);

    /**
     * Format a value with a Casted specific expression depending by the DBMS implementation
     *
     * @param value the value that need to be casted
     * @return the casted queried value
     */
    public String formatCast(String value) {
        return MessageFormat.format(castQuery, value);
    }

    /**
     * Format a value with an isNull specific expression depending by the DBMS implementation
     *
     * @param value the value that need to be isnulled
     * @return the isnulled queried value
     */
    public String formatIsNull(String value) {
        return MessageFormat.format(isnullQuery, value);
    }

    /**
     * Get the function delimiter specific for this DBMS
     *
     * @return the delimiter
     */
    public String getDelimiter() {
        return delimiter;
    }

    /**
     * Get a from SQL query inside a dummy table
     *
     * @return the from formatted query for a dummy table
     */
    public String getFromDummyTable() {
        return dummyTableFromQuery;
    }

    /**
     * Get this DBMS Tech object
     *
     * @return the Tech object associated with this DBMS
     */
    public Tech getTech() {
        return tech;
    }

    /**
     * Get this DBMS name
     *
     * @return the readable name of this DBMS
     */
    public String getName() {
        return tech.getName();
    }

    // Generic SQL comment formation
    public static final String GENERIC_SQL_COMMENT = "-- ";

    /**
     * Get the correct DBMS Handler according to a banner o string value with a given alias.
     *
     * @param value
     * @return
     */
    public static DBMSHelper getByName(String value) {
        for (DBMSHelper helper : DBMSHelper.values()) {
            if (helper.getName().equalsIgnoreCase(value)
                    || ArrayUtils.contains(helper.aliases, value.toLowerCase())) {
                return helper;
            }
        }

        return null;
    }
}
