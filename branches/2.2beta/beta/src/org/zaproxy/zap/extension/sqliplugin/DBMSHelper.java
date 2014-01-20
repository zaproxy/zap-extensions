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

/**
 * DBMS's SQL dialect implementation and Service name aliases module.
 * You can use it to setup and use particular SQL particles
 * that are specific according to the SQL dialect implementation
 * (e.g. string concatenation, type casting and null verification),
 * or to detect the DB instance used by the application.
 * 
 * @author yhawke (2013)
 */
public enum DBMSHelper {
    MYSQL("MySQL", new String[]{"mysql", "my"}, 
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
    
    PGSQL("PostgreSQL", new String[]{"postgresql", "postgres", "pgsql", "psql", "pg"}, 
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
                builder.append((int)value.charAt(i));
                builder.append(')');
            }
            
            builder.append(')');
            return builder.toString();
        }
    },
            
    
    MSSQL("Microsoft SQL Server", new String[]{"microsoft sql server", "mssqlserver", "mssql", "ms"}, 
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

                chr = (int)value.charAt(i);
                builder.append((chr > 0xFF) ? "NCHAR(" : "CHAR(");
                builder.append(chr);
                builder.append(')');
            }
            
            return builder.toString();
        }        
    },
    
    ORACLE("Oracle", new String[]{"oracle", "orcl", "ora", "or"}, 
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

                chr = (int)value.charAt(i);
                builder.append((chr > 0xFF) ? "NCHR(" : "CHR(");
                builder.append(chr);
                builder.append(')');
            }
            
            return builder.toString();
        }        
    },
    
    SQLITE("SQLite", new String[]{"sqlite", "sqlite3"}, 
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
    
    ACCESS("Microsoft Access", new String[]{"msaccess", "access", "jet", "microsoft access"}, 
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
                builder.append((int)value.charAt(i));
                builder.append(')');
            }
            
            return builder.toString();
        }
    },
    
    FIREBIRD("Firebird", new String[]{"firebird", "mozilla firebird", "interbase", "ibase", "fb"}, 
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
                builder.append((int)value.charAt(i));
                builder.append(')');
            }
            
            return builder.toString();
        }        
    },
    
    MAXDB("SAP MaxDB", new String[]{"maxdb", "sap maxdb", "sap db"}, 
            ",", 
            "REPLACE(CHR({0}),''' ''','''_''')", 
            "VALUE({0},''' ''')", 
            " FROM VERSIONS") {
        
        @Override
        public String doEncode(String value) {
            return value;
        }        
    },
    
    SYBASE("Sybase", new String[]{"sybase", "sybase sql server"}, 
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
                
                chr = (int)value.charAt(i);
                builder.append((chr > 0xFF) ? "TO_UNICHAR(" : "CHAR(");
                builder.append(chr);
                builder.append(')');
            }
            
            return builder.toString();
        }            
    },
    
    DB2("IBM DB2", new String[]{"db2", "ibm db2", "ibmdb2"}, 
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
                builder.append((int)value.charAt(i));
                builder.append(')');
            }
            
            builder.append(')');
            return builder.toString();
        }
    },
                
    HSQLDB("HSQLDB", new String[]{"hsql", "hsqldb", "hs", "hypersql"}, 
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
                builder.append((int)value.charAt(i));
                builder.append(')');
            }
            
            return builder.toString();
        }
    };

    // ------------------------------------------------------------------
    
    private String name;
    private String[] aliases;
    private String delimiter;
    private String castQuery;
    private String isnullQuery;
    private String dummyTableFromQuery;

    /**
     * Enum inner constructor
     * 
     * @param name
     * @param aliases
     * @param delimiter
     * @param castQuery
     * @param isnullQuery
     * @param dummyTable 
     */
    private DBMSHelper(String name, String[] aliases, String delimiter, String castQuery, String isnullQuery, String dummyTable) {
        this.name = name;
        this.aliases = aliases;
        this.delimiter = delimiter;
        this.castQuery = castQuery;
        this.isnullQuery = isnullQuery;
        this.dummyTableFromQuery = dummyTable;
    }

    /**
     * Strings encoding method (depending by the DBMS specific).
     * It takes a SQL query containing strings and ecode them to
     * integers or specific SQL constructs so that no apics is
     * involved inside the request
     * 
     * @param payload the payload which strings need to be encoded
     * @return the encoded payload
     */
    public String encodeStrings(String payload) {
        StringBuilder builder = new StringBuilder();
        int eidx = 0;
        int sidx;

        while ((sidx = payload.indexOf('\'', eidx)) != -1) {
            builder.append(payload.substring(eidx, sidx));
            eidx = payload.indexOf('\'', ++sidx);
            if (eidx < 0) {
                // Unclosed ' literal, give back the original payload
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
     * Format a value with a Casted specific expression
     * depending by the DBMS implementation
     * 
     * @param value the value that need to be casted
     * @return the casted queried value
     */
    public String formatCast(String value) {
        return MessageFormat.format(castQuery, value);
    }

    /**
     * Format a value with an isNull specific expression
     * depending by the DBMS implementation
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
     * Get this DBMS name
     * 
     * @return the readable name of this DBMS 
     */
    public String getName() {
        return name;
    }
    
    // Generic SQL comment formation
    public static final String GENERIC_SQL_COMMENT = "-- ";

    /**
     * Get the correct DBMS Handler according to
     * a banner o string value with a given alias.
     * 
     * @param value
     * @return 
     */
    public static DBMSHelper getByName(String value) {
        for (DBMSHelper helper : DBMSHelper.values()) {
            if (ArrayUtils.contains(helper.aliases, value.toLowerCase()) || helper.name.equalsIgnoreCase(value)) {
                return helper;
            }
        }
        
        return null;
    }
}
