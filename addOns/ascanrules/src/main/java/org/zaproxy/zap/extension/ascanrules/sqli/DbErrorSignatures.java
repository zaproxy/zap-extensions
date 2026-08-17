/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules.sqli;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Centralized per-DBMS error-message signatures.
 *
 * <p>The generic SQL injection rule (id 40018) has an equivalent list, but it's a ~200 line inline
 * enum private to that one class -- nowhere else in the repo can reuse it. This is that data,
 * pulled out into its own standalone, independently testable class, with the same underlying
 * signatures (they're real driver/engine error strings, not guesses -- no reason to reinvent them)
 * but a deliberately smaller set of engines: the ones actually worth distinguishing rather than
 * every RDBMS 40018 has ever accumulated a signature for.
 */
public final class DbErrorSignatures {

    /** A database engine and the response fragments that indicate its error output. */
    public enum Dbms {
        MYSQL(
                Tech.MySQL,
                "MySQL",
                List.of(
                        "You have an error in your SQL syntax",
                        "com.mysql.jdbc.exceptions",
                        "org.gjt.mm.mysql",
                        "The used SELECT statements have a different number of columns"),
                List.of(
                        "You have an error in your SQL syntax",
                        "The used SELECT statements have a different number of columns")),
        MSSQL(
                Tech.MsSQL,
                "Microsoft SQL Server",
                List.of(
                        "com.microsoft.sqlserver.jdbc",
                        "com.microsoft.jdbc",
                        "[Microsoft][SQLServer",
                        "Unclosed quotation mark after the character string",
                        "All queries in an SQL statement containing a UNION operator must have an"
                                + " equal number of expressions in their target lists"),
                List.of(
                        "All queries in an SQL statement containing a UNION operator must have an"
                                + " equal number of expressions in their target lists",
                        "All queries combined using a UNION, INTERSECT or EXCEPT operator must have"
                                + " an equal number of expressions in their target lists")),
        ORACLE(
                Tech.Oracle,
                "Oracle",
                List.of(
                        "oracle.jdbc",
                        "ORA-00933",
                        "ORA-06512",
                        "ORA-00942",
                        "ORA-00932",
                        "SQL command not properly ended"),
                List.of(
                        "query block has incorrect number of result columns",
                        "ORA-01789")),
        POSTGRESQL(
                Tech.PostgreSQL,
                "PostgreSQL",
                List.of(
                        "org.postgresql.util.PSQLException",
                        "unterminated quoted string at or near",
                        "syntax error at or near",
                        "each UNION query must have the same number of columns"),
                List.of(
                        "each UNION query must have the same number of columns")),
        SQLITE(
                Tech.SQLite,
                "SQLite",
                List.of(
                        "SQLITE_ERROR",
                        "SELECTs to the left and right of UNION do not have the same number of"
                                + " result columns"),
                List.of(
                        "SELECTs to the left and right of UNION do not have the same number of"
                                + " result columns")),
        GENERIC(
                "Generic SQL RDBMS",
                List.of(
                        "java.sql.SQLException",
                        "org.hibernate",
                        "System.Data.OleDb",
                        "[ODBC Driver Manager]"));

        private final Optional<Tech> tech;
        private final String label;
        private final List<String> fragments;
        private final List<Pattern> patterns;
        private final List<String> unionFragments;
        private final List<Pattern> unionPatterns;

        Dbms(Tech tech, String label, List<String> literalFragments, List<String> unionFragments) {
            this.tech = Optional.of(tech);
            this.label = label;
            this.fragments = literalFragments;
            this.patterns = literalFragments.stream().map(DbErrorSignatures::literal).toList();
            this.unionFragments = unionFragments;
            this.unionPatterns = unionFragments.stream().map(DbErrorSignatures::literal).toList();
        }

        Dbms(String label, List<String> literalFragments) {
            this.tech = Optional.empty();
            this.label = label;
            this.fragments = literalFragments;
            this.patterns = literalFragments.stream().map(DbErrorSignatures::literal).toList();
            this.unionFragments = List.of();
            this.unionPatterns = List.of();
        }

        public String getLabel() {
            return label;
        }

        /** The tech constant for this engine, if any (GENERIC has none). */
        public Optional<Tech> getTech() {
            return tech;
        }

        /** UNION-specific error fragments for this engine. */
        public List<String> getUnionFragments() {
            return unionFragments;
        }

        /** Whether {@code text} contains any of this engine's error fragments. */
        public boolean matches(String text) {
            return findMatchedFragment(text).isPresent();
        }

        /** The first of this engine's error fragments found in {@code text}, if any. */
        public Optional<String> findMatchedFragment(String text) {
            if (text == null || text.isEmpty()) {
                return Optional.empty();
            }
            for (int i = 0; i < patterns.size(); i++) {
                if (patterns.get(i).matcher(text).find()) {
                    return Optional.of(fragments.get(i));
                }
            }
            return Optional.empty();
        }

        /** Whether {@code text} contains any of this engine's UNION-specific fragments. */
        public boolean matchesUnionFragment(String text) {
            if (text == null || text.isEmpty()) {
                return false;
            }
            for (Pattern pattern : unionPatterns) {
                if (pattern.matcher(text).find()) {
                    return true;
                }
            }
            return false;
        }
    }

    private DbErrorSignatures() {}

    private static Pattern literal(String fragment) {
        return Pattern.compile(Pattern.quote(fragment), Pattern.CASE_INSENSITIVE);
    }

    /**
     * Filters the list of database engines to only those whose Tech is in scope. GENERIC (which has
     * no Tech) is always included.
     *
     * @param scope the tech scope to filter by
     * @return list of engines whose Tech is in scope, or all if scope is null
     */
    public static List<Dbms> inTechScope(TechSet scope) {
        if (scope == null) {
            return List.of(Dbms.values());
        }
        List<Dbms> result = new ArrayList<>();
        for (Dbms dbms : Dbms.values()) {
            if (dbms.getTech().map(scope::includes).orElse(true)) {
                result.add(dbms);
            }
        }
        return result;
    }

    /**
     * Finds the first {@link Dbms} whose error signature appears in {@code responseBody}, checking
     * specific engines before the generic fallback so callers can report a precise engine when
     * possible.
     *
     * @param responseBody the response body to search
     * @return the matching engine, or empty if no signature matched
     */
    public static Optional<Dbms> identify(String responseBody) {
        for (Dbms dbms : Dbms.values()) {
            if (dbms.matches(responseBody)) {
                return Optional.of(dbms);
            }
        }
        return Optional.empty();
    }
}
