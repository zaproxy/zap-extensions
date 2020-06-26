/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.utils.ContentMatcher;

public class ApplicationErrorScanRuleRegexMatcherUnitTest {
    private static final String INPUT_PREFIX = "<b>Some text before</b>";
    private static final String INPUT_SUFFIX = "<b>Some text after</b>";

    private static final String APP_ERRORS_FILE = "/xml/application_errors.xml";
    private static final ContentMatcher MATCHER =
            ContentMatcher.getInstance(
                    ApplicationErrorScanRuleRegexMatcherUnitTest.class.getResourceAsStream(
                            APP_ERRORS_FILE));

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Line 1024: Incorrect syntax near 'login'",
                "pg_query(): Query failed: ERROR: column \"tom\" does not exist LINE 2: SET name=tom",
                "'it's a text' is null or not an object",
                "ORA-30625: method dispatch on NULL SELF argument is disallowed\n"
                        + "Cause: A member method of a type is being invoked with a NULL SELF argument.\n"
                        + "Action: Change the method invocation to pass in a valid self argument.",
                "Microsoft JET Database Engine (0x12345678)<br>Syntax error (missing operator) in query expression "
                        + "'UserID ='.<br><b>/index.asp, line 51</b><br>",
                "<h2> <i>Syntax error (test) in query expression 'UserID ='.</i> </h2></span>",
                "<font face=\"Arial\" size=2>Syntax error (test) in query expression 'UserID ='.</font>",
                "PHP Warning:  pg_connect() [<a href='function.pg-connect'>function.pg-connect</a>]: "
                        + "Unable to connect to PostgreSQL server: could not connect to server: Connection refused",
                "System.Data.OleDb.OleDbException: Syntax error (missing operator) in query expression 'User ID = ? And Password = ?'",
                "System.Data.OleDb.OleDbException: Syntax error in string in query expression 'User ID = ? And Password = ?'",
                "<font style=\"COLOR: black; FONT: 8pt/11pt verdana\"> [Macromedia][SQLServer JDBC Driver][SQLServer]",
                "<font style=\"COLOR: black; FONT: 8pt/11pt verdana\"> Syntax error in string in query expression ",
                "The Error Occurred in <b>test: line42</b><br>",
                "The error occurred while processing an element (...) in the template: file X:\\XXX\\XXX.CFM. <br>.",
                "The error occurred while processing an element (...) in the template file <p>X:\\XXX\\XXX.CFM.</p><br>.",
                "<span><h1>Server Error in 'here some text' Application.<hr width=100% size=1 color=silver></h1>",
                "<title>Invalid file name for monitoring: 'c:\\xxx\\xxx'. File names for monitoring must have absolute paths, and no wildcards.</title>",
                "<b>warning</b>: some text in <b>some text</b> on line <b>1234</b><br />",
                "<b>fatal error</b>: some text in <b>some text</b> on line <b>1234</b><br />",
                "<b>parse error</b>: some text in <b>some text</b> on line <b>1234</b><br />",
                "Unknown database 'test'",
                "No database selected",
                "Table 'test' doesn't exist",
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'xxx' at line xxx",
                "Exception report.xxxmessage.xxxdescription.xxxexception.xxxnote.xxx",
                "<head><title>JRun Servlet Error</title></head>",
                "<h1>Servlet Error: test</h1>",
                "Servlet Error</title>"
            })
    public void shouldRegexMatchErrorMessage(String input) {
        assertNotNull(MATCHER.findInContent(INPUT_PREFIX + input + INPUT_SUFFIX));
    }
}
