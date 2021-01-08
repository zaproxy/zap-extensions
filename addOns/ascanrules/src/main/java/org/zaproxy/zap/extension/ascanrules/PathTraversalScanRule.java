/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/** a scanner that looks for Path Traversal vulnerabilities */
public class PathTraversalScanRule extends AbstractAppParamPlugin {

    /*
     * Prefix for internationalised messages used by this rule
     */
    private static final String MESSAGE_PREFIX = "ascanrules.pathtraversal.";

    private static final String NON_EXISTANT_FILENAME = "thishouldnotexistandhopefullyitwillnot";

    /*
     * Windows local file targets and detection pattern
     */
    private static final ContentsMatcher WIN_PATTERN =
            new PatternContentsMatcher(Pattern.compile("\\[drivers\\]"));
    private static final String[] WIN_LOCAL_FILE_TARGETS = {
        // Absolute Windows file retrieval (we suppose C:\\)
        "c:/Windows/system.ini",
        "../../../../../../../../../../../../../../../../Windows/system.ini",
        // Path traversal intended to obtain the filesystem's root
        "c:\\Windows\\system.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        "/../../../../../../../../../../../../../../../../Windows/system.ini",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        // "../../../../../../../../../../../../../../../../Windows/system.ini%00.html",
        // "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini%00.html",
        "Windows/system.ini",
        "Windows\\system.ini",
        // From Wikipedia (http://en.wikipedia.org/wiki/File_URI_scheme)
        // file://host/path
        // If host is omitted, it is taken to be "localhost", the machine from
        // which the URL is being interpreted. Note that when omitting host you
        // do not omit the slash
        "file:///c:/Windows/system.ini",
        "file:///c:\\Windows\\system.ini",
        "file:\\\\\\c:\\Windows\\system.ini",
        "file:\\\\\\c:/Windows/system.ini",
        // "fiLe:///c:\\Windows\\system.ini",
        // "FILE:///c:\\Windows\\system.ini",
        // "fiLe:///c:/Windows/system.ini",
        // "FILE:///c:/Windows/system.ini",
        // Absolute Windows file retrieval in case of D:\\ installation dir
        "d:\\Windows\\system.ini",
        "d:/Windows/system.ini",
        "file:///d:/Windows/system.ini",
        "file:///d:\\Windows\\system.ini",
        "file:\\\\\\d:\\Windows\\system.ini",
        "file:\\\\\\d:/Windows/system.ini"
        // "E:\\Windows\\system.ini",
        // "E:/Windows/system.ini",
        // "file:///E:\\Windows\\system.ini",
        // "file:///E:/Windows/system.ini",
        // "file:\\\\\\E:\\Windows\\system.ini",
        // "file:\\\\\\E:Windows/system.ini"
        // Other LFI ideas (for future expansions)
        // ..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../boot.ini
        /// %2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini
        // %25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..% 25%5c..%25%5c..%255cboot.ini
    };

    /*
     * Unix/Linux/etc. local file targets and detection pattern
     */
    // Dot used to match 'x' or '!' (used in AIX)
    private static final ContentsMatcher NIX_PATTERN =
            new PatternContentsMatcher(Pattern.compile("root:.:0:0"));
    private static final String[] NIX_LOCAL_FILE_TARGETS = {
        // Absolute file retrieval
        "/etc/passwd",
        // Path traversal intended to obtain the filesystem's root
        "../../../../../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../../../../../etc/passwd",
        // "../../../../../../../../../../../../../../../../etc/passwd%00.html",
        "etc/passwd",
        // From Wikipedia (http://en.wikipedia.org/wiki/File_URI_scheme)
        // file://host/path
        // If host is omitted, it is taken to be "localhost", the machine from
        // which the URL is being interpreted. Note that when omitting host you
        // do not omit the slash
        "file:///etc/passwd",
        "file:\\\\\\etc/passwd"
        // "fiLe:///etc/passwd",
        // "FILE:///etc/passwd",
        // Other LFI ideas (for future expansions)
        // "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd",
        // "../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd",
        // "../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd"
        // ..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
        // ..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00.jpg
        // ..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2500.jpg
    };

    /*
     * Windows/Unix/Linux/etc. local directory targets and detection pattern
     */
    private static final ContentsMatcher DIR_PATTERN = new DirNamesContentsMatcher();
    private static final String[] LOCAL_DIR_TARGETS = {
        "c:/",
        "/",
        "c:\\",
        "../../../../../../../../../../../../../../../../",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
        "/../../../../../../../../../../../../../../../../",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
        "file:///c:/",
        "file:///c:\\",
        "file:\\\\\\c:\\",
        "file:\\\\\\c:/",
        "file:///",
        "file:\\\\\\",
        "d:\\",
        "d:/",
        "file:///d:/",
        "file:///d:\\",
        "file:\\\\\\d:\\",
        "file:\\\\\\d:/"
    };

    private static final ContentsMatcher WAR_PATTERN =
            new PatternContentsMatcher(Pattern.compile("</web-app>"));

    /*
     * Standard local file prefixes
     */
    private static final String[] LOCAL_FILE_RELATIVE_PREFIXES = {"", "/", "\\"};

    /*
     * details of the vulnerability which we are attempting to find
     */
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_33");

    private static final Logger log = LogManager.getLogger(PathTraversalScanRule.class);

    @Override
    public int getId() {
        return 6;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }

        return "Failed to load vulnerability reference from file";
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        try {
            // figure out how aggressively we should test
            int nixCount = 0;
            int winCount = 0;
            int dirCount = 0;
            int localTraversalLength = 0;
            String extension = null;
            boolean includeNullByteInjectionPayload = false;
            // DEBUG only
            if (log.isDebugEnabled()) {
                log.debug("Attacking at Attack Strength: {}", this.getAttackStrength());
            }

            switch (this.getAttackStrength()) {
                case LOW:
                    // This works out as a total of 2+2+2+0*4+1 = 7 reqs / param
                    nixCount = 2;
                    winCount = 2;
                    dirCount = 2;
                    localTraversalLength = 0;
                    break;

                case MEDIUM:
                    // This works out as a total of 2+4+4+1*4+1 = 15 reqs / param
                    nixCount = 2;
                    winCount = 4;
                    dirCount = 4;
                    localTraversalLength = 1;
                    break;

                case HIGH:
                    // This works out as a total of 4+8+7+2*4+1 = 28 reqs / param
                    nixCount = 4;
                    winCount = 8;
                    dirCount = 7;
                    localTraversalLength = 2;
                    break;

                case INSANE:
                    // This works out as a total of 6+18+19+4*4+1 = 60 reqs / param
                    nixCount = NIX_LOCAL_FILE_TARGETS.length;
                    winCount = WIN_LOCAL_FILE_TARGETS.length;
                    dirCount = LOCAL_DIR_TARGETS.length;
                    localTraversalLength = 4;
                    includeNullByteInjectionPayload = true;
                    if (value != null) {
                        int index = value.lastIndexOf(".");
                        if (index != -1) {
                            extension = value.substring(index);
                        }
                    }
                    break;

                default:
                    // Default to off
            }

            log.debug(
                    "Checking [{}] [{}], parameter [{}] for Path Traversal to local files",
                    getBaseMsg().getRequestHeader().getMethod(),
                    getBaseMsg().getRequestHeader().getURI(),
                    param);

            // Check 1: Start detection for Windows patterns
            // note that depending on the AttackLevel, the number of prefixes that we will try
            // changes.
            if (inScope(Tech.Windows)) {

                for (int h = 0; h < winCount; h++) {

                    // Check if a there was a finding or the scan has been stopped
                    // if yes dispose resources and exit
                    if (sendAndCheckPayload(param, WIN_LOCAL_FILE_TARGETS[h], WIN_PATTERN)
                            || isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                    // Null Byte is appended to the value for ignoring the postfix data appended
                    // to the input.
                    if (includeNullByteInjectionPayload) {
                        if (sendAndCheckPayload(
                                        param,
                                        WIN_LOCAL_FILE_TARGETS[h] + NULL_BYTE_CHARACTER,
                                        WIN_PATTERN)
                                || isStop()) {
                            return;
                        }
                        if (extension != null) {
                            if (sendAndCheckPayload(
                                            param,
                                            WIN_LOCAL_FILE_TARGETS[h]
                                                    + NULL_BYTE_CHARACTER
                                                    + extension,
                                            WIN_PATTERN)
                                    || isStop()) {
                                return;
                            }
                        }
                    }
                }
            }

            // Check 2: Start detection for *NIX patterns
            // note that depending on the AttackLevel, the number of prefixes that we will try
            // changes.
            if (inScope(Tech.Linux) || inScope(Tech.MacOS)) {

                for (int h = 0; h < nixCount; h++) {

                    // Check if a there was a finding or the scan has been stopped
                    // if yes dispose resources and exit
                    if (sendAndCheckPayload(param, NIX_LOCAL_FILE_TARGETS[h], NIX_PATTERN)
                            || isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                    // Null Byte is appended to the value for ignoring the postfix data appended
                    // to the input
                    if (includeNullByteInjectionPayload) {
                        if (sendAndCheckPayload(
                                        param,
                                        NIX_LOCAL_FILE_TARGETS[h] + NULL_BYTE_CHARACTER,
                                        NIX_PATTERN)
                                || isStop()) {
                            return;
                        }

                        if (extension != null) {
                            if (sendAndCheckPayload(
                                            param,
                                            NIX_LOCAL_FILE_TARGETS[h]
                                                    + NULL_BYTE_CHARACTER
                                                    + extension,
                                            NIX_PATTERN)
                                    || isStop()) {
                                return;
                            }
                        }
                    }
                }
            }

            // Check 3: Detect if this page is a directory browsing component
            // example: https://www.buggedsite.org/log/index.php?dir=C:\
            // note that depending on the AttackLevel, the number of prefixes that we will try
            // changes.
            for (int h = 0; h < dirCount; h++) {

                // Check if a there was a finding or the scan has been stopped
                // if yes dispose resources and exit
                if (sendAndCheckPayload(param, LOCAL_DIR_TARGETS[h], DIR_PATTERN) || isStop()) {
                    // Dispose all resources
                    // Exit the scan rule
                    return;
                }
            }

            // Check 4: Start detection for internal well known files
            // try variants based on increasing ../ ..\ prefixes and the presence of the / and \
            // trailer
            // e.g. WEB-INF/web.xml, /WEB-INF/web.xml, ../WEB-INF/web.xml, /../WEB-INF/web.xml, ecc.
            // Both slashed and backslashed variants are checked
            // -------------------------------
            // Currently we've always checked only for J2EE known files
            // and this remains also for this version
            //
            // Web.config for .NET in the future?
            // -------------------------------
            String sslashPattern = "WEB-INF/web.xml";
            // The backslashed version of the same check
            String bslashPattern = sslashPattern.replace('/', '\\');

            if (inScope(Tech.Tomcat)) {

                for (int idx = 0; idx < localTraversalLength; idx++) {

                    // Check if a there was a finding or the scan has been stopped
                    // if yes dispose resources and exit
                    if (sendAndCheckPayload(param, sslashPattern, WAR_PATTERN)
                            || sendAndCheckPayload(param, bslashPattern, WAR_PATTERN)
                            || sendAndCheckPayload(param, '/' + sslashPattern, WAR_PATTERN)
                            || sendAndCheckPayload(param, '\\' + bslashPattern, WAR_PATTERN)
                            || isStop()) {

                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }

                    sslashPattern = "../" + sslashPattern;
                    bslashPattern = "..\\" + bslashPattern;
                }
            }

            // Check 5: try a local file Path Traversal on the file name of the URL (which obviously
            // will not be in the target list above).
            // first send a query for a random parameter value, and see if we get a 200 back
            // if 200 is returned, abort this check (on the url filename itself), because it would
            // be unreliable.
            // if we know that a random query returns <> 200, then a 200 response likely means
            // something!
            // this logic is all about avoiding false positives, while still attempting to match on
            // actual vulnerabilities
            msg = getNewMsg();
            setParameter(msg, param, NON_EXISTANT_FILENAME);

            // send the modified message (with a hopefully non-existent filename), and see what we
            // get back
            try {
                sendAndReceive(msg);

            } catch (SocketException
                    | IllegalStateException
                    | UnknownHostException
                    | IllegalArgumentException
                    | InvalidRedirectLocationException
                    | URIException ex) {
                log.debug(
                        "Caught {} {} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg.getRequestHeader().getURI().toString());

                return; // Something went wrong, no point continuing
            }

            // do some pattern matching on the results.
            Pattern errorPattern = Pattern.compile("Exception|Error");
            Matcher errorMatcher = errorPattern.matcher(msg.getResponseBody().toString());

            String urlfilename = msg.getRequestHeader().getURI().getName();

            // url file name may be empty, i.e. there is no file name for next check
            if (!StringUtils.isEmpty(urlfilename) && (!isPage200(msg) || errorMatcher.find())) {

                log.debug(
                        "It is possible to check for local file Path Traversal on the url filename on [{}] [{}], [{}]",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI().toString(),
                        param);

                String prefixedUrlfilename;

                // for the url filename, try each of the prefixes in turn
                for (String prefix : LOCAL_FILE_RELATIVE_PREFIXES) {

                    prefixedUrlfilename = prefix + urlfilename;
                    msg = getNewMsg();
                    setParameter(msg, param, prefixedUrlfilename);

                    // send the modified message (with the url filename), and see what we get back
                    try {
                        sendAndReceive(msg);

                    } catch (SocketException
                            | IllegalStateException
                            | UnknownHostException
                            | IllegalArgumentException
                            | InvalidRedirectLocationException
                            | URIException ex) {
                        log.debug(
                                "Caught {} {} when accessing: {}",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                msg.getRequestHeader().getURI().toString());

                        continue; // Something went wrong, move to the next prefix in the loop
                    }

                    // did we get an Exception or an Error?
                    errorMatcher = errorPattern.matcher(msg.getResponseBody().toString());
                    if (isPage200(msg) && (!errorMatcher.find())) {

                        // if it returns OK, and the random string above did NOT return ok, then
                        // raise an alert
                        // since the filename has likely been picked up and used as a file name from
                        // the parameter
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(param)
                                .setAttack(prefixedUrlfilename)
                                .setMessage(msg)
                                .raise();

                        // All done. No need to look for vulnerabilities on subsequent parameters
                        // on the same request (to reduce performance impact)
                        return;
                    }

                    // Check if the scan has been stopped
                    // if yes dispose resources and exit
                    if (isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                }
            }

            // Check 6 for local file names
            // TODO: consider making this check 1, for performance reasons
            // TODO: if the original query was http://www.example.com/a/b/c/d.jsp?param=paramvalue
            // then check if the following gives comparable results to the original query
            // http://www.example.com/a/b/c/d.jsp?param=../c/paramvalue
            // if it does, then we likely have a local file Path Traversal vulnerability
            // this is nice because it means we do not have to guess any file names, and would only
            // require one
            // request to find the vulnerability
            // but it would be foiled by simple input validation on "..", for instance.

        } catch (SocketTimeoutException ste) {
            log.warn(
                    "A timeout occurred while checking [{}] [{}], parameter [{}] for Path Traversal. The currently configured timeout is: {}",
                    msg.getRequestHeader().getMethod(),
                    msg.getRequestHeader().getURI(),
                    param,
                    Integer.toString(
                            Model.getSingleton()
                                    .getOptionsParam()
                                    .getConnectionParam()
                                    .getTimeoutInSecs()));

            log.debug("Caught {} {}", ste.getClass().getName(), ste.getMessage());

        } catch (IOException e) {
            log.warn(
                    "An error occurred while checking [{}] [{}], parameter [{}] for Path Traversal.Caught {} {}",
                    msg.getRequestHeader().getMethod(),
                    msg.getRequestHeader().getURI(),
                    param,
                    e.getClass().getName(),
                    e.getMessage());
        }
    }

    private boolean sendAndCheckPayload(
            String param, String newValue, ContentsMatcher contentsMatcher) throws IOException {
        if (contentsMatcher.match(getContentsToMatch(getBaseMsg())) != null) {
            // Evidence already present, no point sending the payload/attack.
            return false;
        }

        // get a new copy of the original message (request only)
        // and set the specific pattern
        HttpMessage msg = getNewMsg();
        setParameter(msg, param, newValue);

        log.debug(
                "Checking [{}] [{}], parameter [{}] for Windows Path Traversal (local file) with value [{}]",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                param,
                newValue);

        // send the modified request, and see what we get back
        try {
            sendAndReceive(msg);

        } catch (SocketException
                | IllegalStateException
                | UnknownHostException
                | IllegalArgumentException
                | InvalidRedirectLocationException
                | URIException ex) {
            log.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    msg.getRequestHeader().getURI().toString());

            return false; // Something went wrong, no point continuing
        }

        // does it match the pattern specified for that file name?
        String match = contentsMatcher.match(getContentsToMatch(msg));

        // if the output matches, and we get a 200
        if (isPage200(msg) && match != null) {
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(param)
                    .setAttack(newValue)
                    .setEvidence(match)
                    .setMessage(msg)
                    .raise();

            // All done. No need to look for vulnerabilities on subsequent parameters
            // on the same request (to reduce performance impact)
            return true;
        }

        return false;
    }

    private String getContentsToMatch(HttpMessage message) {
        return message.getResponseHeader().isHtml()
                ? StringEscapeUtils.unescapeHtml(message.getResponseBody().toString())
                : message.getResponseHeader().toString() + message.getResponseBody().toString();
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 22;
    }

    @Override
    public int getWascId() {
        return 33;
    }

    private static interface ContentsMatcher {

        String match(String contents);
    }

    private static class PatternContentsMatcher implements ContentsMatcher {

        private final Pattern pattern;

        public PatternContentsMatcher(Pattern pattern) {
            this.pattern = pattern;
        }

        @Override
        public String match(String contents) {
            Matcher matcher = pattern.matcher(contents);
            if (matcher.find()) {
                return matcher.group();
            }
            return null;
        }
    }

    private static class DirNamesContentsMatcher implements ContentsMatcher {

        @Override
        public String match(String contents) {
            if (contents.contains("etc") && contents.contains("bin") && contents.contains("boot")) {
                Pattern nixDoubleCheckPattern = Pattern.compile("\\betc\\b");
                Matcher nixDoubleCheckMatcher = nixDoubleCheckPattern.matcher(contents);

                if (nixDoubleCheckMatcher.find()) {
                    return "etc";
                }
            }

            if (contents.contains("Windows")
                    && Pattern.compile("Program\\sFiles").matcher(contents).find()) {
                return "Windows";
            }

            return null;
        }
    }
}
