/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scan rule that looks for application source code disclosure using SVN metadata/file disclosure
 *
 * @author 70pointer
 */
public class SourceCodeDisclosureSvnScanRule extends AbstractAppPlugin {

    /**
     * if we got a 404 or a redirect specifically, then this is NOT a match note that since we are
     * simply relying on the file existing or not, we will not attempt any fuzzy matching. Old
     * school. Checks based on this are necessary, otherwise a recursive scan on nodes in the url
     * path cause lots of false positives. MOVED_PERMANENTLY - 301 FOUND - 302 SEE_OTHER - 303
     * NOT_MODIFIED - 304 USE_PROXY - 305 (306 is currently unused) TEMPORARY_REDIRECT - 307
     * NOT_FOUND - 404
     */
    private static final List<Integer> UNWANTED_RESPONSE_CODES =
            Arrays.asList(301, 302, 303, 304, 305, 307, 404);

    private static final String MESSAGE_PREFIX = "ascanbeta.sourcecodedisclosure.svnbased.";

    /**
     * details of the vulnerability which we are attempting to find 34 = "Predictable Resource
     * Location"
     */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_34");

    /** the logger object */
    private static Logger log = Logger.getLogger(SourceCodeDisclosureSvnScanRule.class);

    /**
     * patterns expected in the output for common server side file extensions TODO: add support for
     * verification of other file types, once I get some real world test cases.
     */
    private static final Pattern PATTERN_JSP = Pattern.compile("<%.*%>");

    private static final Pattern PATTERN_PHP = Pattern.compile("<\\?php");
    private static final Pattern PATTERN_JAVA =
            Pattern.compile(
                    "class"); // Java is compiled, not interpreted, but this helps with my test
    // cases.
    private static final Pattern PATTERN_HTML =
            Pattern.compile(
                    "<html"); // helps eliminate some common false positives in the case of 403s,
    // 302s, etc.

    /** returns the plugin id */
    @Override
    public int getId() {
        return 42;
    }

    /** returns the name of the plugin */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.sourcecodedisclosure.desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
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

    public String getExtraInfo(String urlfilename, String attackFilename) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + "extrainfo", urlfilename, attackFilename);
    }

    @Override
    public void scan() {
        // at Low or Medium strength, do not attack URLs which returned "Not Found"
        AttackStrength attackStrength = getAttackStrength();
        if ((attackStrength == AttackStrength.LOW || attackStrength == AttackStrength.MEDIUM)
                && (getBaseMsg().getResponseHeader().getStatusCode() == HttpStatus.SC_NOT_FOUND))
            return;

        // scan the node itself (ie, at URL level, rather than at parameter level)
        if (log.isDebugEnabled()) {
            log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
            log.debug(
                    "Checking ["
                            + getBaseMsg().getRequestHeader().getMethod()
                            + "] ["
                            + getBaseMsg().getRequestHeader().getURI()
                            + "], for Source Code Disclosure using SVN meta-data");
        }

        try {
            URI uri = this.getBaseMsg().getRequestHeader().getURI();
            String filename = uri.getName();

            if (filename != null && filename.length() > 0) {
                // there is a file name at the end of the path.

                // Look for SVN metadata that can be exploited to give us the source code.
                if (findSourceCodeSVN(this.getBaseMsg())) {
                    // found one. no need to try other methods, so bale out.
                    return;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "The URI has no filename component, so there is not much point in looking for corresponding source code!");
                }
            }
        } catch (Exception e) {
            log.error(
                    "Error scanning a request for SVN based Source Code Disclosure: "
                            + e.getMessage(),
                    e);
        }
    }

    /**
     * returns whether the message response content matches the specified extension
     *
     * @param data
     * @param fileExtension
     * @return
     */
    private String findEvidenceForExtension(byte[] data, String fileExtension) {
        if (fileExtension != null) {
            Matcher matcher;
            if (fileExtension.equals("JSP")) {
                matcher = PATTERN_JSP.matcher(new String(data));
                if (matcher.find()) return matcher.group();
            } else if (fileExtension.equals("PHP")) {
                matcher = PATTERN_PHP.matcher(new String(data));
                if (matcher.find()) return matcher.group();
            } else if (fileExtension.equals("JAVA")) {
                matcher = PATTERN_JAVA.matcher(new String(data));
                if (matcher.find()) return matcher.group();
            } else if (fileExtension.equals("HTML")) {
                matcher = PATTERN_HTML.matcher(new String(data));
                if (matcher.find()) return matcher.group();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Unknown file extension "
                                    + fileExtension
                                    + ". Accepting this file type without verifying it. Could therefore be a false positive.");
                }
                if (getAlertThreshold() == AlertThreshold.LOW) {
                    // unknown file extension. just accept it as it is, despite no actual evidence
                    return "";
                } else {
                    // Not good enough for medium / high thresholds
                    return null;
                }
            }
            // known file type, but not matched. do not accept it.
            return null;
        } else {
            if (getAlertThreshold() == AlertThreshold.LOW) {
                // no file extension, therefore no way to verify the source code.. so accept it as
                // it is, despite no actual evidence
                return "";
            } else {
                // Not good enough for medium / high thresholds
                return null;
            }
        }
    }

    @Override
    public int getRisk() {
        // If we get the source (and its not open source), we don't need to hack the app any more,
        // because we can just analyse it off-line! Sweet..
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 541; // Information Exposure Through Include Source Code
    }

    @Override
    public int getWascId() {
        return 34; // Predictable Resource Location
    }

    private boolean shouldStop(AlertThreshold alertThreshold, int statusCode) {
        // At MEDIUM or HIGH ignore all client and server error responses
        if ((alertThreshold == AlertThreshold.MEDIUM || alertThreshold == AlertThreshold.HIGH)
                && (HttpStatusCode.isClientError(statusCode)
                        || HttpStatusCode.isServerError(statusCode))) {
            return true;
        }
        return false;
    }

    private int getConfidence(int statusCode) {
        if (HttpStatusCode.isClientError(statusCode) || HttpStatusCode.isServerError(statusCode)) {
            return Alert.CONFIDENCE_LOW; // Less confident due to response status code
        }
        return Alert.CONFIDENCE_MEDIUM;
    }

    /**
     * finds the source code for the given file, using SVN metadata on the server (if this is
     * available)
     *
     * @param uri the URI of a file, whose source code we want to find
     * @return Did we find the source code?
     */
    private boolean findSourceCodeSVN(HttpMessage originalMessage) throws Exception {

        AlertThreshold alertThreshold = getAlertThreshold();

        // SVN formats 1-10 (format 11 is not used) are supported by this logic.
        // TODO: The SQLite based (and centralised, except for pre-release formats which we don't
        // plan to support) ".svn/wc.db" style used from SVN format 12 through to 31
        // (and possibly later formats) is not yet supported here. It's a work in progress.
        // It is fully supported in the Spider, however.

        URI uri = originalMessage.getRequestHeader().getURI();
        String path = uri.getPath();
        if (path == null) path = "";
        // String filename = path.substring( path.lastIndexOf('/')+1, path.length() );
        String urlfilename = uri.getName();

        String fileExtension = null;
        if (urlfilename.contains(".")) {
            fileExtension = urlfilename.substring(urlfilename.lastIndexOf(".") + 1);
            fileExtension = fileExtension.toUpperCase();
        }

        // do not recurse into a Subversion folder... this would cause infinite recursion issues in
        // Attack Mode. (which goes depth first!)
        // in any event, it doesn't make sense to do this.
        if (path.contains("/.svn/") || path.endsWith("/.svn")) {
            if (log.isDebugEnabled())
                log.debug(
                        "Nope. It doesn't make any sense to look for a Subversion repo *within* a Subversion repo");
            return false;
        }

        // Look for SVN < 1.7 metadata (i.e. internal SVN format < 29) containing source code
        // These versions all store the pristine copies in the the same format (insofar as the logic
        // here is concerned, at least)
        try {
            String pathminusfilename = path.substring(0, path.lastIndexOf(urlfilename));

            HttpMessage svnsourcefileattackmsg =
                    new HttpMessage(
                            new URI(
                                    uri.getScheme(),
                                    uri.getAuthority(),
                                    pathminusfilename
                                            + ".svn/text-base/"
                                            + urlfilename
                                            + ".svn-base",
                                    null,
                                    null));
            svnsourcefileattackmsg.setCookieParams(this.getBaseMsg().getCookieParams());
            // svnsourcefileattackmsg.setRequestHeader(this.getBaseMsg().getRequestHeader());
            sendAndReceive(svnsourcefileattackmsg, false); // do not follow redirects

            int attackmsgResponseStatusCode =
                    svnsourcefileattackmsg.getResponseHeader().getStatusCode();

            if (shouldStop(alertThreshold, attackmsgResponseStatusCode)) {
                return false;
            }

            if (originalMessage
                    .getResponseBody()
                    .toString()
                    .equals(svnsourcefileattackmsg.getResponseBody().toString())) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Response bodies are exactly the same, so can not be the source code");
                }
            } else if (!UNWANTED_RESPONSE_CODES.contains(
                    attackmsgResponseStatusCode)) { // If the response is wanted (not on the
                // unwanted list)

                String attackFilename =
                        uri.getScheme()
                                + "://"
                                + uri.getAuthority()
                                + pathminusfilename
                                + ".svn/text-base/"
                                + urlfilename
                                + ".svn-base";
                if (log.isDebugEnabled()) {
                    log.debug(
                            "The contents for request '"
                                    + attackFilename
                                    + "' do not return 404 or 3**, so we possibly have the source code using SVN < 1.7");
                }
                // check the contents of the output to some degree, if we have a file extension.
                // if not, just try it (could be a false positive, but hey)
                String evidence =
                        findEvidenceForExtension(
                                svnsourcefileattackmsg.getResponseBody().getBytes(), fileExtension);
                if (evidence != null) {
                    // if we get to here, is is very likely that we have source file inclusion
                    // attack. alert it.
                    newAlert()
                            .setConfidence(getConfidence(attackmsgResponseStatusCode))
                            .setUri(getBaseMsg().getRequestHeader().getURI().getURI())
                            .setAttack(attackFilename)
                            .setOtherInfo(getExtraInfo(urlfilename, attackFilename))
                            .setEvidence(evidence)
                            .setMessage(svnsourcefileattackmsg)
                            .raise();
                    // if we found one, do not even try the "super" method, which tries each of the
                    // parameters,
                    // since this is slow, and we already found an instance
                    return true;
                } else {
                    if (log.isDebugEnabled())
                        log.debug(
                                "The HTML output does not look like source code of type "
                                        + fileExtension);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Got an unsuitable response code "
                                    + svnsourcefileattackmsg.getResponseHeader().getStatusCode()
                                    + ", so it looks like SVN < 1.7 source code file was not found");
                }
            }
        } catch (Exception e) {
            log.warn(
                    "Got an error trying to find source code using the format used by SVN < 1.7",
                    e);
        }

        // try again, by assuming that SVN 1.7 or later is used.  These versions use a different
        // internal format, and store the source code in different locations compared to SVN < 1.7.
        // Note that it's not as simple this time around, because the name of the file that contains
        // the source code is based on a SHA1 hash of the file contents, rather than being based on
        // the source file name.
        // In other words, we can't guess the name of the internal SVN file, and we can't just
        // calculate it from the file name.  The good news is that the file name that we need is
        // contained in the centralised
        // "wc.db" SVN metadata file that is associated with SVN >= 1.7.
        // "wc.db" lives in ".svn/wc.db".  This file contains data for all of the files in the repo
        // (ie, it contains data for the root directory and all subdirectories of the repo).
        // The only real issue we have is the question of where within the web folder structure (or
        // mappings) that the "wc.db" file resides.
        // For instance, the ".svn" directory might have been deployed into
        // "http://www.example.com/.svn",
        // or it *might* have been deployed into "http://www.example.com/dir1/dir2/.svn".
        // If we're looking for the SVN >= 1.7 source for
        // "http://www.example.com/dir1/dir2/login.php", for instance, we need to check for the
        // "wc.db" file in the following locations:
        //	"http://www.example.com/dir1/dir2/.svn/wc.db"
        //	"http://www.example.com/dir1/.svn/wc.db"
        //	"http://www.example.com/.svn/wc.db"
        // ie, we need to traverse all the way back to the web root looking for it.
        // Once we've found the "wc.db" file, we use it as an index, looking up the name of the file
        // for which we're trying to get the source code.
        // That gives us the internal SVN file name (containing the SHA1 value), which we can (in
        // theory) then retrieve. If it works, we will retrieve the source code for the file!
        try {
            String pathminusfilename = path.substring(0, path.lastIndexOf(urlfilename));
            while (!pathminusfilename.equals("/")) {
                HttpMessage svnWCDBAttackMsg =
                        new HttpMessage(
                                new URI(
                                        uri.getScheme(),
                                        uri.getAuthority(),
                                        pathminusfilename + ".svn/wc.db",
                                        null,
                                        null));
                svnWCDBAttackMsg.setCookieParams(this.getBaseMsg().getCookieParams());
                // svnsourcefileattackmsg.setRequestHeader(this.getBaseMsg().getRequestHeader());
                sendAndReceive(svnWCDBAttackMsg, false); // do not follow redirects

                int svnWCDBAttackMsgStatusCode =
                        svnWCDBAttackMsg.getResponseHeader().getStatusCode();

                if (shouldStop(alertThreshold, svnWCDBAttackMsgStatusCode)) {
                    return false;
                }

                if (originalMessage
                        .getResponseBody()
                        .toString()
                        .equals(svnWCDBAttackMsg.getResponseBody().toString())) {
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "Response bodies are exactly the same, so can not be the source code");
                    }
                } else if (!UNWANTED_RESPONSE_CODES.contains(
                        svnWCDBAttackMsgStatusCode)) { // If the response is wanted (not on the
                    // unwanted list)
                    // calculate the path used to access the wc.db, as well as the matching relpath
                    // to query the wc.db
                    // since the relpath is calculated from the original message URL path, after
                    // removing the base used in the wc.db url path
                    String wcdbAttackFilename =
                            uri.getScheme()
                                    + "://"
                                    + uri.getAuthority()
                                    + pathminusfilename
                                    + ".svn/wc.db";
                    String relPath =
                            path.substring(
                                    path.indexOf(pathminusfilename) + pathminusfilename.length());
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "The contents for request '"
                                        + wcdbAttackFilename
                                        + "' do not return 404 or 3**, so we found the '.svn/wc.db' file for SVN >= 1.7..");
                        log.debug("The relpath to query SQLite is '" + relPath + "'");
                    }

                    // so we found the wc.db file... handle it.
                    // get the binary data, and put it in a temp file we can use with the SQLite
                    // JDBC driver
                    // Note: File is not AutoClosable, so cannot use a "try with resources" to
                    // manage it
                    File tempSqliteFile;
                    tempSqliteFile = File.createTempFile("sqlite_svn_wc_db", null);
                    tempSqliteFile.deleteOnExit();
                    OutputStream fos = new FileOutputStream(tempSqliteFile);
                    fos.write(svnWCDBAttackMsg.getResponseBody().getBytes());
                    fos.close();

                    if (log.isDebugEnabled()) {
                        org.sqlite.JDBC jdbcDriver = new org.sqlite.JDBC();
                        log.debug(
                                "Created a temporary SQLite database file '"
                                        + tempSqliteFile
                                        + "'");
                        log.debug(
                                "SQLite JDBC Driver is version "
                                        + jdbcDriver.getMajorVersion()
                                        + "."
                                        + jdbcDriver.getMinorVersion());
                    }

                    // now load the temporary SQLite file using JDBC, and query the file entries
                    // within.
                    Class.forName("org.sqlite.JDBC");
                    String sqliteConnectionUrl = "jdbc:sqlite:" + tempSqliteFile.getAbsolutePath();

                    try (Connection conn = DriverManager.getConnection(sqliteConnectionUrl)) {
                        if (conn != null) {
                            ResultSet rsSVNWCFormat = null;
                            ResultSet rsNode = null;
                            ResultSet rsRepo = null;
                            try (Statement pragmaStatement = conn.createStatement();
                                    PreparedStatement nodeStatement =
                                            conn.prepareStatement(
                                                    "select kind,local_relpath,'pristine/'||substr(checksum,7,2) || \"/\" || substr(checksum,7)|| \".svn-base\" from nodes where local_relpath = ? order by wc_id")) {
                                rsSVNWCFormat = pragmaStatement.executeQuery("pragma USER_VERSION");

                                // get the precise internal version of SVN in use
                                // this will inform how the scanner should proceed in an efficient
                                // manner.
                                int svnFormat = 0;
                                while (rsSVNWCFormat.next()) {
                                    if (log.isDebugEnabled())
                                        log.debug("Got a row from 'pragma USER_VERSION'");
                                    svnFormat = rsSVNWCFormat.getInt(1);
                                    break;
                                }
                                if (svnFormat < 29) {
                                    throw new Exception(
                                            "The SVN Working Copy Format of the SQLite database should be >= 29. We found "
                                                    + svnFormat);
                                }
                                if (svnFormat > 31) {
                                    throw new Exception(
                                            "SVN Working Copy Format "
                                                    + svnFormat
                                                    + " is not supported at this time.  We support up to and including format 31 (~ SVN 1.8.5)");
                                }
                                if (log.isDebugEnabled()) {
                                    log.debug(
                                            "Internal SVN Working Copy Format for "
                                                    + tempSqliteFile
                                                    + " is "
                                                    + svnFormat);
                                    log.debug(
                                            "Refer to http://svn.apache.org/repos/asf/subversion/trunk/subversion/libsvn_wc/wc.h for more details!");
                                }

                                // now set the parameter, and execute the query
                                nodeStatement.setString(1, relPath);
                                rsNode = nodeStatement.executeQuery();

                                // and get the internal name of the SVN file stored in the SVN repo
                                while (rsNode.next()) {
                                    if (log.isDebugEnabled())
                                        log.debug(
                                                "Got a Node from the SVN wc.db file (format "
                                                        + svnFormat
                                                        + ")");
                                    // String kind = rsNode.getString(1);
                                    // String filename = rsNode.getString(2);
                                    String svnFilename = rsNode.getString(3);

                                    if (svnFilename != null && svnFilename.length() > 0) {
                                        log.debug(
                                                "Found "
                                                        + relPath
                                                        + " in the wc.db: "
                                                        + svnFilename);

                                        // try get the source, using the internal SVN file path,
                                        // building the path back up correctly
                                        HttpMessage svnSourceFileAttackMsg =
                                                new HttpMessage(
                                                        new URI(
                                                                uri.getScheme(),
                                                                uri.getAuthority(),
                                                                pathminusfilename
                                                                        + ".svn/"
                                                                        + svnFilename,
                                                                null,
                                                                null));
                                        svnSourceFileAttackMsg.setCookieParams(
                                                this.getBaseMsg().getCookieParams());
                                        // svnsourcefileattackmsg.setRequestHeader(this.getBaseMsg().getRequestHeader());
                                        sendAndReceive(
                                                svnSourceFileAttackMsg,
                                                false); // do not follow redirects

                                        int svnSourceFileAttackMsgStatusCode =
                                                svnSourceFileAttackMsg
                                                        .getResponseHeader()
                                                        .getStatusCode();

                                        if (shouldStop(
                                                alertThreshold, svnSourceFileAttackMsgStatusCode)) {
                                            return false;
                                        }

                                        if (!UNWANTED_RESPONSE_CODES.contains(
                                                svnSourceFileAttackMsgStatusCode)) { // If the
                                            // response is
                                            // wanted (not
                                            // on the
                                            // unwanted
                                            // list)

                                            String attackFilename =
                                                    uri.getScheme()
                                                            + "://"
                                                            + uri.getAuthority()
                                                            + pathminusfilename
                                                            + ".svn/"
                                                            + svnFilename;
                                            if (log.isDebugEnabled()) {
                                                log.debug(
                                                        "The contents for request '"
                                                                + attackFilename
                                                                + "' do not return 404 or 3**, so we possibly have the source code using SVN >= 1.7");
                                            }
                                            // check the contents of the output to some degree, if
                                            // we have a file extension.
                                            // if not, just try it (could be a false positive, but
                                            // hey)
                                            String evidence =
                                                    findEvidenceForExtension(
                                                            svnSourceFileAttackMsg
                                                                    .getResponseBody()
                                                                    .getBytes(),
                                                            fileExtension);
                                            if (evidence != null) {
                                                // if we get to here, is is very likely that we have
                                                // source file inclusion attack. alert it.
                                                newAlert()
                                                        .setConfidence(
                                                                getConfidence(
                                                                        svnSourceFileAttackMsgStatusCode))
                                                        .setUri(
                                                                getBaseMsg()
                                                                        .getRequestHeader()
                                                                        .getURI()
                                                                        .getURI())
                                                        .setAttack(attackFilename)
                                                        .setOtherInfo(
                                                                getExtraInfo(
                                                                        urlfilename,
                                                                        attackFilename))
                                                        .setEvidence(evidence)
                                                        .setMessage(svnSourceFileAttackMsg)
                                                        .raise();
                                                // do not return.. need to tidy up first
                                            } else {
                                                if (log.isDebugEnabled())
                                                    log.debug(
                                                            "The HTML output does not look like source code of type "
                                                                    + fileExtension);
                                            }
                                        } else {
                                            if (log.isDebugEnabled()) {
                                                log.debug(
                                                        "Got an unsuitable response code "
                                                                + svnSourceFileAttackMsg
                                                                        .getResponseHeader()
                                                                        .getStatusCode()
                                                                + ", so it looks like SVN >= 1.7 source code file was not found");
                                            }
                                        }

                                        break; // out of the loop. even though there should be just
                                        // 1 entry
                                    }
                                }
                            } catch (SQLException sqlEx) {
                                StringBuilder errorSb = new StringBuilder(300);
                                errorSb.append(
                                        "Error executing SQL on temporary SVN SQLite database '");
                                errorSb.append(sqliteConnectionUrl);
                                errorSb.append("': ");
                                errorSb.append(sqlEx);
                                errorSb.append("\nThe saved response likely wasn't a SQLite db.");
                                log.debug(errorSb);
                            } catch (Exception e) {
                                log.debug(
                                        "An error has occurred, related to the temporary SVN SQLite DB. "
                                                + e);
                            } finally {
                                // the JDBC driver in use does not play well with "try with
                                // resource" construct. I tried!
                                if (rsRepo != null) rsRepo.close();
                                if (rsNode != null) rsNode.close();
                                if (rsSVNWCFormat != null) rsSVNWCFormat.close();
                            }
                        } else
                            throw new SQLException(
                                    "Could not open a JDBC connection to SQLite file "
                                            + tempSqliteFile.getAbsolutePath());
                    } catch (Exception e) {
                        // the connection will have been closed already, since we're used a try with
                        // resources
                        log.error(
                                "Error parsing temporary SVN SQLite database "
                                        + sqliteConnectionUrl);
                    } finally {
                        // delete the temp file.
                        // this will be deleted when the VM is shut down anyway, but better to be
                        // safe than to run out of disk space.
                        tempSqliteFile.delete();
                    }

                    break; // out of the while loop
                } // non 404, 300, etc. for "wc.db", for SVN >= 1.7
                // set up the parent directory name
                pathminusfilename =
                        pathminusfilename.substring(
                                0,
                                pathminusfilename
                                                .substring(0, pathminusfilename.length() - 1)
                                                .lastIndexOf("/")
                                        + 1);
            }

        } catch (Exception e) {
            log.warn(
                    "Got an error trying to find source code using the format used by SVN >= 1.7",
                    e);
        }
        return false;
    }
}
