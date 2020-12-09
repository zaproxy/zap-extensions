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

import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scan rule that looks for application source code disclosure using Git metadata/file disclosure
 *
 * @author 70pointer
 */
public class SourceCodeDisclosureGitScanRule extends AbstractAppPlugin {

    /**
     * details of the vulnerability which we are attempting to find 34 = "Predictable Resource
     * Location"
     */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_34");

    /** the logger object */
    private static Logger log = Logger.getLogger(SourceCodeDisclosureGitScanRule.class);

    /**
     * patterns expected in the output for common server side file extensions TODO: add support for
     * verification of other file types, once I get some real world test cases.
     */
    private static final Pattern PATTERN_JSP = Pattern.compile("<%.*%>");

    private static final Pattern PATTERN_PHP = Pattern.compile("<?php");
    private static final Pattern PATTERN_JAVA =
            Pattern.compile(
                    "class"); // Java is compiled, not interpreted, but this helps with my test
    // cases.
    private static final Pattern PATTERN_HTML =
            Pattern.compile(
                    "<html"); // helps eliminate some common false positives in the case of 403s,
    // 302s, etc

    @Override
    public int getId() {
        return 41;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sourcecodedisclosure.gitbased.name");
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
        return Constant.messages.getString("ascanbeta.sourcecodedisclosure.gitbased.soln");
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

    private String getEvidence(String filename, String gitURIs) {
        return Constant.messages.getString(
                "ascanbeta.sourcecodedisclosure.gitbased.evidence", filename, gitURIs);
    }

    @Override
    public void scan() {
        // at Low or Medium strength, do not attack URLs which returned "Not Found"
        AttackStrength attackStrength = getAttackStrength();
        if ((attackStrength == AttackStrength.LOW || attackStrength == AttackStrength.MEDIUM)
                && (isPage404(getBaseMsg()))) return;

        // scan the node itself (ie, at URL level, rather than at parameter level)
        if (log.isDebugEnabled()) {
            log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
            log.debug(
                    "Checking ["
                            + getBaseMsg().getRequestHeader().getMethod()
                            + "] ["
                            + getBaseMsg().getRequestHeader().getURI()
                            + "], for Source Code Disclosure using Git meta-data");
        }

        try {
            URI uri = this.getBaseMsg().getRequestHeader().getURI();
            String filename = uri.getName();

            if (filename != null && filename.length() > 0) {
                // there is a file name at the end of the path.

                // Look for Git metadata that can be exploited to give us the source code.
                if (findSourceCodeGit(this.getBaseMsg())) {
                    // found one. bale out.
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
                    "Error scanning a request for Git based Source Code Disclosure: "
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
    private boolean dataMatchesExtension(byte[] data, String fileExtension) {
        if (fileExtension != null) {
            if (fileExtension.equals("JSP")) {
                if (PATTERN_JSP.matcher(new String(data)).find()) return true;
            } else if (fileExtension.equals("PHP")) {
                if (PATTERN_PHP.matcher(new String(data)).find()) return true;
            } else if (fileExtension.equals("JAVA")) {
                if (PATTERN_JAVA.matcher(new String(data)).find()) return true;
            } else if (fileExtension.equals("HTML")) {
                if (PATTERN_HTML.matcher(new String(data)).find()) return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Unknown file extension "
                                    + fileExtension
                                    + ". Accepting this file type without verifying it. Could therefore be a false positive.");
                }
                // unknown file extension. just accept it as it is.
                return true;
            }
            // known file type, but not matched. do not accept it.
            return false;
        } else {
            // no file extension, therefore no way to verify the source code.. so accept it as it is
            return true;
        }
    }

    @Override
    public int getRisk() {
        return Alert
                .RISK_HIGH; // definitely a High. If we get the source, we don't need to hack the
        // app any more, because we can just analyse it off-line! Sweet..
    }

    @Override
    public int getCweId() {
        return 541; // Information Exposure Through Include Source Code
    }

    @Override
    public int getWascId() {
        return 34; // Predictable Resource Location
    }

    /**
     * finds the source code for the given file, using Git metadata on the server (if this is
     * available)
     *
     * @param uri the URI of a file, whose source code we want to find
     * @return Did we find the source code?
     */
    private boolean findSourceCodeGit(HttpMessage originalMessage) throws Exception {
        byte[] disclosedData = {};
        String gitsha1 = null;
        String gitindexpath = null;
        try {
            URI originalURI = originalMessage.getRequestHeader().getURI();
            // String originalURIWithoutQuery = originalURI.getScheme() + "://" +
            // originalURI.getAuthority() + originalURI.getPath();
            // String canonicalisedOriginalURIStringWithoutQuery =
            // URLCanonicalizer.getCanonicalURL(originalURIWithoutQuery);
            String path = originalURI.getPath();
            if (path == null) path = "";
            String filename = originalURI.getName();

            String fileExtension = null;
            if (filename.contains(".")) {
                fileExtension = filename.substring(filename.lastIndexOf(".") + 1);
                fileExtension = fileExtension.toUpperCase();
            }

            URI originalURIWithoutQuery =
                    new URI(originalURI.getScheme(), originalURI.getAuthority(), path, null, null);
            GitMetadata git = new GitMetadata(this.getParent(), 4096);
            GitIndexEntryCache gitindexentrycache = GitIndexEntryCache.getSingleton();

            // look for the .git/index file in the directory and parent directories of the file for
            // which we are attempting to get the source code.
            String modifiedpath = path;
            byte[] data = {};
            boolean gitSHA1located = false;
            // work backwards from the original path, stripping off one folder at a time
            // until we find a valid Git index file that contains our file name!
            modifiedpath =
                    modifiedpath.substring(
                            0,
                            modifiedpath.lastIndexOf("/")
                                    + 1); // leave the trailing slash on, if there was one
            while ((!modifiedpath.equals("")) && (!gitSHA1located)) {

                if (log.isDebugEnabled()) log.debug("Path is " + modifiedpath);

                gitindexpath = modifiedpath + ".git/index";

                URI gitindexuri =
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                gitindexpath,
                                null,
                                null);
                try {
                    if (log.isDebugEnabled())
                        log.debug("Trying for a Git index file " + gitindexuri.getURI());

                    if (!gitindexentrycache.isIndexCached(gitindexuri)) {
                        // The Git index is not cached, so parse it and cache it.
                        if (log.isDebugEnabled())
                            log.debug(
                                    "Git Index "
                                            + gitindexuri.getURI()
                                            + " is not cached. We will parse and cache it");

                        data = git.getURIResponseBody(gitindexuri, false, originalMessage);
                        // get the list of relative file paths and Git SHA1s from the file
                        Map<String, String> gitFiles = git.getIndexSha1s(data);
                        if (gitFiles != null) {
                            if (log.isDebugEnabled())
                                log.debug("We found a Git index file at '" + gitindexpath + "'");

                            Set<Entry<String, String>> entrySet = gitFiles.entrySet();
                            Iterator<Entry<String, String>> entryIterator = entrySet.iterator();
                            while (entryIterator.hasNext()) {
                                Entry<String, String> gitIndexEntry = entryIterator.next();

                                // the URIs from the Git index file do not have a query or fragment
                                // component, so no need to strip those off here
                                URI gitIndexEntryUri =
                                        new URI(
                                                originalURI.getScheme(),
                                                originalURI.getAuthority(),
                                                modifiedpath + gitIndexEntry.getKey(),
                                                null,
                                                null);
                                String gitSHA1Temp = gitIndexEntry.getValue();

                                // cache the entry..
                                if (log.isDebugEnabled())
                                    log.debug(
                                            "Caching Git Index file "
                                                    + gitindexuri.getURI()
                                                    + ", Index Entry "
                                                    + gitIndexEntryUri.getURI()
                                                    + ", SHA1 "
                                                    + gitSHA1Temp);
                                gitindexentrycache.putIndexEntry(
                                        gitindexuri, gitIndexEntryUri, gitSHA1Temp);
                            }
                        }
                    }
                    // at this point, we know the Git index file is cached, one way or another.
                    // did we get the Git SHA1 of the file we were interested in, after all that?
                    if (gitindexentrycache.isIndexEntryCached(
                            gitindexuri, originalURIWithoutQuery)) {
                        // no need to keep on looping back up, if we found our entry
                        gitSHA1located = true;
                        gitsha1 =
                                gitindexentrycache.getIndexEntry(
                                        gitindexuri, originalURIWithoutQuery);
                        log.debug(
                                "Git SHA1 '"
                                        + gitsha1
                                        + "' was found for Git index file '"
                                        + gitindexuri
                                        + ", Git index entry file '"
                                        + originalURIWithoutQuery
                                        + "'");
                        break;
                    } else {
                        log.debug(
                                "A cache entry was not found for Git index file '"
                                        + gitindexuri
                                        + ", Git index entry file '"
                                        + originalURIWithoutQuery
                                        + "'");
                    }

                } catch (Exception e) {
                    if (log.isDebugEnabled())
                        log.debug(
                                "Ignoring an error getting/parsing '"
                                        + gitindexpath
                                        + "', while trying to find the Git SHA1 value for '"
                                        + path
                                        + "': "
                                        + e);
                } finally {
                    // move to the next parent directory, by first stripping off the trailing index,
                    // and grabbing up to and including the last index
                    modifiedpath = modifiedpath.substring(0, modifiedpath.length() - 1);
                    modifiedpath =
                            modifiedpath.substring(
                                    0,
                                    modifiedpath.lastIndexOf("/")
                                            + 1); // leave the trailing slash on, if there was one
                }

                if (isStop()) {
                    if (log.isDebugEnabled())
                        log.debug(
                                "Stopped scan rule (while trying to find the Git index file), due to a user request");
                    return false;
                }
            }

            // do we have a shot at getting the source code using Git?
            if (gitsha1 == null
                    || gitsha1.equals("")
                    || gitindexpath == null
                    || gitindexpath.equals("")) {
                if (log.isDebugEnabled())
                    log.debug(
                            "A Git SHA1 value or Git index path for '" + path + "' was not found.");
                return false;
            }
            if (!git.validateSHA1(gitsha1)) {
                if (log.isDebugEnabled())
                    log.debug(
                            "The 'gitsha1' parameter '"
                                    + gitsha1
                                    + "' does not appear to be a valid format for a Git SHA1 value");
                return false;
            }
            String gitbasepath = git.getBaseFolder(gitindexpath);
            if (gitbasepath == null || gitbasepath.equals("")) {
                if (log.isDebugEnabled())
                    log.debug(
                            "The 'gitindexpath' parameter '"
                                    + gitbasepath
                                    + "' does not appear to be valid.");
                return false;
            }
            // get the data from Git, using its SHA1 value.
            disclosedData =
                    git.getObjectData(
                            this.getBaseMsg(),
                            gitbasepath,
                            gitsha1); // look for data for the file's Git SHA1, and inflate it
            String gitURIs = git.getGitURIs();

            // so we have the data from Git for the sha1/file in questions.. does it match the
            // original data?
            // if not (but if it still looks valid), then throw a "source code disclosure" alert
            if (!Arrays.equals(disclosedData, originalMessage.getResponseBody().getBytes())) {

                // check the contents of the output to some degree, if we have a file extension.
                // if not, just try it (could be a false positive, but hey)
                if (dataMatchesExtension(disclosedData, fileExtension)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Source code disclosure, using Git metadata leakage!");
                    }

                    // source file inclusion attack. alert it.
                    // Note that, unlike with SVN, the Git data is extracted not from one file, but
                    // by parsing a series of files.
                    // we cannot meaningfully raise an alert on any one file, except perhaps the
                    // file on which the attack was launched.
                    // it's the least worst way of doing it, IMHO.
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().getURI())
                            .setOtherInfo(new String(disclosedData))
                            .setEvidence(getEvidence(filename, gitURIs))
                            .setMessage(originalMessage)
                            .raise();
                    return true;
                }
                // does not match the extension
                return false;
            } else {
                if (log.isDebugEnabled())
                    log.debug(
                            "The data disclosed via Git meta-data is not source code, since it matches the data served when we requested the file in the normal manner (source code is not served by web apps, and if it is, then you have bigger problems)");
                return false;
            }
        } catch (FileNotFoundException e) {
            if (log.isDebugEnabled()) log.debug("A file was not found for SHA1 '" + gitsha1 + "'");
            return false;
        } catch (Exception e) {
            log.error(
                    "Some other error occurred when reading data for Git SHA1 '"
                            + gitsha1
                            + "': "
                            + e);
            return false;
        }
    }
}
