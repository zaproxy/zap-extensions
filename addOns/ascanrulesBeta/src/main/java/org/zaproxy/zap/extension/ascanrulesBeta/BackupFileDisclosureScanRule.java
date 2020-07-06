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

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
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
 * a scan rule that looks for backup files disclosed on the web server
 *
 * @author 70pointer
 */
public class BackupFileDisclosureScanRule extends AbstractAppPlugin {

    int numExtensionsToTry = 0;
    int numSuffixesToTry = 0;
    int numPrefixesToTry = 0;
    boolean doSwitchFileExtension = false;

    /** the ordered set of (lowercase) file extensions to try */
    static final Set<String> fileExtensions =
            new LinkedHashSet<String>(
                    Arrays.asList(
                            new String[] {
                                ".bak",
                                ".backup",
                                ".bac",
                                ".zip",
                                ".tar",
                                ".jar",
                                ".log",
                                ".swp",
                                "~" /* no "." */,
                                ".old",
                                ".~bk",
                                ".orig",
                                ".tmp",
                                ".exe",
                                ".0",
                                ".1",
                                ".2",
                                ".3",
                                ".gz",
                                ".bz2",
                                ".7z",
                                ".s7z",
                                ".lz",
                                ".z",
                                ".lzma",
                                ".lzo",
                                ".apk",
                                ".cab",
                                ".rar",
                                ".war",
                                ".ear",
                                ".tar.gz",
                                ".tgz",
                                ".tar.z",
                                ".tar.bz2",
                                ".tbz2",
                                ".tar.lzma",
                                ".tlz",
                                ".zipx",
                                ".iso",
                                ".src",
                                ".dev",
                                ".a",
                                ".a",
                                ".ar",
                                ".cbz",
                                ".cpio",
                                ".shar",
                                ".lbr",
                                ".lbr",
                                ".mar",
                                ".f",
                                ".rz",
                                ".sfark",
                                ".xz",
                                ".ace",
                                ".afa",
                                ".alz",
                                ".arc",
                                ".arj",
                                ".ba",
                                ".bh",
                                ".cfs",
                                ".cpt",
                                ".dar",
                                ".dd",
                                ".dgc",
                                ".dmg",
                                ".gca",
                                ".ha",
                                ".hki",
                                ".ice",
                                ".inc",
                                ".j",
                                ".kgb",
                                ".lhz",
                                ".lha",
                                ".lzk",
                                ".pak",
                                ".partimg.",
                                ".paq6",
                                ".paq7",
                                ".paq8",
                                ".pea",
                                ".pim",
                                ".pit",
                                ".qda",
                                ".rk",
                                ".sda",
                                ".sea",
                                ".sen",
                                ".sfx",
                                ".sit",
                                ".sitx",
                                ".sqx",
                                "s.xz",
                                ".tar.7z",
                                ".tar.xz",
                                ".uc",
                                ".uc0",
                                ".uc2",
                                ".ucn",
                                ".ur2",
                                ".ue2",
                                ".uca",
                                ".uha",
                                ".wim",
                                ".xar",
                                ".xp3",
                                ".yz1",
                                ".zoo",
                                ".zpaq",
                                ".zz",
                                ".include"
                                // extensions that get appended without the dot.
                                // these are fairly random, and are included to catch the remainder
                                // of the wavsep test cases, but are not likely in the real world
                                // which is why they are included at the very end, and will only be
                                // tried in "Insane" mode. Keepin' it real... :)
                                ,
                                "1",
                                "_1",
                                "2",
                                "_2",
                                "x",
                                "_x",
                                "bak",
                                "_bak",
                                "old",
                                "_old",
                                "a",
                                "b",
                                "c",
                                "d",
                                "e",
                                "f",
                                "_a",
                                "_b",
                                "_c",
                                "_d",
                                "_e",
                                "_f",
                                "inc",
                                "_inc",
                                "_backup"
                            }));

    /**
     * the ordered set of file suffixes to try (after the file path and file name, but immediately
     * before the extension) also used as directory suffixes for the parent folder of the file
     */
    static final Set<String> fileSuffixes =
            new LinkedHashSet<String>(
                    Arrays.asList(
                            new String[] {
                                " - Copy",
                                " - Copy (2)",
                                " - Copy (3)",
                                "backup",
                                "_backup",
                                "-backup",
                                "bak",
                                "_bak",
                                "-bak",
                                "old",
                                "_old",
                                "-old",
                                "1",
                                "-1",
                                "_1",
                                "2"
                                // ,".2"  //see above
                                ,
                                "-2",
                                "_2",
                                " - Copy - Copy" // a copy of a copy! :)
                                ,
                                "(copy)",
                                "(another copy)",
                                "(second copy)",
                                "(third copy)",
                                "(fourth copy)",
                                "(2nd copy)",
                                "(3rd copy)",
                                "(4th copy)",
                                " (copy)",
                                " (another copy)",
                                " (second copy)",
                                " (third copy)",
                                " (fourth copy)",
                                " (2nd copy)",
                                " (3rd copy)",
                                " (4th copy)"
                            }));

    /**
     * the ordered set of file prefixes to try (after the file path and file name, but immediately
     * before the extension)
     */
    static final Set<String> filePrefixes =
            new LinkedHashSet<String>(
                    Arrays.asList(
                            new String[] {
                                "Copy of ",
                                "Copy (2) of ",
                                "Copy (3) of ",
                                "Copy of Copy of " // a copy of a copy!
                                ,
                                "backup",
                                "backup_",
                                "backup-",
                                "bak",
                                "bak_",
                                "bak-",
                                "old",
                                "old_",
                                "old-",
                                "1",
                                "1_",
                                "1-",
                                "2",
                                "2_",
                                "2-"
                            }));

    /**
     * details of the vulnerability which we are attempting to find 34 = "Predictable Resource
     * Location"
     */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_34");

    private static Logger log = Logger.getLogger(BackupFileDisclosureScanRule.class);

    @Override
    public int getId() {
        return 10095;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.backupfiledisclosure.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.backupfiledisclosure.desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
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
        return Constant.messages.getString("ascanbeta.backupfiledisclosure.refs");
    }

    @Override
    public void init() {
        switch (this.getAttackStrength()) {
            case LOW:
                numExtensionsToTry = 3;
                numSuffixesToTry = 2;
                numPrefixesToTry = 0;
                doSwitchFileExtension = false;
                break;
            case MEDIUM:
                numExtensionsToTry = 10;
                numSuffixesToTry = 3;
                numPrefixesToTry = 2;
                doSwitchFileExtension = false;
                break;
            case HIGH:
                numExtensionsToTry = 20;
                numSuffixesToTry = 5;
                numPrefixesToTry = 4;
                doSwitchFileExtension = true;
                break;
            case INSANE:
                numExtensionsToTry = fileExtensions.size();
                numSuffixesToTry = fileSuffixes.size();
                numPrefixesToTry = filePrefixes.size();
                doSwitchFileExtension = true;
                break;
            default:
        }
    }

    @Override
    public void scan() {
        if (log.isDebugEnabled()) {
            log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
            log.debug(
                    "Checking ["
                            + getBaseMsg().getRequestHeader().getMethod()
                            + "] ["
                            + getBaseMsg().getRequestHeader().getURI()
                            + "], for Backup File Disclosure");
        }

        try {
            URI uri = this.getBaseMsg().getRequestHeader().getURI();
            String filename = uri.getName();

            int statusCode = this.getBaseMsg().getResponseHeader().getStatusCode();
            if (log.isDebugEnabled())
                log.debug(
                        "About to look for a backup for '"
                                + uri.getURI()
                                + "', which returned "
                                + statusCode);

            // is it worth looking for a copy of the file?
            if (statusCode == HttpStatus.SC_NOT_FOUND) {
                if (log.isDebugEnabled())
                    log.debug(
                            "The original file request was not successfuly retrieved (status = "
                                    + statusCode
                                    + "), so there is not much point in looking for a backup of a non-existent file!");
                return;
            }
            if (filename != null && filename.length() > 0) {
                // there is a file name at the end of the path, so look for a backup file for the
                // file
                findBackupFile(this.getBaseMsg());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "The URI has no filename component, so there is not much point in looking for a corresponding backup file!");
                }
            }
        } catch (Exception e) {
            log.error("Error scanning a request for Backup File Disclosure: " + e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM; // Medium or maybe High.. depends on the file.
    }

    @Override
    public int getCweId() {
        return 530; // CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
    }

    @Override
    public int getWascId() {
        return 34; // Predictable Resource Location
    }

    private boolean isEmptyResponse(byte[] response) {
        return response.length == 0;
    }

    private void findBackupFile(HttpMessage originalMessage) throws Exception {

        try {
            boolean gives404s = true;
            boolean parentgives404s = true;
            byte[] nonexistparentmsgdata = null;

            URI originalURI = originalMessage.getRequestHeader().getURI();

            // request a file in the same directory to see how it handles "File not found". Using a
            // 404? Something else?
            String temppath = originalURI.getPath();
            if (temppath == null) temppath = "";
            int slashposition = temppath.lastIndexOf("/");
            if (slashposition < 0) {
                // WTF? there was no slash in the path..
                throw new Exception("The message has a path with a malformed path component");
            }
            String filename = originalMessage.getRequestHeader().getURI().getName();

            String randomfilename =
                    RandomStringUtils.random(
                            filename.length(), "abcdefghijklmoopqrstuvwxyz9123456789");
            String randomfilepath = temppath.substring(0, slashposition) + "/" + randomfilename;

            if (log.isDebugEnabled()) log.debug("Trying non-existent file: " + randomfilepath);
            HttpMessage nonexistfilemsg =
                    new HttpMessage(
                            new URI(
                                    originalURI.getScheme(),
                                    originalURI.getAuthority(),
                                    randomfilepath,
                                    null,
                                    null));
            try {
                nonexistfilemsg.setCookieParams(originalMessage.getCookieParams());
            } catch (Exception e) {
                if (log.isDebugEnabled())
                    log.debug("Could not set the cookies from the base request:" + e);
            }
            sendAndReceive(nonexistfilemsg, false);
            byte[] nonexistfilemsgdata = nonexistfilemsg.getResponseBody().getBytes();
            // does the server give a 404 for a non-existent file?
            if (nonexistfilemsg.getResponseHeader().getStatusCode() != HttpStatus.SC_NOT_FOUND) {
                gives404s = false;
                if (log.isDebugEnabled())
                    log.debug(
                            "The server does not return a 404 status for a non-existent path: "
                                    + nonexistfilemsg.getRequestHeader().getURI().getURI());
            } else {
                gives404s = true;
                if (log.isDebugEnabled())
                    log.debug(
                            "The server gives a 404 status for a non-existent path: "
                                    + nonexistfilemsg.getRequestHeader().getURI().getURI());
            }

            // now request a different (and non-existent) parent directory,
            // to see whether a non-existent parent folder causes a 404
            String[] pathbreak = temppath.split("/");
            HttpMessage nonexistparentmsg = null;
            if (pathbreak.length
                    > 2) { // the file has a parent folder that is not the root folder (ie, there is
                // a parent folder to mess with)
                String[] temppathbreak = pathbreak;
                String parentfoldername = pathbreak[pathbreak.length - 2];
                String randomparentfoldername =
                        RandomStringUtils.random(
                                parentfoldername.length(), "abcdefghijklmoopqrstuvwxyz9123456789");

                // replace the parent folder name with the random one, and build it back into a
                // string
                temppathbreak[pathbreak.length - 2] = randomparentfoldername;
                String randomparentpath = StringUtils.join(temppathbreak, "/");

                if (log.isDebugEnabled())
                    log.debug("Trying non-existent parent path: " + randomparentpath);
                nonexistparentmsg =
                        new HttpMessage(
                                new URI(
                                        originalURI.getScheme(),
                                        originalURI.getAuthority(),
                                        randomparentpath,
                                        null,
                                        null));
                try {
                    nonexistparentmsg.setCookieParams(originalMessage.getCookieParams());
                } catch (Exception e) {
                    if (log.isDebugEnabled())
                        log.debug("Could not set the cookies from the base request:" + e);
                }
                sendAndReceive(nonexistparentmsg, false);
                nonexistparentmsgdata = nonexistparentmsg.getResponseBody().getBytes();
                // does the server give a 404 for a non-existent parent folder?
                if (nonexistparentmsg.getResponseHeader().getStatusCode()
                        != HttpStatus.SC_NOT_FOUND) {
                    parentgives404s = false;
                    if (log.isDebugEnabled())
                        log.debug(
                                "The server does not return a 404 status for a non-existent parent path: "
                                        + nonexistparentmsg.getRequestHeader().getURI().getURI());
                } else {
                    parentgives404s = true;
                    if (log.isDebugEnabled())
                        log.debug(
                                "The server gives a 404 status for a non-existent parent path: "
                                        + nonexistparentmsg.getRequestHeader().getURI().getURI());
                }
            }

            String actualfilename = originalURI.getName();
            String actualfileExtension = null;
            String path = originalURI.getPath();
            if (path == null) path = "";

            // record the position of the various injection points, always relative to the full path
            int positionExtensionInjection = 0;
            int positionFileSuffixInjection = 0;
            if (actualfilename.contains(".")) {
                positionExtensionInjection = path.lastIndexOf(".");
                positionFileSuffixInjection = positionExtensionInjection;
                actualfileExtension = actualfilename.substring(actualfilename.lastIndexOf("."));
            } else {
                positionExtensionInjection = path.length();
                positionFileSuffixInjection = path.length();
                actualfileExtension = "";
            }
            int positionFilePrefixInjection = path.lastIndexOf("/") + 1;
            int positionDirectorySuffixInjection = path.lastIndexOf("/");
            int positionDirectoryPrefixInjection = 0;
            if (positionDirectorySuffixInjection >= 0)
                positionDirectoryPrefixInjection =
                        path.substring(0, positionDirectorySuffixInjection).lastIndexOf("/") + 1;

            // the set of files we will try, in the order of insertion
            Set<URI> candidateBackupFileURIs = new LinkedHashSet<URI>();
            Set<URI> candidateBackupFileChangedFolderURIs =
                    new LinkedHashSet<
                            URI>(); // for a changed parent folder name, which we need to handle
            // separately

            log.debug("The path is " + path);

            // for each file extension to try (both appending, and replacing)
            int counted = 0;
            for (String fileExtensionToTry : fileExtensions) {
                // to append, inject the file extension at the end of the path
                String candidateBackupFilePath = path + fileExtensionToTry;
                log.debug("File Extension (append): '" + candidateBackupFilePath + "'");
                candidateBackupFileURIs.add(
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                candidateBackupFilePath,
                                null,
                                null));

                // to replace the extension, append the file extension at positionExtensionInjection
                candidateBackupFilePath =
                        path.substring(0, positionExtensionInjection) + fileExtensionToTry;
                log.debug("File Extension (replace): '" + candidateBackupFilePath + "'");
                candidateBackupFileURIs.add(
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                candidateBackupFilePath,
                                null,
                                null));

                // to switch the extension (if there was one), append the file extension at
                // positionExtensionInjection
                if (!actualfileExtension.equals("") && doSwitchFileExtension) {
                    candidateBackupFilePath =
                            path.substring(0, positionExtensionInjection)
                                    + fileExtensionToTry
                                    + actualfileExtension;
                    log.debug("File Extension (switch): '" + candidateBackupFilePath + "'");
                    candidateBackupFileURIs.add(
                            new URI(
                                    originalURI.getScheme(),
                                    originalURI.getAuthority(),
                                    candidateBackupFilePath,
                                    null,
                                    null));
                }
                counted++;
                if (counted > numExtensionsToTry) {
                    break; // out of the loop.
                }
            }

            // for each file suffix to try
            counted = 0;
            for (String fileSuffixToTry : fileSuffixes) {
                // inject the file suffix at positionFileSuffixInjection
                String candidateBackupFilePath =
                        path.substring(0, positionFileSuffixInjection)
                                + fileSuffixToTry
                                + (positionFileSuffixInjection >= path.length()
                                        ? ""
                                        : path.substring(positionFileSuffixInjection));
                log.debug("File Suffix (insert): '" + candidateBackupFilePath + "'");
                candidateBackupFileURIs.add(
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                candidateBackupFilePath,
                                null,
                                null));
                counted++;
                if (counted > numSuffixesToTry) {
                    break; // out of the loop.
                }
            }

            // for each file prefix to try
            counted = 0;
            for (String filePrefixToTry : filePrefixes) {
                // inject the file prefix at positionFilePrefixInjection
                String candidateBackupFilePath =
                        path.substring(0, positionFilePrefixInjection)
                                + filePrefixToTry
                                + (positionFilePrefixInjection >= path.length()
                                        ? ""
                                        : path.substring(positionFilePrefixInjection));
                log.debug("File Prefix (insert): '" + candidateBackupFilePath + "'");
                candidateBackupFileURIs.add(
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                candidateBackupFilePath,
                                null,
                                null));
                counted++;
                if (counted > numPrefixesToTry) {
                    break; // out of the loop.
                }
            }

            // for each directory suffix/prefix to try (using the file prefixes/suffixes - or
            // whatever the plural of prefix/suffix is)
            counted = 0;
            if (pathbreak.length > 2) {
                // if there is a a parent folder to play with
                for (String fileSuffixToTry : fileSuffixes) {
                    // inject the directory suffix at positionDirectorySuffixInjection
                    String candidateBackupFilePath =
                            path.substring(0, positionDirectorySuffixInjection)
                                    + fileSuffixToTry
                                    + (positionDirectorySuffixInjection >= path.length()
                                            ? ""
                                            : path.substring(positionDirectorySuffixInjection));
                    log.debug("Directory Suffix (insert): '" + candidateBackupFilePath + "'");
                    candidateBackupFileChangedFolderURIs.add(
                            new URI(
                                    originalURI.getScheme(),
                                    originalURI.getAuthority(),
                                    candidateBackupFilePath,
                                    null,
                                    null));
                    counted++;
                    if (counted > numSuffixesToTry) {
                        break; // out of the loop.
                    }
                }
                for (String filePrefixToTry : filePrefixes) {
                    // inject the directory prefix at positionDirectorySuffixInjection
                    String candidateBackupFilePath =
                            path.substring(0, positionDirectoryPrefixInjection)
                                    + filePrefixToTry
                                    + (positionDirectoryPrefixInjection >= path.length()
                                            ? ""
                                            : path.substring(positionDirectoryPrefixInjection));
                    log.debug("Directory Suffix (insert): '" + candidateBackupFilePath + "'");
                    candidateBackupFileChangedFolderURIs.add(
                            new URI(
                                    originalURI.getScheme(),
                                    originalURI.getAuthority(),
                                    candidateBackupFilePath,
                                    null,
                                    null));
                    counted++;
                    if (counted > numSuffixesToTry) {
                        break; // out of the loop.
                    }
                }
            }

            // now we have a set of candidate URIs appropriate to the attack strength chosen by the
            // user
            // try each candidate URI in turn.
            for (URI candidateBackupFileURI : candidateBackupFileURIs) {
                byte[] disclosedData = {};
                if (log.isDebugEnabled())
                    log.debug(
                            "Trying possible backup file path: " + candidateBackupFileURI.getURI());
                HttpMessage requestmsg = new HttpMessage(candidateBackupFileURI);
                try {
                    requestmsg.setCookieParams(originalMessage.getCookieParams());
                } catch (Exception e) {
                    if (log.isDebugEnabled())
                        log.debug("Could not set the cookies from the base request:" + e);
                }
                // Do not follow redirects. They're evil. Yep.
                sendAndReceive(requestmsg, false);
                if (!isWithinThreshold(requestmsg)) {
                    continue;
                }
                disclosedData = requestmsg.getResponseBody().getBytes();
                int requestStatusCode = requestmsg.getResponseHeader().getStatusCode();

                // just to complicate things.. I have a test case which for the random file, does
                // NOT give a 404 (so gives404s == false)
                // but for a "Copy of" file, actually gives a 404 (for some unknown reason). We need
                // to handle this case.
                if (!isEmptyResponse(disclosedData)
                        && ((gives404s && requestStatusCode != HttpStatus.SC_NOT_FOUND)
                                || ((!gives404s)
                                        && nonexistfilemsg.getResponseHeader().getStatusCode()
                                                != requestStatusCode
                                        && (!Arrays.equals(disclosedData, nonexistfilemsgdata))))) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(candidateBackupFileURI.getURI())
                            .setOtherInfo(originalMessage.getRequestHeader().getURI().getURI())
                            .setSolution(
                                    Constant.messages.getString(
                                            "ascanbeta.backupfiledisclosure.soln"))
                            .setEvidence(
                                    Constant.messages.getString(
                                            "ascanbeta.backupfiledisclosure.evidence",
                                            originalURI,
                                            candidateBackupFileURI.getURI()))
                            .setMessage(requestmsg)
                            .raise();
                }

                if (isStop()) {
                    if (log.isDebugEnabled())
                        log.debug("The scan rule was stopped in response to a user request");
                    return;
                }
            }

            // now try the changed parent folders (if any)
            // the logic here needs to check using the parent 404 logic, and the output for a
            // non-existent parent folder.
            for (URI candidateBackupFileURI : candidateBackupFileChangedFolderURIs) {
                byte[] disclosedData = {};
                if (log.isDebugEnabled())
                    log.debug(
                            "Trying possible backup file path (with changed parent folder): "
                                    + candidateBackupFileURI.getURI());
                HttpMessage requestmsg = new HttpMessage(candidateBackupFileURI);
                try {
                    requestmsg.setCookieParams(originalMessage.getCookieParams());
                } catch (Exception e) {
                    if (log.isDebugEnabled())
                        log.debug("Could not set the cookies from the base request:" + e);
                }
                // Do not follow redirects. They're evil. Yep.
                sendAndReceive(requestmsg, false);
                if (!isWithinThreshold(requestmsg)) {
                    continue;
                }
                disclosedData = requestmsg.getResponseBody().getBytes();
                int requestStatusCode = requestmsg.getResponseHeader().getStatusCode();
                // If the response is empty it's probably not really a backup

                if (!isEmptyResponse(disclosedData)
                        && ((parentgives404s && requestStatusCode != HttpStatus.SC_NOT_FOUND)
                                || ((!parentgives404s)
                                        && nonexistparentmsg.getResponseHeader().getStatusCode()
                                                != requestStatusCode
                                        && (!Arrays.equals(
                                                disclosedData, nonexistparentmsgdata))))) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setName(
                                    Constant.messages.getString(
                                            "ascanbeta.backupfiledisclosure.name"))
                            .setAttack(candidateBackupFileURI.getURI())
                            .setOtherInfo(originalMessage.getRequestHeader().getURI().getURI())
                            .setSolution(
                                    Constant.messages.getString(
                                            "ascanbeta.backupfiledisclosure.soln"))
                            .setEvidence(
                                    Constant.messages.getString(
                                            "ascanbeta.backupfiledisclosure.evidence",
                                            originalURI,
                                            candidateBackupFileURI.getURI()))
                            .setMessage(requestmsg)
                            .raise();
                }

                if (isStop()) {
                    if (log.isDebugEnabled())
                        log.debug("The scan rule was stopped in response to a user request");
                    return;
                }
            }

        } catch (Exception e) {
            log.error(
                    "Some error occurred when looking for a backup file for '"
                            + originalMessage.getRequestHeader().getURI(),
                    e);
            return;
        }
    }

    private boolean isWithinThreshold(HttpMessage msg) {
        // Ignore messages with non-success codes unless at LOW threshold
        return this.getAlertThreshold().equals(AlertThreshold.LOW)
                || HttpStatusCode.isSuccess(msg.getResponseHeader().getStatusCode());
    }
}
