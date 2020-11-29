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
package org.zaproxy.zap.extension.importLogFiles;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.importLogFiles.ExtensionImportLogFiles.LogType;

/// This class extends the ImportLog functionality to the ZAP REST API
public class ImportLogAPI extends ApiImplementor {

    private static Logger log = Logger.getLogger(ImportLogAPI.class);

    // API method names
    private static final String PREFIX = "importLogFiles";
    private static final String Import_Zap_Log_From_File = "ImportZAPLogFromFile";
    private static final String Import_ModSec_Log_From_File = "ImportModSecurityLogFromFile";
    private static final String Import_Zap_HttpRequestResponsePair =
            "ImportZAPHttpRequestResponsePair";
    private static final String POST_ModSec_AuditEvent = "PostModSecurityAuditEvent";
    private static final String OtherPOST_ModSec_AuditEvent = "OtherPostModSecurityAuditEvent";

    // API method parameters
    private static final String PARAM_FILE = "FilePath";
    private static final String PARAM_REQUEST = "HTTPRequest";
    private static final String PARAM_RESPONSE = "HTTPResponse";
    private static final String PARAM_AuditEventString = "AuditEventString";

    // Serverside directory locations
    private static final String SERVERSIDE_FILEREPOSITORY =
            org.parosproxy.paros.Constant.getZapHome() + "Imported_Logs";
    private static final String ZAP_LOGS_DIR =
            SERVERSIDE_FILEREPOSITORY + File.separatorChar + "ZAPLogs";
    private static final String MOD_SEC_LOGS_DIR =
            SERVERSIDE_FILEREPOSITORY + File.separatorChar + "ModSecLogs";
    // private static String ADDEDFILESDICTIONARY = SERVERSIDE_FILEREPOSITORY + "\\AddedFiles";
    private static boolean ZapDirChecked = false;
    private static boolean ModSecDirChecked = false;

    // private static boolean DirAddedFilesChecked = false;

    // Get the existing logging repository for REST retrieval if it exists, if not create it.
    private static String getLoggingStorageDirectory(LogType logType) {
        if (logType == LogType.ZAP) {
            if (!ZapDirChecked) {
                File directory = new File(ZAP_LOGS_DIR);
                if (!directory.isDirectory()) {
                    directory.mkdirs();
                    ZapDirChecked = true;
                    return directory.getAbsolutePath();
                }
                return ZAP_LOGS_DIR;
            }
            return ZAP_LOGS_DIR;
        }
        if (!ModSecDirChecked) {
            File directory = new File(MOD_SEC_LOGS_DIR);
            if (!directory.isDirectory()) {
                directory.mkdirs();
                ModSecDirChecked = true;
                return directory.getAbsolutePath();
            }
            return MOD_SEC_LOGS_DIR;
        }
        return MOD_SEC_LOGS_DIR;
    }

    /*
    private static String getAddedFilesDictionary() throws IOException {
        while (!DirAddedFilesChecked) {
            File hashes = new File(ADDEDFILESDICTIONARY);
            if (!hashes.isFile()) hashes.createNewFile();
            return hashes.getAbsolutePath();
        }
        return ADDEDFILESDICTIONARY;
    }

    private static void appendAddedFilesHashes(File file) throws IOException {
        BufferedWriter wr = null;
        FileInputStream fs = null;
        try {
            fs = new FileInputStream(file);
            String md5 = DigestUtils.md5Hex(fs);

            wr = new BufferedWriter(new FileWriter(getAddedFilesDictionary()));
            wr.write(md5);
            wr.newLine();
        } finally {
            try {
                if (fs != null) fs.close();
                if (wr != null) wr.close();
            } catch (IOException ex) {
                log.error(ex.getMessage(), ex);
            }
        }
    }

    private static boolean FileAlreadyExists(File file) {
        boolean fileExists = false;
        FileInputStream fs = null;
        BufferedReader br = null;
        try {
            fs = new FileInputStream(file);
            String md5 = DigestUtils.md5Hex(fs);

            // TODO figure out what parts of the file to compare with MD5 as currently its giving different hashes as the
            // metadata is different.
            // Probably have to hash the string[] lines of the file. Also might be worth adding an abstraction on the REST api
            // so that the files are named by the hash.
            String sCurrentLine;
            br = new BufferedReader(new FileReader(getAddedFilesDictionary()));
            while ((sCurrentLine = br.readLine()) != null) {
                if (md5 == sCurrentLine) fileExists = true;
            }
        }

        catch (Exception e) {
            log.error(e.getMessage(), e);
        } finally {
            try {
                if (fs != null) fs.close();
                if (br != null) br.close();
            } catch (IOException ex) {
                log.error(ex.getMessage(), ex);
            }
        }
        return fileExists;
    }
    */

    /** Provided only for API client generator usage. */
    public ImportLogAPI() {
        this(null);
    }

    // Methods to show in the http API view
    public ImportLogAPI(ExtensionImportLogFiles extensionImportLogFiles) {
        this.addApiAction(new ApiAction(Import_Zap_Log_From_File, new String[] {PARAM_FILE}));
        this.addApiAction(new ApiAction(Import_ModSec_Log_From_File, new String[] {PARAM_FILE}));
        this.addApiAction(
                new ApiAction(
                        Import_Zap_HttpRequestResponsePair,
                        new String[] {PARAM_REQUEST, PARAM_RESPONSE}));
        this.addApiAction(
                new ApiAction(POST_ModSec_AuditEvent, null, new String[] {PARAM_AuditEventString}));
        this.addApiOthers(
                new ApiOther(OtherPOST_ModSec_AuditEvent, new String[] {PARAM_AuditEventString}));
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params) {
        ExtensionImportLogFiles importer = new ExtensionImportLogFiles();
        if (OtherPOST_ModSec_AuditEvent.equals(name)) {
            String trimmed =
                    params.getString("POSTBODY")
                            .replaceFirst("zapapiformat=JSON&AuditEventString=", "");
            String filename = "\\" + java.util.UUID.randomUUID().toString() + ".txt";
            try {
                // TODO - this doesn't work as the source needs to be a local file
                processLogs(filename, importer, LogType.MOD_SECURITY_2, trimmed);
            } catch (Exception ex) {
                // String errMessage = "Failed - " + ex.getMessage();
                // return new ApiResponseElement("Parsing audit event log to ZAPs site tree",
                // errMessage);
            }
        }
        return null;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        ExtensionImportLogFiles importer = new ExtensionImportLogFiles();
        if (Import_Zap_Log_From_File.equals(name))
            return processLogsFromFile(params.getString(PARAM_FILE), importer, LogType.ZAP);
        if (Import_ModSec_Log_From_File.equals(name))
            return processLogsFromFile(
                    params.getString(PARAM_FILE), importer, LogType.MOD_SECURITY_2);
        if (Import_Zap_HttpRequestResponsePair.equals(name)) {
            try {
                List<HttpMessage> messages =
                        importer.getHttpMessageFromPair(
                                params.getString(PARAM_REQUEST), params.getString(PARAM_RESPONSE));
                return ProcessRequestResponsePair(messages, importer);
            } catch (HttpMalformedHeaderException e) {
                String errMessage = "Failed - " + e.getMessage();
                return new ApiResponseElement("Parsing logs files to ZAPs site tree", errMessage);
            }
        }
        // TODO - Need to add functionality to handle the POSTBody processing at some level of the
        // implementation.
        if (POST_ModSec_AuditEvent.equals(name)) {
            // TODO - figure out how best to add the post and where the params should be set!!!
            String trimmed =
                    params.getString("POSTBODY")
                            .replaceFirst("zapapiformat=JSON&AuditEventString=", "");
            String filename = "\\" + java.util.UUID.randomUUID().toString() + ".txt";
            try {
                // TODO - this doesn't work as the source needs to be a local file
                return processLogs(filename, importer, LogType.MOD_SECURITY_2, trimmed);
            } catch (Exception ex) {
                String errMessage = "Failed - " + ex.getMessage();
                return new ApiResponseElement(
                        "Parsing audit event log to ZAPs site tree", errMessage);
            }
        }
        return new ApiResponseElement("Requested Method", "Failed - Method Not Found");
    }

    public static ApiResponseElement processLogsFromFile(
            String filePath, ExtensionImportLogFiles importer, LogType logType) {
        return processLogs(filePath, importer, logType, null);
    }

    /**
     * This method creates a file in the application data folder and streams the input from the ZAP
     * API to it depending on how it receives the data (HTTP POST or direct file reference)
     *
     * @param filePath, in the case of the HTTP POST this is just a guid created from
     *     pre-processing.
     * @param importer
     * @param logType - Either ZAP or ModSec currently
     * @param httpPOSTData - If this is null this signifies to read from the given filePath
     * @return
     */
    private static ApiResponseElement processLogs(
            String filePath,
            ExtensionImportLogFiles importer,
            LogType logType,
            String httpPOSTData) {
        // Not appending the file with client state info as REST should produce a resource based on
        // the request indefinitely.
        String sourceFilePath = filePath;
        String targetfileName =
                sourceFilePath.substring(
                                sourceFilePath.lastIndexOf("\\") + 1,
                                sourceFilePath.lastIndexOf("."))
                        + ".txt";
        String absoluteTargetFilePath = getLoggingStorageDirectory(logType) + "\\" + targetfileName;
        File targetFile = new File(absoluteTargetFilePath);

        if (!targetFile.isFile() /* && !FileAlreadyExists(new File(sourceFilePath)) */) {
            try {
                targetFile.createNewFile();
                // TODO investigate how to check for uniqueness of the file. Potentially hashing
                // (md5) the string[] of the read
                // file. Might be overkill?
                // appendAddedFilesHashes(targetFile);
            } catch (Exception ex) {
                return new ApiResponseElement(
                        "Parsing logs files to ZAPs site tree",
                        "Failed - Could not create file on server");
            }
        } else {
            return new ApiResponseElement(
                    "Parsing logs files to ZAPs site tree", "Not processed - File already added");
        }

        if (httpPOSTData == null) {
            try (BufferedReader br = new BufferedReader(new FileReader(sourceFilePath));
                    BufferedWriter wr = new BufferedWriter(new FileWriter(targetFile))) {
                String sCurrentLine;

                while ((sCurrentLine = br.readLine()) != null) {
                    wr.write(sCurrentLine);
                    wr.newLine();
                }

            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        } else {
            try (FileOutputStream fop = new FileOutputStream(targetFile)) {
                byte[] contentInBytes = httpPOSTData.getBytes();
                fop.write(contentInBytes);
                fop.flush();
            } catch (IOException ex) {
                log.error(ex.getMessage(), ex);
            }
        }

        importer.processInput(targetFile, logType);

        return new ApiResponseElement("Parsing log files to ZAPs site tree", "Suceeded");
    }

    private static ApiResponseElement ProcessRequestResponsePair(
            List<HttpMessage> messages, ExtensionImportLogFiles importer) {
        try {
            importer.addToTree(importer.getHistoryRefs(messages));
            return new ApiResponseElement("Parsing log files to ZAPs site tree", "Suceeded");
        } catch (HttpMalformedHeaderException httpex) {
            String exceptionMessage =
                    String.format(
                            "Parsing log files to ZAPs site tree",
                            "Failed - %s",
                            httpex.getLocalizedMessage());
            return new ApiResponseElement(exceptionMessage);
        } catch (Exception e) {
            String exceptionMessage =
                    String.format(
                            "Parsing log files to ZAPs site tree",
                            "Failed - %s",
                            e.getLocalizedMessage());
            return new ApiResponseElement(exceptionMessage);
        }
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }
}
