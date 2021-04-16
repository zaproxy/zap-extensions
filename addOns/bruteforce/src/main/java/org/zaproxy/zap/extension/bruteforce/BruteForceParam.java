/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.bruteforce;

import com.sittinglittleduck.DirBuster.Config;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.parosproxy.paros.common.AbstractParam;

public class BruteForceParam extends AbstractParam {

    private static final String THREAD_PER_SCAN = "bruteforce.threadPerHost";
    private static final String DEFAULT_FILE = "bruteforce.defaultFile";
    private static final String RECURSIVE = "bruteforce.recursive";
    private static final String BROWSE_FILES = "bruteforce.browsefiles";
    private static final String BROWSE_FILES_WITHOUT_EXTENSION =
            "bruteforce.browsefileswithoutextension";
    private static final String FILE_EXTENSIONS = "bruteforce.fileextensions";
    private static final String EXTENSIONS_TO_MISS = "bruteforce.extensionsToMiss";
    private static final String FAIL_CASE_STRING = "bruteforce.failCaseString";

    public static final int DEFAULT_THREAD_PER_SCAN = 10;
    public static final int MAXIMUM_THREADS_PER_SCAN = 200;
    public static final boolean DEFAULT_RECURSIVE = true;
    public static final boolean DEFAULT_BROWSE_FILES = false;
    public static final boolean DEFAULT_BROWSE_FILES_WITHOUT_EXTENSION = false;
    public static final String EMPTY_STRING = "";
    public static final String DEFAULT_EXTENSIONS_TO_MISS = "jpg, gif, jpeg, ico, tiff, png, bmp";
    public static final String DEFAULT_FAIL_CASE_STRING = Config.failCaseString;

    private int threadPerScan = DEFAULT_THREAD_PER_SCAN;
    private boolean recursive = DEFAULT_RECURSIVE;
    private ForcedBrowseFile defaultFile = null;
    private boolean browseFiles = DEFAULT_BROWSE_FILES;
    private boolean browseFilesWithoutExtension = DEFAULT_BROWSE_FILES_WITHOUT_EXTENSION;
    // can't be null
    private String fileExtensions = EMPTY_STRING;
    private String extensionsToMiss = DEFAULT_EXTENSIONS_TO_MISS;
    private String failCaseString = DEFAULT_FAIL_CASE_STRING;

    public BruteForceParam() {}

    @Override
    protected void parse() {
        try {
            this.threadPerScan = getConfig().getInt(THREAD_PER_SCAN, DEFAULT_THREAD_PER_SCAN);
            this.recursive = getConfig().getBoolean(RECURSIVE, DEFAULT_RECURSIVE);
            this.browseFiles = getConfig().getBoolean(BROWSE_FILES, DEFAULT_BROWSE_FILES);
            this.browseFilesWithoutExtension =
                    getConfig()
                            .getBoolean(
                                    BROWSE_FILES_WITHOUT_EXTENSION,
                                    DEFAULT_BROWSE_FILES_WITHOUT_EXTENSION);
            this.fileExtensions = getConfig().getString(FILE_EXTENSIONS, EMPTY_STRING);
            this.extensionsToMiss =
                    getConfig().getString(EXTENSIONS_TO_MISS, DEFAULT_EXTENSIONS_TO_MISS);
            this.failCaseString = getConfig().getString(FAIL_CASE_STRING, DEFAULT_FAIL_CASE_STRING);
        } catch (Exception e) {
        }

        String path = getString(DEFAULT_FILE, "");
        if (!"".equals(path)) {
            this.defaultFile = new ForcedBrowseFile(new File(path));
        } else {
            this.defaultFile = null;
        }
    }

    public int getThreadPerScan() {
        return threadPerScan;
    }

    public void setThreadPerScan(int threadPerHost) {
        this.threadPerScan = threadPerHost;
        getConfig().setProperty(THREAD_PER_SCAN, Integer.toString(this.threadPerScan));
    }

    public boolean getRecursive() {
        return recursive;
    }

    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
        getConfig().setProperty(RECURSIVE, Boolean.toString(this.recursive));
    }

    protected ForcedBrowseFile getDefaultFile() {
        return defaultFile;
    }

    protected void setDefaultFile(ForcedBrowseFile defaultFile) {
        this.defaultFile = defaultFile;

        String absolutePath = "";
        if (defaultFile != null) {
            absolutePath = defaultFile.getFile().getAbsolutePath();
        }

        getConfig().setProperty(DEFAULT_FILE, absolutePath);
    }

    public boolean isBrowseFilesWithoutExtension() {
        return browseFilesWithoutExtension;
    }

    public void setBrowseFilesWithoutExtension(boolean browseFilesWithoutExtension) {
        this.browseFilesWithoutExtension = browseFilesWithoutExtension;
        getConfig().setProperty(BROWSE_FILES_WITHOUT_EXTENSION, browseFilesWithoutExtension);
    }

    public boolean isBrowseFiles() {
        return browseFiles;
    }

    public void setBrowseFiles(boolean browseFiles) {
        this.browseFiles = browseFiles;
        getConfig().setProperty(BROWSE_FILES, browseFiles);
    }

    /**
     * Define a comma-separated list of file extensions for resources to be brute forced.
     *
     * <p>This method returns an empty string if extensions haven't been defined
     *
     * @return comma-separated list of file extensions.
     */
    public String getFileExtensions() {
        return fileExtensions;
    }

    /**
     * Define a comma-separated list of file extensions for resources to be brute forced
     *
     * @param fileExtensions file extensions string
     * @throws IllegalArgumentException if {@code fileExtensions} is {@code null}
     */
    public void setFileExtensions(String fileExtensions) {
        if (fileExtensions == null) {
            throw new IllegalArgumentException("fileExtensions is null");
        }

        this.fileExtensions = fileExtensions;
        getConfig().setProperty(FILE_EXTENSIONS, fileExtensions);
    }

    /**
     * Returns a list of file extensions to be force browsed
     *
     * @return list of force browse file extensions, or an empty list in case no extensions have
     *     been defined.
     */
    public List<String> getFileExtensionsList() {
        if (fileExtensions.trim().equals(EMPTY_STRING)) {
            return Collections.emptyList();
        }

        List<String> fileExtensionsList = new ArrayList<>();
        for (String fileExtension : fileExtensions.replaceAll("\\s", EMPTY_STRING).split(",")) {
            if (!fileExtension.equals(EMPTY_STRING)) {
                fileExtensionsList.add(fileExtension);
            }
        }

        return fileExtensionsList;
    }

    /**
     * @return {@code String} of comma-separated file-extensions that are ignored. URIs ending with
     *     these extensions are ignored from making requests to the server. {@link
     *     #DEFAULT_EXTENSIONS_TO_MISS} is returned by default
     */
    String getExtensionsToMiss() {
        return extensionsToMiss;
    }

    /**
     * Define a {@code String} of comma-separated file-extensions for resources to ignore
     *
     * @param extensionsToMiss file-extensions string
     * @throws IllegalArgumentException if {@code extensionsToMiss} is {@code null}
     */
    void setExtensionsToMiss(String extensionsToMiss) {
        if (extensionsToMiss == null) {
            throw new IllegalArgumentException("extensionsToMiss is null");
        }

        this.extensionsToMiss = extensionsToMiss;
        getConfig().setProperty(EXTENSIONS_TO_MISS, extensionsToMiss);
    }

    /**
     * @return {@code Set} of file extensions that are ignored. URIs ending with these extensions
     *     are ignored from making requests to the server. By default returned {@code Set} will
     *     contain following extensions, {@link #DEFAULT_EXTENSIONS_TO_MISS}
     */
    Set<String> getExtensionsToMissSet() {
        if (extensionsToMiss.trim().equals(EMPTY_STRING)) {
            return new HashSet<>();
        }
        String[] tempArray = extensionsToMiss.replaceAll("\\s", EMPTY_STRING).split(",");
        Set<String> tempSet = new HashSet<>(Arrays.asList(tempArray));
        tempSet.remove(EMPTY_STRING);
        return tempSet;
    }

    String getFailCaseString() {
        return failCaseString;
    }

    void setFailCaseString(String failCaseString) {
        if (failCaseString == null) {
            throw new IllegalArgumentException("failCaseString is null");
        }
        if (failCaseString.isEmpty()) {
            throw new IllegalArgumentException("failCaseString is empty");
        }
        Config.failCaseString = failCaseString;
        this.failCaseString = failCaseString;
        getConfig().setProperty(FAIL_CASE_STRING, failCaseString);
    }
}
