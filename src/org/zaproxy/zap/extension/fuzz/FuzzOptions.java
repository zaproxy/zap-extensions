/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.configuration.ConversionException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;

public class FuzzOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = Logger.getLogger(FuzzOptions.class);

    public static final int MAX_THREADS_PER_FUZZER = Constant.MAX_THREADS_PER_SCAN;

    public static final int DEFAULT_THREADS_PER_FUZZER = 5;

    public static final int DEFAULT_FUZZ_DELAY_IN_MS = 0;

    public static final int DEFAULT_RETRIES_ON_IO_ERROR = 3;

    public static final int DEFAULT_MAX_ERRORS_ALLOWED = 25;

    public static final int DEFAULT_MAX_FUZZERS_IN_UI = 5;

    public static final boolean DEFAULT_PROMPT_TO_CLEAR_FINISHED_SCANS = true;

    /**
     * The version of the configurations. Used to keep track of configurations changes between releases, if updates are needed.
     * <p>
     * It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 1;

    /**
     * The base configuration key for all "fuzz" configurations.
     */
    private static final String BASE_KEY = "fuzz";

    private static final String IS_CUSTOM_DEFAULT_CATEGORY_KEY = BASE_KEY + ".isCustomDefaultCategory";
    private static final String DEFAULT_CATEGORY_NAME_KEY = BASE_KEY + ".defaultCategoryName";
    private static final String CUSTOM_FUZZER_LAST_SELECTED_DIRECTORY_KEY = BASE_KEY + ".customFuzzerLastSelectedDirectory";
    private static final String MAX_FINISHED_FUZZERS_IN_UI_KEY = BASE_KEY + ".maxCompletedFuzzersInUI";
    private static final String PROMPT_TO_CLEAR_FINISHED_FUZZERS_KEY = BASE_KEY + ".promptToClearFinishedFuzzers";

    private static final String DEFAULT_RETRIES_ON_IO_ERROR_KEY = BASE_KEY + ".defaultRetriesOnIOError";
    private static final String DEFAULT_MAX_ERRORS_ALLOWED_KEY = BASE_KEY + ".defaultMaxErrorsAllowed";
    private static final String DEFAULT_PAYLOAD_REPLACEMENT_STRATEGY_KEY = BASE_KEY + ".defaultPayloadReplacementStrategy";
    private static final String DEFAULT_THREADS_PER_FUZZER_KEY = BASE_KEY + ".defaultThreadsPerFuzzer";
    private static final String DEFAULT_FUZZ_DELAY_IN_MS_KEY = BASE_KEY + ".defaultFuzzDelayInMs";

    private boolean customCategory;
    private String defaultCategoryName;
    private Path customFuzzerLastSelectedDirectory;
    private int maxFinishedFuzzersInUI;
    private boolean promptToClearFinishedFuzzers;

    private int defaultRetriesOnIOError;
    private int defaultMaxErrorsAllowed;
    private MessageLocationsReplacementStrategy defaultPayloadReplacementStrategy;
    private int defaultThreadsPerFuzzer;
    private int defaultFuzzDelayInMs;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected void parseImpl() {
        try {
            customCategory = getConfig().getBoolean(IS_CUSTOM_DEFAULT_CATEGORY_KEY, false);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + IS_CUSTOM_DEFAULT_CATEGORY_KEY + "':", e);
        }

        try {
            defaultCategoryName = getConfig().getString(DEFAULT_CATEGORY_NAME_KEY, "");
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + DEFAULT_CATEGORY_NAME_KEY + "':", e);
        }

        try {
            customFuzzerLastSelectedDirectory = Paths.get(getConfig().getString(CUSTOM_FUZZER_LAST_SELECTED_DIRECTORY_KEY, ""));
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + CUSTOM_FUZZER_LAST_SELECTED_DIRECTORY_KEY + "':", e);
        }

        try {
            maxFinishedFuzzersInUI = getConfig().getInt(MAX_FINISHED_FUZZERS_IN_UI_KEY, DEFAULT_MAX_FUZZERS_IN_UI);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + MAX_FINISHED_FUZZERS_IN_UI_KEY + "':", e);
        }

        try {
            promptToClearFinishedFuzzers = getConfig().getBoolean(
                    PROMPT_TO_CLEAR_FINISHED_FUZZERS_KEY,
                    DEFAULT_PROMPT_TO_CLEAR_FINISHED_SCANS);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + PROMPT_TO_CLEAR_FINISHED_FUZZERS_KEY + "':", e);
        }

        try {
            defaultRetriesOnIOError = getConfig().getInt(DEFAULT_RETRIES_ON_IO_ERROR_KEY, DEFAULT_RETRIES_ON_IO_ERROR);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + DEFAULT_RETRIES_ON_IO_ERROR_KEY + "':", e);
        }

        try {
            defaultMaxErrorsAllowed = getConfig().getInt(DEFAULT_MAX_ERRORS_ALLOWED_KEY, DEFAULT_MAX_ERRORS_ALLOWED);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + DEFAULT_MAX_ERRORS_ALLOWED_KEY + "':", e);
        }

        try {
            defaultPayloadReplacementStrategy = MessageLocationsReplacementStrategy.getValue(getConfig().getString(
                    DEFAULT_PAYLOAD_REPLACEMENT_STRATEGY_KEY,
                    MessageLocationsReplacementStrategy.DEPTH_FIRST.getConfigId()));
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + DEFAULT_PAYLOAD_REPLACEMENT_STRATEGY_KEY + "':", e);
        }

        try {
            defaultThreadsPerFuzzer = getConfig().getInt(DEFAULT_THREADS_PER_FUZZER_KEY, DEFAULT_THREADS_PER_FUZZER);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + DEFAULT_THREADS_PER_FUZZER_KEY + "':", e);
        }

        try {
            defaultFuzzDelayInMs = getConfig().getInt(DEFAULT_FUZZ_DELAY_IN_MS_KEY, DEFAULT_FUZZ_DELAY_IN_MS);
        } catch (ConversionException e) {
            LOGGER.error("Error while loading '" + DEFAULT_FUZZ_DELAY_IN_MS_KEY + "':", e);
        }
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
        case NO_CONFIG_VERSION:
            // Previously in core. Normalise the name of old options.
            String threadPerScanKey = "fuzzer.threadPerScan";
            try {
                int oldThreadPerScan = getConfig().getInt(threadPerScanKey, DEFAULT_THREADS_PER_FUZZER);
                getConfig().setProperty(DEFAULT_THREADS_PER_FUZZER_KEY, Integer.valueOf(oldThreadPerScan));
            } catch (ConversionException e) {
                LOGGER.warn("Failed to read (old) configuration '" + threadPerScanKey + "', no update will be made.");
            }
            getConfig().clearProperty(threadPerScanKey);

            String defaultCategoryKey = "fuzzer.defaultCategory";
            try {
                String defaultCategory = getConfig().getString(defaultCategoryKey, "");
                getConfig().setProperty(DEFAULT_CATEGORY_NAME_KEY, defaultCategory);
            } catch (ConversionException e) {
                LOGGER.warn("Failed to read (old) configuration '" + defaultCategoryKey + "', no update will be made.");
            }
            getConfig().clearProperty(defaultCategoryKey);

            String dealyInMsKey = "fuzzer.delayInMs";
            try {
                int delayInMs = getConfig().getInt(dealyInMsKey, DEFAULT_FUZZ_DELAY_IN_MS);
                getConfig().setProperty(DEFAULT_FUZZ_DELAY_IN_MS_KEY, Integer.valueOf(delayInMs));
            } catch (ConversionException e) {
                LOGGER.warn("Failed to read (old) configuration '" + dealyInMsKey + "', no update will be made.");
            }
            getConfig().clearProperty(dealyInMsKey);

            String lastSelectedDirectoryKey = "fuzzer.lastSelectedDirectoryAddCustomFile";
            try {
                String lastSelectedDirectory = getConfig().getString(lastSelectedDirectoryKey, "");
                getConfig().setProperty(CUSTOM_FUZZER_LAST_SELECTED_DIRECTORY_KEY, lastSelectedDirectory);
            } catch (ConversionException e) {
                LOGGER.warn("Failed to read (old) configuration '" + lastSelectedDirectoryKey + "', no update will be made.");
            }
            getConfig().clearProperty(lastSelectedDirectoryKey);
        }
    }

    public boolean isCustomDefaultCategory() {
        return customCategory;
    }

    public void setCustomDefaultCategory(boolean custom) {
        if (customCategory == custom) {
            return;
        }
        customCategory = custom;
        getConfig().setProperty(IS_CUSTOM_DEFAULT_CATEGORY_KEY, Boolean.valueOf(customCategory));
    }

    public String getDefaultCategoryName() {
        return defaultCategoryName;
    }

    public void setDefaultCategoryName(String categoryName) {
        if (defaultCategoryName == null) {
            if (categoryName == null) {
                return;
            }
        } else if (defaultCategoryName.equals(categoryName)) {
            return;
        }
        defaultCategoryName = categoryName;
        getConfig().setProperty(DEFAULT_CATEGORY_NAME_KEY, defaultCategoryName);
    }

    public Path getCustomFuzzerLastSelectedDirectory() {
        return customFuzzerLastSelectedDirectory;
    }

    public void setCustomFuzzerLastSelectedDirectory(Path directory) {
        if (directory == null) {
            throw new IllegalArgumentException("Parameter directory must not be null.");
        }
        if (!Files.isDirectory(directory)) {
            throw new IllegalArgumentException("Parameter directory must be a directory.");
        }
        if (customFuzzerLastSelectedDirectory.equals(directory)) {
            return;
        }
        customFuzzerLastSelectedDirectory = directory;
        getConfig().setProperty(
                CUSTOM_FUZZER_LAST_SELECTED_DIRECTORY_KEY,
                customFuzzerLastSelectedDirectory.toAbsolutePath().toString());
    }

    public int getMaxFinishedFuzzersInUI() {
        return maxFinishedFuzzersInUI;
    }

    public void setMaxFinishedFuzzersInUI(int maxFuzzers) {
        if (maxFinishedFuzzersInUI == maxFuzzers) {
            return;
        }
        maxFinishedFuzzersInUI = maxFuzzers;
        getConfig().setProperty(MAX_FINISHED_FUZZERS_IN_UI_KEY, Integer.valueOf(maxFinishedFuzzersInUI));
    }

    public boolean isPromptToClearFinishedFuzzers() {
        return promptToClearFinishedFuzzers;
    }

    public void setPromptToClearFinishedFuzzers(boolean prompt) {
        if (promptToClearFinishedFuzzers == prompt) {
            return;
        }
        promptToClearFinishedFuzzers = prompt;
        getConfig().setProperty(PROMPT_TO_CLEAR_FINISHED_FUZZERS_KEY, Boolean.valueOf(promptToClearFinishedFuzzers));

    }

    public int getDefaultRetriesOnIOError() {
        return defaultRetriesOnIOError;
    }

    public void setDefaultRetriesOnIOError(int retries) {
        if (defaultRetriesOnIOError == retries) {
            return;
        }
        defaultRetriesOnIOError = retries;
        getConfig().setProperty(DEFAULT_RETRIES_ON_IO_ERROR_KEY, Integer.valueOf(defaultRetriesOnIOError));
    }

    public int getDefaultMaxErrorsAllowed() {
        return defaultMaxErrorsAllowed;
    }

    public void setDefaultMaxErrorsAllowed(int maxErrors) {
        if (defaultMaxErrorsAllowed == maxErrors) {
            return;
        }
        this.defaultMaxErrorsAllowed = maxErrors;
        getConfig().setProperty(DEFAULT_MAX_ERRORS_ALLOWED_KEY, Integer.valueOf(defaultMaxErrorsAllowed));
    }

    public MessageLocationsReplacementStrategy getDefaultPayloadReplacementStrategy() {
        return defaultPayloadReplacementStrategy;
    }

    public void setDefaultPayloadReplacementStrategy(MessageLocationsReplacementStrategy strategy) {
        if (strategy == null) {
            throw new IllegalArgumentException("Parameter strategy must not be null.");
        }
        if (defaultPayloadReplacementStrategy.equals(strategy)) {
            return;
        }
        defaultPayloadReplacementStrategy = strategy;
        getConfig().setProperty(DEFAULT_PAYLOAD_REPLACEMENT_STRATEGY_KEY, defaultPayloadReplacementStrategy.getConfigId());
    }

    public int getDefaultThreadsPerFuzzer() {
        return defaultThreadsPerFuzzer;
    }

    public void setDefaultThreadsPerFuzzer(int threads) {
        if (defaultThreadsPerFuzzer == threads) {
            return;
        }
        defaultThreadsPerFuzzer = threads;
        getConfig().setProperty(DEFAULT_THREADS_PER_FUZZER_KEY, Integer.valueOf(defaultThreadsPerFuzzer));

    }

    public int getDefaultFuzzDelayInMs() {
        return defaultFuzzDelayInMs;
    }

    public void setDefaultFuzzDelayInMs(int delayInMs) {
        if (defaultFuzzDelayInMs == delayInMs) {
            return;
        }
        this.defaultFuzzDelayInMs = delayInMs;
        getConfig().setProperty(DEFAULT_FUZZ_DELAY_IN_MS_KEY, Integer.valueOf(defaultFuzzDelayInMs));
    }

}
