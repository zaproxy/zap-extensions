/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.pscan.internal.scanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import net.htmlparser.jericho.MasonTagTypes;
import net.htmlparser.jericho.MicrosoftConditionalCommentTagTypes;
import net.htmlparser.jericho.PHPTagTypes;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.PassiveScannersManager;
import org.zaproxy.addon.pscan.internal.PassiveScannerOptions;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PassiveScanTaskHelper {

    private static final Logger LOGGER = LogManager.getLogger(PassiveScanTaskHelper.class);

    private static Set<Integer> optedInHistoryTypes = new HashSet<>();

    private volatile boolean shutDown = false;

    private final ExtensionPassiveScan2 extPscan;
    private final ExtensionAlert extAlert;
    private Map<Integer, Integer> alertCounts = new HashMap<>();

    private List<PassiveScanner> activeList = Collections.synchronizedList(new ArrayList<>());
    private List<PassiveScanTask> taskList = Collections.synchronizedList(new ArrayList<>());

    public PassiveScanTaskHelper(ExtensionPassiveScan2 extPscan, ExtensionAlert extensionAlert) {

        if (extensionAlert == null) {
            throw new IllegalArgumentException("Parameter extensionAlert must not be null.");
        }

        this.extPscan = extPscan;
        this.extAlert = extensionAlert;

        MicrosoftConditionalCommentTagTypes.register();
        PHPTagTypes.register();
        // remove PHP short tags otherwise they override processing
        PHPTagTypes.PHP_SHORT.deregister();
        MasonTagTypes.register();
    }

    public void addActivePassiveScanner(PassiveScanner scanner) {
        this.activeList.add(scanner);
    }

    public void removeActivePassiveScanner(PassiveScanner scanner) {
        this.activeList.remove(scanner);
    }

    public synchronized void addTaskToList(PassiveScanTask task) {
        this.taskList.add(task);
    }

    public synchronized void removeTaskFromList(PassiveScanTask task) {
        this.taskList.remove(task);
    }

    public int getTaskListSize() {
        return this.taskList.size();
    }

    public synchronized void shutdownTasks() {
        this.taskList.stream().forEach(PassiveScanTask::shutdown);
    }

    public synchronized PassiveScanTask getOldestRunningTask() {
        for (PassiveScanTask task : this.taskList) {
            if (Boolean.FALSE.equals(task.hasCompleted())) {
                return task;
            }
        }
        return null;
    }

    public synchronized List<PassiveScanTask> getRunningTasks() {
        return this.taskList.stream()
                .filter(task -> Boolean.FALSE.equals(task.hasCompleted()))
                .collect(Collectors.toList());
    }

    public synchronized PassiveScanner getOldestRunningScanner() {
        PassiveScanner scanner;
        for (PassiveScanTask task : this.taskList) {
            if (Boolean.FALSE.equals(task.hasCompleted())) {
                scanner = task.getCurrentScanner();
                if (scanner != null) {
                    return scanner;
                }
            }
        }
        return null;
    }

    PassiveScannersManager getPassiveScanRuleManager() {
        return extPscan.getPassiveScannersManager();
    }

    public int getMaxBodySizeInBytesToScan() {
        return getOptions().getMaxBodySizeInBytesToScan();
    }

    private PassiveScannerOptions getOptions() {
        return extPscan.getModel().getOptionsParam().getParamSet(PassiveScannerOptions.class);
    }

    public void raiseAlert(HistoryReference href, Alert alert) {
        if (shutDown) {
            return;
        }

        alert.setSource(Alert.Source.PASSIVE);
        // Raise the alert
        extAlert.alertFound(alert, href);

        int maxAlertsPerRule = getOptions().getMaxAlertsPerRule();
        if (maxAlertsPerRule > 0) {
            // Theres a limit on how many each rule can raise
            Integer count = alertCounts.get(alert.getPluginId());
            if (count == null) {
                count = Integer.valueOf(0);
            }
            alertCounts.put(alert.getPluginId(), count + 1);
            if (count > maxAlertsPerRule) {
                // Disable the plugin
                PassiveScanner scanner =
                        getPassiveScanRuleManager().getScanRule(alert.getPluginId());
                if (scanner != null) {
                    LOGGER.info(
                            "Disabling passive scan rule {} as it has raised more than {} alerts.",
                            scanner.getName(),
                            maxAlertsPerRule);
                    scanner.setEnabled(false);
                }
            }
        }
    }

    /**
     * Adds the given tag to the specified message.
     *
     * @param tag the name of the tag.
     */
    public void addHistoryTag(HistoryReference href, String tag) {
        if (shutDown) {
            return;
        }

        try {
            if (!href.getTags().contains(tag)) {
                href.addTag(tag);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Add the History Type ({@code int}) to the set of applicable history types.
     *
     * @param type the type to be added to the set of applicable history types
     */
    public static void addApplicableHistoryType(int type) {
        optedInHistoryTypes.add(type);
    }

    /**
     * Remove the History Type ({@code int}) from the set of applicable history types.
     *
     * @param type the type to be removed from the set of applicable history types
     */
    public static void removeApplicableHistoryType(int type) {
        optedInHistoryTypes.remove(type);
    }

    /**
     * Returns the set of History Types which have "opted-in" to be applicable for passive scanning.
     *
     * @return a set of {@code Integer} representing all of the History Types which have "opted-in"
     *     for passive scanning.
     */
    public static Set<Integer> getOptedInHistoryTypes() {
        return Collections.unmodifiableSet(optedInHistoryTypes);
    }

    /**
     * Returns the full set (both default and "opted-in") which are to be applicable for passive
     * scanning.
     *
     * @return a set of {@code Integer} representing all of the History Types which are applicable
     *     for passive scanning.
     */
    public static Set<Integer> getApplicableHistoryTypes() {
        Set<Integer> allApplicableTypes = new HashSet<>();
        allApplicableTypes.addAll(PluginPassiveScanner.getDefaultHistoryTypes());
        if (!optedInHistoryTypes.isEmpty()) {
            allApplicableTypes.addAll(optedInHistoryTypes);
        }
        return allApplicableTypes;
    }
}
