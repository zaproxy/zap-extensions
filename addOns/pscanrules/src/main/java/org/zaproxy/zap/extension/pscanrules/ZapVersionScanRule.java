/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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

import java.lang.reflect.Field;
import java.time.LocalDate;
import java.time.Period;
import java.time.YearMonth;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.Version;
import org.zaproxy.zap.extension.autoupdate.ExtensionAutoUpdate;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ZapVersionScanRule extends PluginPassiveScanner implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.zapversion.";

    private static final int PLUGIN_ID = 10116;

    private static final Logger LOGGER = LogManager.getLogger(ZapVersionScanRule.class);

    /** Used to make sure we only raise one alert per host. */
    private static Set<String> hosts = new HashSet<>();

    private static String latestVersionStr;
    private static Integer risk;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        try {
            if (Constant.isSilent() && !hasLatestVersionInfo()) {
                return;
            }
            int risk = getRisk();
            if (risk <= 0) {
                return;
            }
            String host = msg.getRequestHeader().getURI().getHost();
            synchronized (hosts) {
                if (hosts.contains(host)) {
                    return;
                }
                hosts.add(host);
            }
            buildAlert(risk, getLatestVersionStr()).raise();
        } catch (Exception e) {
            LOGGER.debug(e.getMessage(), e);
        }
    }

    private int getRisk() {
        if (risk != null) {
            return risk;
        }
        if (Constant.isDevBuild()) {
            // Assume the user is keeping this up to date
            risk = -1;
            return risk;
        }

        if (Constant.isDailyBuild()) {
            risk = getDateRisk(Constant.PROGRAM_VERSION, LocalDate.now());
            return risk;
        }

        String latestVersion = getLatestVersionStr();
        if (latestVersion == null) {
            // No CFU req yet, might be done next time?
            return -1;
        }
        risk = getVersionRisk(Constant.PROGRAM_VERSION, latestVersion);
        return risk;
    }

    /**
     * Returns the risk based on 2 semantic version strings like "2.16.1"
     *
     * @param currentVer the version of ZAP being run
     * @param latestVer the latest ZAP version based on the Check For Updates call
     * @return the risk, where <= 0: no risk, 1: low, 2: medium, 3: high
     */
    protected static int getVersionRisk(String currentVer, String latestVer) {
        try {
            Version cv = new Version(currentVer);
            Version lv = new Version(latestVer);

            if (cv.getMajorVersion() == lv.getMajorVersion()) {
                // Easy case, no major version difference
                return intToRisk(lv.getMinorVersion() - cv.getMinorVersion(), 0);
            }
            if (lv.getMajorVersion() - cv.getMajorVersion() > 1) {
                // 2+ major version differences
                return Alert.RISK_HIGH;
            }
            // 1 major version difference, always min of medium risk
            return intToRisk(lv.getMinorVersion(), Alert.RISK_MEDIUM);
        } catch (Exception e) {
            LOGGER.debug(e.getMessage(), e);
            return -1;
        }
    }

    private static int intToRisk(int i, int minRisk) {
        if (i < minRisk) {
            return minRisk;
        }
        if (i > Alert.RISK_HIGH) {
            return Alert.RISK_HIGH;
        }
        return i;
    }

    /**
     * Returns the risk based on 1 date-stamped version string like "D-2025-06-30"
     *
     * @param currentVer the date-stamped version of ZAP being run
     * @param today todays date (makes testing so much easier)
     * @return the risk, where <= 0: no risk, 1: low, 2: medium, 3: high
     */
    protected static int getDateRisk(String currentVer, LocalDate today) {
        if (currentVer == null || !currentVer.startsWith("D-")) {
            return -1;
        }
        YearMonth yearMonth = YearMonth.parse(currentVer.substring(2, 9));
        LocalDate pastDate = yearMonth.atDay(1);
        return diffToRisk(Period.between(pastDate, today).getYears());
    }

    private static int diffToRisk(int diff) {
        if (diff > Alert.RISK_HIGH) {
            return Alert.RISK_HIGH;
        }
        return diff;
    }

    private static String getLatestVersionStr() {
        if (latestVersionStr == null) {
            ExtensionAutoUpdate ext =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAutoUpdate.class);

            if (ext != null) {
                try {
                    Object ver = MethodUtils.invokeMethod(ext, true, "getLatestVersionNumber");

                    latestVersionStr = (String) ver;
                } catch (Exception e) {
                    LOGGER.debug(e.getMessage(), e);
                }
            }
        }
        return latestVersionStr;
    }

    private static boolean hasLatestVersionInfo() {
        ExtensionAutoUpdate ext =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutoUpdate.class);

        if (ext != null) {
            try {
                Field f = ext.getClass().getDeclaredField("latestVersionInfo");
                f.setAccessible(true);
                return f.get(ext) != null;
            } catch (Exception e) {
                LOGGER.debug(e.getMessage(), e);
            }
        }
        return false;
    }

    private AlertBuilder buildAlert(int risk, String latest) {
        AlertBuilder ab =
                newAlert()
                        .setRisk(risk)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                        .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                        .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                        .setCweId(1104) // CWE-1104: Use of Unmaintained Third Party Components
                        .setWascId(45); // WASC-45: Application Misconfiguration
        if (latest != null) {
            ab.setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", latest));
        }

        return ab;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert(Alert.RISK_MEDIUM, null).build());
    }

    protected static void clear() {
        hosts.clear();
    }
}
