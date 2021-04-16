/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import java.lang.reflect.Method;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;

public class JobUtils {

    public static AttackStrength parseAttackStrength(
            Object o, String jobName, AutomationProgress progress) {
        AttackStrength strength = null;
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            try {
                strength = AttackStrength.valueOf(((String) o).toUpperCase());
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString("automation.error.ascan.strength", jobName, o));
            }
        } else {
            progress.warn(
                    Constant.messages.getString("automation.error.ascan.strength", jobName, o));
        }
        return strength;
    }

    public static AlertThreshold parseAlertThreshold(
            Object o, String jobName, AutomationProgress progress) {
        AlertThreshold threshold = null;
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            try {
                threshold = AlertThreshold.valueOf(((String) o).toUpperCase());
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.ascan.threshold", jobName, o));
            }
        } else if (o instanceof Boolean && (!(Boolean) o)) {
            // This will happen if OFF is not quoted
            threshold = AlertThreshold.OFF;
        } else {
            progress.warn(
                    Constant.messages.getString("automation.error.ascan.threshold", jobName, o));
        }
        return threshold;
    }

    public static Object getJobOptions(AutomationJob job, AutomationProgress progress) {
        Object obj = job.getParamMethodObject();
        String optionsGetterName = job.getParamMethodName();
        if (obj != null && optionsGetterName != null) {
            try {
                Method method = obj.getClass().getDeclaredMethod(optionsGetterName);
                method.setAccessible(true);
                return method.invoke(obj);
            } catch (Exception e1) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.options.methods",
                                obj.getClass().getCanonicalName(),
                                optionsGetterName,
                                e1.getMessage()));
                return null;
            }
        }
        return null;
    }
}
