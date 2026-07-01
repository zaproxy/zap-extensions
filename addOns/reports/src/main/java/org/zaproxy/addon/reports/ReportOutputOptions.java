/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import java.awt.event.ItemEvent;
import javax.swing.JCheckBox;
import org.zaproxy.zap.view.StandardFieldsDialog;

/** ZIP and display report output options are mutually exclusive. */
public final class ReportOutputOptions {

    private ReportOutputOptions() {}

    public static boolean resolveDisplay(boolean zipReport, boolean displayReport) {
        return zipReport ? false : displayReport;
    }

    public static boolean bothEnabled(boolean zipReport, boolean displayReport) {
        return zipReport && displayReport;
    }

    public static boolean[] resolveInitialSelection(boolean zipReport, boolean displayReport) {
        if (zipReport && displayReport) {
            return new boolean[] {true, false};
        }
        return new boolean[] {zipReport, displayReport};
    }

    public static void bindMutuallyExclusiveCheckBoxes(
            StandardFieldsDialog dialog, String zipFieldKey, String displayFieldKey) {
        JCheckBox zipCheckBox = (JCheckBox) dialog.getField(zipFieldKey);
        JCheckBox displayCheckBox = (JCheckBox) dialog.getField(displayFieldKey);

        zipCheckBox.addItemListener(
                e -> {
                    if (e.getStateChange() == ItemEvent.SELECTED) {
                        displayCheckBox.setSelected(false);
                    }
                });
        displayCheckBox.addItemListener(
                e -> {
                    if (e.getStateChange() == ItemEvent.SELECTED) {
                        zipCheckBox.setSelected(false);
                    }
                });
    }
}
