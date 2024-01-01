/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import java.awt.Component;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import javax.swing.JPanel;
import org.zaproxy.zap.view.StandardFieldsDialog;

// XXX Remove once the new method is available:
// StandardFieldsDialog.addCustomComponent(int, String, Component, double)
public final class ReflectionUtils {

    private static Method addFieldMethod;
    private static Field tabPanelsField;
    private static Field tabOffsetsField;
    private static Method incTabOffsetMethod;

    static {
        try {
            addFieldMethod =
                    StandardFieldsDialog.class.getDeclaredMethod(
                            "addField",
                            JPanel.class,
                            int.class,
                            String.class,
                            Component.class,
                            Component.class,
                            double.class);
            addFieldMethod.setAccessible(true);

            tabPanelsField = StandardFieldsDialog.class.getDeclaredField("tabPanels");
            tabPanelsField.setAccessible(true);
            tabOffsetsField = StandardFieldsDialog.class.getDeclaredField("tabOffsets");
            tabOffsetsField.setAccessible(true);

            incTabOffsetMethod =
                    StandardFieldsDialog.class.getDeclaredMethod("incTabOffset", int.class);
            incTabOffsetMethod.setAccessible(true);
        } catch (Exception e) {
            // Ignore, defaults to old behaviour if something goes wrong.
        }
    }

    private ReflectionUtils() {}

    @SuppressWarnings("unchecked")
    public static void addCustomComponent(
            StandardFieldsDialog instance,
            int tabIndex,
            String componentLabel,
            Component component,
            double weighty) {
        try {
            addFieldMethod.invoke(
                    instance,
                    ((List<JPanel>) tabPanelsField.get(instance)).get(tabIndex),
                    ((List<Integer>) tabOffsetsField.get(instance)).get(tabIndex),
                    componentLabel,
                    component,
                    component,
                    weighty);
            incTabOffsetMethod.invoke(instance, tabIndex);
        } catch (Exception e) {
            instance.addCustomComponent(tabIndex, componentLabel, component);
            instance.addPadding(tabIndex);
        }
    }
}
