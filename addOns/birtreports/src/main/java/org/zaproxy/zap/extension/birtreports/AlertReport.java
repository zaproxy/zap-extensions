/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.birtreports;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;

public class AlertReport implements IAlertReport {
    // implement the interface to add functionality to the class and create a sample report to
    // demonstrate the functionality of the scripted data source.
    private SiteNode site;
    public List<Alert> alerts;
    public int Size;

    public int getSize() {
        // return the alerts size count
        return site.getAlerts().size();
    }

    public AlertReport() {
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        site = siteMap.getRoot();
    }

    @Override
    public AlertReport getAlertsReport() {
        AlertReport report = new AlertReport();
        this.alerts = site.getAlerts();
        // this.Size = alerts.size();
        return report;
    }

    public List<Alert> sortAndGroupAlerts(int countTotal) {
        List<Alert> temp = new ArrayList<>();
        List<Alert> sortAlerts = new ArrayList<>();
        int count = 1;
        int newid = 0;
        int oldid = 0;
        List<Alert> alerts = this.alerts;

        if (alerts.isEmpty()) return temp;

        int size = alerts.size();

        for (int i = 0; i < size; i++) {
            System.out.println("Plugin ID Before Sorting: " + alerts.get(i).getPluginId());
        }

        for (int i = 0; i < size; i++) {

            for (int j = size - 1; j >= (i + 1); j--) {
                if (alerts.get(j).getPluginId() < alerts.get(j - 1).getPluginId()) {
                    Alert tempAlert = alerts.get(j);
                    alerts.set(j, alerts.get(j - 1));
                    alerts.set(j - 1, tempAlert);
                }
            }
        }

        for (int i = 0; i < size; i++) {
            System.out.println("Plugin ID After sorting: " + alerts.get(i).getPluginId());
        }

        oldid = alerts.get(0).getPluginId();
        for (Alert alert : alerts) {
            if (alert.getConfidence() != Alert.CONFIDENCE_FALSE_POSITIVE) {

                newid = alert.getPluginId();
                if (newid == oldid & count > countTotal) {
                    oldid = newid;
                    continue;
                }

                if (newid == oldid & count <= countTotal) count++;

                if (newid != oldid) {
                    count = 2; // because the first alert will be added in this iteration
                }

                // add alert into a container
                temp.add(alert);
                oldid = newid;
            } // end if
        } // end for-loop

        return temp;
    }
}
