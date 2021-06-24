/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.bugtracker;

import java.awt.Dimension;
import java.awt.Frame;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class RaiseSemiAutoIssueDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = -3223449799557586758L;

    private ExtensionBugTracker extension = null;
    private List<BugTracker> bugTrackers = null;

    private Set<Alert> alerts = null;
    private String FIELD_TRACKER_LIST = "bugtracker.trackers.list";

    public RaiseSemiAutoIssueDialog(ExtensionBugTracker ext, Frame owner, Dimension dim) {
        super(owner, "bugtracker.dialog.semi.title", dim);
        this.extension = ext;
        bugTrackers = extension.getBugTrackers();
    }

    public void setAlert(Set<Alert> alerts) {
        this.alerts = alerts;
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        this.removeAllFields();
        this.setTitle(Constant.messages.getString("bugtracker.popup.issue.semi"));
        addTrackerList(bugTrackers.get(0).getName());
        updateTrackerFields();
    }

    public void addTrackerList(String value) {
        List<String> trackerNames = new ArrayList<>();
        for (BugTracker bugTracker : bugTrackers) {
            trackerNames.add(bugTracker.getName());
        }
        this.addComboField(FIELD_TRACKER_LIST, trackerNames, value);
        for (BugTracker bugTracker : bugTrackers) {
            bugTracker.setDialog(this);
            bugTracker.setDetails(alerts);
        }
        this.addFieldListener(FIELD_TRACKER_LIST, e -> updateTrackerFields());
    }

    public void updateTrackerFields() {
        String currentItem = this.getStringValue(FIELD_TRACKER_LIST);
        for (BugTracker bugTracker : bugTrackers) {
            if (bugTracker.getName().equals(currentItem)) {
                this.removeAllFields();
                addTrackerList(bugTracker.getName());
                bugTracker.createDialogs();
                revalidate();
                repaint();
            }
        }
    }

    @Override
    public String validateFields() {
        String currentItem = this.getStringValue(FIELD_TRACKER_LIST);
        for (BugTracker bugTracker : bugTrackers) {
            if (bugTracker.getName().equals(currentItem)) {
                String response = bugTracker.raise(this);
                if (response != null) {
                    return response;
                }
                break;
            }
        }
        View.getSingleton().showMessageDialog(Constant.messages.getString("bugtracker.msg.raised"));
        return null;
    }

    @Override
    public void save() {}
}
