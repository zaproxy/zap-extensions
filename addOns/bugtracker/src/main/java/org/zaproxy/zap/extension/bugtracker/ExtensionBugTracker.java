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

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;

/** A ZAP Extension to help user raise issues in bug trackers from within ZAP. */
public class ExtensionBugTracker extends ExtensionAdaptor {

    public static final String NAME = "ExtensionBugTracker";

    protected static final String PREFIX = "bugtracker";

    private List<BugTracker> bugTrackers = new ArrayList<>();
    private PopupSemiAutoIssue popupMsgRaiseSemiAuto;

    public ExtensionBugTracker() {
        super(NAME);
    }

    public void addBugTracker(BugTracker bugTracker) {
        bugTrackers.add(bugTracker);
    }

    public List<BugTracker> getBugTrackers() {
        return bugTrackers;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        BugTrackerGithub githubTracker = new BugTrackerGithub();
        extensionHook.addOptionsParamSet(githubTracker.getOptions());
        BugTrackerBugzilla bugzillaTracker = new BugTrackerBugzilla();
        extensionHook.addOptionsParamSet(bugzillaTracker.getOptions());

        if (getView() != null) {
            addBugTracker(githubTracker);
            addBugTracker(bugzillaTracker);
            View.getSingleton()
                    .getOptionsDialog("")
                    .addParamPanel(
                            new String[] {Constant.messages.getString("bugtracker.name")},
                            githubTracker.getOptionsPanel(),
                            true);
            View.getSingleton()
                    .getOptionsDialog("")
                    .addParamPanel(
                            new String[] {Constant.messages.getString("bugtracker.name")},
                            bugzillaTracker.getOptionsPanel(),
                            true);
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgRaiseSemiAuto());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (hasView()) {
            bugTrackers.forEach(
                    bugTracker ->
                            View.getSingleton()
                                    .getOptionsDialog("")
                                    .removeParamPanel(bugTracker.getOptionsPanel()));
        }
    }

    private PopupSemiAutoIssue getPopupMsgRaiseSemiAuto() {
        if (popupMsgRaiseSemiAuto == null) {
            popupMsgRaiseSemiAuto =
                    new PopupSemiAutoIssue(
                            this, Constant.messages.getString(PREFIX + ".popup.issue.semi"));
        }
        return popupMsgRaiseSemiAuto;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("bugtracker.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
