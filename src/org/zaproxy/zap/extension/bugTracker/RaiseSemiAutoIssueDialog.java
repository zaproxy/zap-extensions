/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 sanchitlucknow@gmail.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.bugTracker;

import java.awt.Frame;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.utils.ZapTextField;
 
import org.zaproxy.zap.view.StandardFieldsDialog;
import java.awt.Dimension;
import java.util.HashSet;

public class RaiseSemiAutoIssueDialog extends StandardFieldsDialog {

	private static final long serialVersionUID = -3223449799557586758L;

	private ExtensionBugTracker extension = null;
	private ZapTextField txtFind = null;
    
	protected static final String PREFIX = "bugTracker";
    private String[] bugTrackers = {"github","bugzilla"/*,"jira","atlassan"*/};
    private BugTrackerGithubIssue githubIssue;
    private BugTrackerBugzillaIssue bugzillaIssue;
    private HashSet<Alert> alerts = null;

    public RaiseSemiAutoIssueDialog(ExtensionBugTracker ext, Frame owner, Dimension dim){
        super(owner, "bugTracker.dialog.semi.title", dim,
                new String[] {
                                "bugTracker.trackers.github.tab",
                                "bugTracker.trackers.bugzilla.tab",
                                // "bugTracker.trackers.jira.tab",
                                // "bugTracker.trackers.atlassan.tab"
                            });
        this.extension = ext;
        this.alerts = ext.alerts;
        // System.out.println(this.alerts[0].getName());
 		initialize();
    }

    public void setAlert(HashSet<Alert> alerts) {
    	this.alerts = alerts;
    	initialize();
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
		this.removeAllFields();
        this.setTitle(Constant.messages.getString("bugTracker.popup.issue.semi"));
        int bugTrackerCount = bugTrackers.length;
        for(int i = 0; i < bugTrackerCount; i++ ) {
        	if(bugTrackers[i].equals("github")){
        		githubIssue = new BugTrackerGithubIssue(this, i, alerts);

        	} else if(bugTrackers[i].equals("bugzilla")){
        		bugzillaIssue = new BugTrackerBugzillaIssue(this, i);
        	}
        	// System.out.println(githubIssue);
        }
	}

	@Override
    public String validateFields() {
    	return null;
    }

    public void save() {
    	int bugTrackerCount = bugTrackers.length;
        for(int i = 0; i < bugTrackerCount; i++ ) {
        	if(bugTrackers[i].equals("github")){
        		githubIssue.raise(this);

        	} else if(bugTrackers[i].equals("bugzilla")){
        		// bugzillaIssue = new BugTrackerBugzillaIssue(this, i);
        	}
        	// System.out.println(githubIssue);
        }
    }

}
