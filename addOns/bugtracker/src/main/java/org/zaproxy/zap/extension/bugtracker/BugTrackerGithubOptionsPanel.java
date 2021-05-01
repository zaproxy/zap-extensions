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

import java.awt.BorderLayout;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.bugtracker.BugTrackerGithub.BugTrackerGithubMultipleOptionsPanel;

public class BugTrackerGithubOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private BugTrackerGithubMultipleOptionsPanel githubPanel;

    public BugTrackerGithubOptionsPanel() {
        super();
        setLayout(new BorderLayout());
        this.setName(Constant.messages.getString("bugtracker.trackers.github.tab"));
        githubPanel = new BugTrackerGithubMultipleOptionsPanel(getGithubModel());

        add(githubPanel, BorderLayout.CENTER);
    }

    private BugTrackerGithubTableModel githubModel;

    private BugTrackerGithubTableModel getGithubModel() {
        if (githubModel == null) {
            githubModel = new BugTrackerGithubTableModel();
        }
        return githubModel;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        BugTrackerGithubParam options = optionsParam.getParamSet(BugTrackerGithubParam.class);
        githubModel.setConfigs(options.getConfigs());
    }

    @Override
    public void validateParam(Object obj) throws Exception {}

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        BugTrackerGithubParam options = optionsParam.getParamSet(BugTrackerGithubParam.class);
        options.setConfigs(githubModel.getElements());
    }

    @Override
    public String getHelpIndex() {
        return "addon.bugtracker.bugtracker";
    }
}
