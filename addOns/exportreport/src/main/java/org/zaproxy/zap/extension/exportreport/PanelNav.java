/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport;

import java.awt.GridLayout;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JProgressBar;

import org.parosproxy.paros.Constant;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR:RYERSON UNIVERSITY
 */

@SuppressWarnings("serial")
public class PanelNav extends JPanel {
    private JButton btnBack;
    private JButton btnNext;
    private JProgressBar progressBar;
    private int cardCount;

    public PanelNav(int cardCount) {
        this.cardCount = cardCount;
        initialize();
    }

    private void initialize() {
        this.setLayout(new GridLayout(2, 0, 0, 0)); // -Create a two column grid

        progressBar = new JProgressBar(); // -Create, initialize and setup a progress bar
        progressBar.setValue((100 / cardCount));
        this.add(progressBar); // -Positions the progress bar into the top column
        JPanel navBar = new JPanel(); // -Create a two row grid for navigation buttons
        this.add(navBar);
        navBar.setLayout(new GridLayout(0, 2, 0, 0));

        btnBack = new JButton(Constant.messages.getString("exportreport.previous.back.label")); // -Create the back button and place it into the left row
        btnBack.setEnabled(false);
        navBar.add(btnBack);

        btnNext = new JButton(Constant.messages.getString("exportreport.forward.next.label")); // -Create the next button and place it into the right row
        navBar.add(btnNext);
    }

    void setProgress(int i) // -Setter method accessible from other classes to update the progres bar
    {
        i = i * (100 / cardCount);
        progressBar.setValue(i);
    }

    JProgressBar getProgressBar() // -Retrieve the progress bar
    {
        return progressBar;
    }

    JButton getBack() // -Retrieve the back button
    {
        return btnBack;
    }

    JButton getNext() // -Retrieve the next button
    {
        return btnNext;
    }
}