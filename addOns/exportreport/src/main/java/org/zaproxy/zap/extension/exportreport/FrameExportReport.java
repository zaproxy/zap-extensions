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
package org.zaproxy.zap.extension.exportreport;

import java.awt.CardLayout;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.SpringLayout;
import javax.swing.border.CompoundBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractFrame;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

@SuppressWarnings("serial")
public class FrameExportReport extends AbstractFrame implements ActionListener {
    private final String FINISH = Constant.messages.getString("exportreport.forward.finish.label");
    private final String NEXT = Constant.messages.getString("exportreport.forward.next.label");
    private ExtensionExportReport extension = null;
    private JPanel pnlCards;
    private JButton btnBack;
    private JButton btnNext;
    private PanelNav pnlNav;
    private int curCard = 0;
    final String PANEL_SOURCE = Constant.messages.getString("exportreport.panel.source.label");
    final String PANEL_RISK = Constant.messages.getString("exportreport.panel.risk.label");
    final String PANEL_DETAILS = Constant.messages.getString("exportreport.panel.details.label");
    final String cardItems[] = {PANEL_SOURCE, PANEL_RISK, PANEL_DETAILS};

    public FrameExportReport(
            ExtensionExportReport extension,
            PanelSource cardSource,
            PanelAlertRisk cardAlertRisk,
            PanelAlertDetails cardAlertDetails) {
        this.extension = extension;
        this.setTitle(Constant.messages.getString("exportreport.menu.title.label"));
        this.addComponentToPane(this.getContentPane(), cardSource, cardAlertRisk, cardAlertDetails);
    }

    public void addComponentToPane(
            Container contentPane,
            PanelSource cardSource,
            PanelAlertRisk cardAlertRisk,
            PanelAlertDetails cardAlertDetails) {

        SpringLayout sl_contentPane = new SpringLayout();
        contentPane.setLayout(sl_contentPane);

        pnlCards = new JPanel(new CardLayout());
        pnlCards.add(cardSource, PANEL_SOURCE);
        pnlCards.add(cardAlertRisk, PANEL_RISK);
        pnlCards.add(cardAlertDetails, PANEL_DETAILS);

        pnlCards.setBorder(new CompoundBorder()); // -Give the cards panel a border
        sl_contentPane.putConstraint(
                SpringLayout.NORTH, pnlCards, 10, SpringLayout.NORTH, contentPane);
        sl_contentPane.putConstraint(
                SpringLayout.WEST, pnlCards, 10, SpringLayout.WEST, contentPane);
        sl_contentPane.putConstraint(
                SpringLayout.SOUTH, pnlCards, 345, SpringLayout.NORTH, contentPane);
        sl_contentPane.putConstraint(
                SpringLayout.EAST, pnlCards, 370, SpringLayout.WEST, contentPane);
        contentPane.add(pnlCards);

        pnlNav =
                new PanelNav(cardItems.length); // -Use the constructor to initialize the navigation
        // panel.
        sl_contentPane.putConstraint(SpringLayout.NORTH, pnlNav, 20, SpringLayout.SOUTH, pnlCards);
        sl_contentPane.putConstraint(SpringLayout.WEST, pnlNav, 10, SpringLayout.WEST, contentPane);
        sl_contentPane.putConstraint(SpringLayout.SOUTH, pnlNav, 100, SpringLayout.SOUTH, pnlCards);
        sl_contentPane.putConstraint(SpringLayout.EAST, pnlNav, 0, SpringLayout.EAST, pnlCards);

        // Assign buttons from the navigation pane action listeners.
        this.btnBack = pnlNav.getBack();
        this.btnBack.addActionListener(this);
        this.btnNext = pnlNav.getNext();
        this.btnNext.addActionListener(this);

        contentPane.add(pnlNav); // -Add the navigation panel to the content
    }

    private int incCard(int curCard) {
        if (curCard < cardItems.length - 1) curCard = curCard + 1;
        return curCard;
    }

    private int decCard(int curCard) {
        if (curCard > 0) curCard = curCard - 1;
        return curCard;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == btnBack) {
            curCard = decCard(curCard);
            CardLayout cl = (CardLayout) (pnlCards.getLayout());
            cl.show(pnlCards, cardItems[curCard]);
            if (curCard > 0) {
                pnlNav.setProgress(curCard + 1);
                btnNext.setText(NEXT);
            } else {
                pnlNav.setProgress(1);
                btnBack.setEnabled(false);
            }
        }
        if (e.getSource() == this.btnNext) {
            if (FINISH.equals(btnNext.getText())) {
                extension.generateReport();
            }

            curCard = incCard(curCard);

            CardLayout cl = (CardLayout) (pnlCards.getLayout());
            cl.show(pnlCards, cardItems[curCard]);
            if (curCard < (cardItems.length - 1)) {
                pnlNav.setProgress(curCard + 1);
                btnBack.setEnabled(true);
            } else {
                pnlNav.setProgress(cardItems.length);
                btnNext.setText(FINISH);
            }
        }
    }
}
