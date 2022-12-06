/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.revisit;

import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class RevisitDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = LogManager.getLogger(RevisitDialog.class);

    private JPanel jPanel;
    private JButton resetButton;
    private JButton cancelButton;
    private JButton okButton;

    private final int[] DATE_FIELDS = {
        Calendar.YEAR,
        Calendar.MONTH,
        Calendar.DAY_OF_MONTH,
        Calendar.HOUR,
        Calendar.MINUTE,
        Calendar.SECOND
    };

    private final String[] HEADER_FIELDS = {"year", "month", "day", "hour", "minute", "second"};

    private final int[] FIELD_SIZES = {4, 2, 2, 2, 2, 2};

    private final String[] DATE_SEPARATORS = {"/", "/", " ", ":", ":", ""};

    private JLabel header;
    /* Fields for the start date/time as per DATE_FIELDS */
    private ZapTextField[] startFields = new ZapTextField[DATE_FIELDS.length];
    /* Fields for the end date/time as per DATE_FIELDS */
    private ZapTextField[] endFields = new ZapTextField[DATE_FIELDS.length];
    private ExtensionRevisit extension;
    private SiteNode sn;
    private Date startTime;
    private Date endTime;

    /** @throws HeadlessException */
    public RevisitDialog(ExtensionRevisit extension) throws HeadlessException {
        super();
        this.extension = extension;
        this.setAlwaysOnTop(true);
        init();
    }

    /**
     * @param arg0
     * @param arg1
     * @throws HeadlessException
     */
    public RevisitDialog(ExtensionRevisit extension, Frame arg0, boolean arg1)
            throws HeadlessException {
        super(arg0, arg1);
        this.extension = extension;
        this.setAlwaysOnTop(true);
        init();
    }

    /** This method initializes this */
    private void init() {
        this.setContentPane(getJPanel());
        this.pack();

        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(400, 185);
        }
    }

    public void init(SiteNode sn, Date startTime, Date endTime) {
        this.sn = sn;
        this.startTime = startTime;
        this.endTime = endTime;

        getHeader()
                .setText(
                        Constant.messages.getString(
                                "revisit.dialog.header.site",
                                ExtensionRevisit.getSiteForURL(sn.getHierarchicNodeName())));

        Calendar startCal = Calendar.getInstance();
        startCal.setTime(startTime);

        Calendar endCal = Calendar.getInstance();
        endCal.setTime(endTime);

        boolean disable = true;
        for (int i = 0; i < DATE_FIELDS.length; i++) {
            this.getStartField(i, FIELD_SIZES[i])
                    .setText(
                            String.format(
                                    "%0" + FIELD_SIZES[i] + "d", startCal.get(DATE_FIELDS[i])));

            this.getEndField(i, FIELD_SIZES[i])
                    .setText(
                            String.format("%0" + FIELD_SIZES[i] + "d", endCal.get(DATE_FIELDS[i])));

            if (disable && startCal.get(DATE_FIELDS[i]) == endCal.get(DATE_FIELDS[i])) {
                // Disable any fields that have the same value - no point in changing them
                this.getStartField(i, FIELD_SIZES[i]).setEnabled(false);
                this.getEndField(i, FIELD_SIZES[i]).setEnabled(false);

            } else {
                disable = false;
            }
        }
        getOkButton().setEnabled(true);
    }
    /**
     * This method initializes jPanel
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel() {
        if (jPanel == null) {
            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());

            jPanel.add(getHeader(), LayoutHelper.getGBC(0, 0, 2, 1.0D, 0.0D));

            JPanel headerPanel = new JPanel();
            headerPanel.setLayout(new GridBagLayout());
            int x = 0;
            for (int i = 0; i < DATE_FIELDS.length; i++) {
                ZapTextField ztf = new ZapTextField(FIELD_SIZES[i]);
                ztf.setText(
                        Constant.messages.getString("revisit.dialog.header." + HEADER_FIELDS[i]));
                ztf.setEnabled(false);
                headerPanel.add(ztf, LayoutHelper.getGBC(x++, 0, 1, 0.0D, 0.0D));
                headerPanel.add(
                        new JLabel(DATE_SEPARATORS[i]), LayoutHelper.getGBC(x++, 0, 1, 0.0D, 0.0D));
            }
            jPanel.add(new JLabel(""), LayoutHelper.getGBC(0, 1, 1, 1.0D, 0.0D));
            jPanel.add(headerPanel, LayoutHelper.getGBC(1, 1, 1, 0.0D, 0.0D));

            JPanel startPanel = new JPanel();
            startPanel.setLayout(new GridBagLayout());
            x = 0;
            for (int i = 0; i < DATE_FIELDS.length; i++) {
                startPanel.add(
                        this.getStartField(i, FIELD_SIZES[i]),
                        LayoutHelper.getGBC(x++, 0, 1, 0.0D, 0.0D));
                startPanel.add(
                        new JLabel(DATE_SEPARATORS[i]), LayoutHelper.getGBC(x++, 0, 1, 0.0D, 0.0D));
            }
            jPanel.add(
                    new JLabel(Constant.messages.getString("revisit.dialog.start.label")),
                    LayoutHelper.getGBC(0, 2, 1, 1.0D, 0.0D));
            jPanel.add(startPanel, LayoutHelper.getGBC(1, 2, 1, 0.0D, 0.0D));

            JPanel endPanel = new JPanel();
            endPanel.setLayout(new GridBagLayout());
            x = 0;
            for (int i = 0; i < DATE_FIELDS.length; i++) {
                endPanel.add(
                        this.getEndField(i, FIELD_SIZES[i]),
                        LayoutHelper.getGBC(x++, 0, 1, 0.0D, 0.0D));
                endPanel.add(
                        new JLabel(DATE_SEPARATORS[i]), LayoutHelper.getGBC(x++, 0, 1, 0.0D, 0.0D));
            }
            jPanel.add(
                    new JLabel(Constant.messages.getString("revisit.dialog.end.label")),
                    LayoutHelper.getGBC(0, 3, 1, 1.0D, 0.0D));
            jPanel.add(endPanel, LayoutHelper.getGBC(1, 3, 1, 0.0D, 0.0D));

            JPanel buttonPanel = new JPanel();
            buttonPanel.setLayout(new GridBagLayout());
            buttonPanel.add(new JLabel(), LayoutHelper.getGBC(0, 0, 1, 1.0D, 0.0D)); // Spacer
            buttonPanel.add(getCancelButton(), LayoutHelper.getGBC(1, 0, 1, 0.0D, 0.0D));
            buttonPanel.add(getResetButton(), LayoutHelper.getGBC(2, 0, 1, 0.0D, 0.0D));
            buttonPanel.add(getOkButton(), LayoutHelper.getGBC(3, 0, 1, 0.0D, 0.0D));

            jPanel.add(buttonPanel, LayoutHelper.getGBC(0, 5, 2, 1.0D, 0.0D));
        }
        return jPanel;
    }

    private JLabel getHeader() {
        if (header == null) {
            header = new JLabel();
        }
        return header;
    }

    private ZapTextField getStartField(final int id, int size) {
        if (startFields[id] == null) {
            startFields[id] = new ZapTextField(size);
            startFields[id].addKeyListener(
                    new KeyListener() {
                        @Override
                        public void keyTyped(KeyEvent e) {}

                        @Override
                        public void keyPressed(KeyEvent e) {}

                        @Override
                        public void keyReleased(KeyEvent e) {
                            validateField(startFields[id]);
                        }
                    });
        }
        return startFields[id];
    }

    private void validateField(ZapTextField field) {
        if (field.getText().length() > field.getColumns()) {
            getOkButton().setEnabled(false);
            return;
        }
        try {
            getStartCal();
            getOkButton().setEnabled(true);
        } catch (Exception e1) {
            getOkButton().setEnabled(false);
        }
    }

    private ZapTextField getEndField(final int id, int size) {
        if (endFields[id] == null) {
            endFields[id] = new ZapTextField(size);
            endFields[id].addKeyListener(
                    new KeyListener() {
                        @Override
                        public void keyTyped(KeyEvent e) {}

                        @Override
                        public void keyPressed(KeyEvent e) {}

                        @Override
                        public void keyReleased(KeyEvent e) {
                            validateField(endFields[id]);
                        }
                    });
        }
        return endFields[id];
    }

    private Calendar getStartCal() {
        Calendar startCal = new GregorianCalendar();
        startCal.setTime(startTime);
        // Update with any user changes
        for (int i = 0; i < DATE_FIELDS.length; i++) {
            startCal.set(
                    DATE_FIELDS[i],
                    Integer.parseInt(this.getStartField(i, FIELD_SIZES[i]).getText()));
        }
        return startCal;
    }

    private Calendar getEndCal() {
        Calendar endCal = new GregorianCalendar();
        endCal.setTime(endTime);
        // Update with any user changes
        for (int i = 0; i < DATE_FIELDS.length; i++) {
            endCal.set(
                    DATE_FIELDS[i],
                    Integer.parseInt(this.getEndField(i, FIELD_SIZES[i]).getText()));
        }
        return endCal;
    }

    public void saveAndClose() {
        try {
            extension.setEnabledForSite(sn, getStartCal().getTime(), getEndCal().getTime());
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }

        RevisitDialog.this.dispose();
    }

    private JButton getOkButton() {
        if (okButton == null) {
            okButton = new JButton();
            okButton.setText(Constant.messages.getString("all.button.ok"));
            okButton.addActionListener(e -> saveAndClose());
        }
        return okButton;
    }

    private JButton getCancelButton() {
        if (cancelButton == null) {
            cancelButton = new JButton();
            cancelButton.setText(Constant.messages.getString("all.button.cancel"));
            cancelButton.addActionListener(e -> RevisitDialog.this.dispose());
        }
        return cancelButton;
    }

    private JButton getResetButton() {
        if (resetButton == null) {
            resetButton = new JButton();
            resetButton.setText(Constant.messages.getString("revisit.dialog.button.reset"));
            resetButton.addActionListener(e -> RevisitDialog.this.init(sn, startTime, endTime));
        }
        return resetButton;
    }
    /*
    private class LimitedIntField extends ZapTextField {
    	private static final long serialVersionUID = 1L;
    	private int limit;

    	public LimitedIntField(int limit) {
    		super(limit);
    		this.limit = limit;
    		this.i
    	}

    	public void insertString( int offset, String  str, AttributeSet attr ) throws BadLocationException {
    	    if (str == null) return;

    	    if ((getText().length() + str.length()) <= limit) {
    	      super.insertString(offset, str, attr);
    	    }
    	  }

    }
    */
}
