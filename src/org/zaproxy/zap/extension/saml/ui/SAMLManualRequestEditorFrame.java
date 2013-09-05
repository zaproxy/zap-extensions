package org.zaproxy.zap.extension.saml.ui;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.saml.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Map;

public class SAMLManualRequestEditorFrame {

    //The UI components
    private JPanel samlEditorPanel;                     //the root panel of the Jframe

    private JTabbedPane tabbedPane1RequestResponse;     //Tabbed pane for request and response
    private JPanel requestPanel;                        //The panel to display the components of request
    private JPanel responsePanel;                       //The panel to display the components of the response

    private JSplitPane responseSplitPane;               //Split pane to divide response head and body
    private JScrollPane responseHeaderScrollPane;
    private JScrollPane responseBodyScrollPane;
    private JTextArea responseHeaderTextArea;           //Text area to display the http headers of the response
    private JTextArea responseBodyTextArea;             //Text area to display the http response body

    private JScrollPane reqAttribScrollPane;            //Scroll pane to give the scrollability to attrib panel

    private JTextArea samlMsgTxtArea;                   //The text area to display the decoded saml message
    private JScrollPane samlMsgScrollPane;              //Scroll pane to give the scrollability to saml msg text area
    private JLabel lblWarningMsg;                       //Label to show the warning text

    private JPanel footerPanel;                         //Panel to hold the items like buttons
    private JButton resendButton;                       //Button to resend the request
    private JButton resetButton;                        //Button to reset the request items

    //Other variables
    private SAMLMessage samlMessage;

    public SAMLManualRequestEditorFrame(HttpMessage message) {
        try {
            samlMessage = new SAMLMessage(message);
        } catch (SAMLException e) {
            //todo show error dialog
        }
    }

    /**
     * Initialize UI components and layouts
     */
    protected void initUIComponents() {
        samlEditorPanel = new JPanel();

        tabbedPane1RequestResponse = new JTabbedPane();
        requestPanel = new JPanel();
        responsePanel = new JPanel();

        responseSplitPane = new JSplitPane();
        responseBodyTextArea = new JTextArea();
        responseHeaderTextArea = new JTextArea();
        responseHeaderScrollPane = new JScrollPane();
        responseBodyScrollPane = new JScrollPane();

        reqAttribScrollPane = new JScrollPane();

        samlMsgTxtArea = new JTextArea();
        samlMsgScrollPane = new JScrollPane();
        lblWarningMsg = new JLabel();

        footerPanel = new JPanel();
        resendButton = new JButton();
        resetButton = new JButton();
    }

    /**
     * Do the layout of the components in the frame
     */
    private void doLayout() {
        samlEditorPanel.setLayout(new BorderLayout());
        samlEditorPanel.add(tabbedPane1RequestResponse);
        tabbedPane1RequestResponse.add("Request", requestPanel);
        tabbedPane1RequestResponse.add("Response", responsePanel);

        requestPanel.setLayout(new BorderLayout());
        samlMsgScrollPane.setViewportView(samlMsgTxtArea);
        requestPanel.add(samlMsgScrollPane, BorderLayout.PAGE_START);

        initSAMLContents();    //Initialize the layout of the saml attributes
        requestPanel.add(reqAttribScrollPane, BorderLayout.CENTER);

        //Footer
        footerPanel.setLayout(new GridLayout(2, 1));
        lblWarningMsg.setText("Note : This add-on would only run very basic test cases for SAML implementations. " +
                "Signed SAML assertions cannot be tampered with at this time because the signing keys have not been " +
                "made available to ZAP");
        JSplitPane buttonSplitPane = new JSplitPane();
        buttonSplitPane.setDividerSize(0);
        buttonSplitPane.setLeftComponent(resendButton);
        buttonSplitPane.setRightComponent(resetButton);
        buttonSplitPane.setResizeWeight(0.5);
        resendButton.setText("Resend");
        resetButton.setText("Reset");
        footerPanel.add(buttonSplitPane);
        footerPanel.add(lblWarningMsg);
        requestPanel.add(footerPanel, BorderLayout.PAGE_END);

        //Response panel
        responsePanel.setLayout(new BorderLayout());
        responsePanel.add(responseSplitPane);
        responseHeaderScrollPane.setViewportView(responseHeaderTextArea);
        responseBodyScrollPane.setViewportView(responseBodyTextArea);
        responseSplitPane.setTopComponent(responseHeaderScrollPane);
        responseSplitPane.setBottomComponent(responseBodyScrollPane);
        responseSplitPane.setResizeWeight(0.5);
        responseSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
    }

    /**
     * Initialize the SAML contents. i.e. message and the attributes
     */
    private void initSAMLContents() {
        initSAMLTextArea();
        initSAMLAttributes();
    }

    /**
     * Initialize the saml message text area
     */
    private void initSAMLTextArea() {
        samlMsgTxtArea.setText(samlMessage.getSamlMessageString());
        samlMsgTxtArea.setRows(10);
        samlMsgTxtArea.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
            }

            @Override
            public void focusLost(FocusEvent e) {
                samlMessage.setSamlMessageString(samlMsgTxtArea.getText());
                //todo check for validity
                initSAMLAttributes();
            }
        });
    }

    /**
     * Initialize the SAML attributes (label, value pairs)
     */
    private void initSAMLAttributes() {
        Map<String, Attribute> samlAttributes;
        samlAttributes = samlMessage.getAttributeMap();

        JPanel attribPanel = new JPanel();
        attribPanel.setLayout(new GridLayout(Math.max(15,samlAttributes.size()), 1, 5, 5));

        for (final Attribute attribute : samlAttributes.values()) {
            JSplitPane sPane = new JSplitPane();
            JLabel lbl = new JLabel();
            final JTextField txtValue = new JTextField();

            sPane.setDividerLocation(300);
            sPane.setDividerSize(0);

            lbl.setText(attribute.getViewName());
            sPane.setLeftComponent(lbl);

            txtValue.setText(attribute.getValue().toString());
            sPane.setRightComponent(txtValue);

            //update the saml message on attribute value changes
            txtValue.addFocusListener(new FocusListener() {
                @Override
                public void focusGained(FocusEvent e) {
                }

                @Override
                public void focusLost(FocusEvent e) {
                    samlMessage.changeAttributeValueTo(attribute.getName(),txtValue.getText());
                    samlMsgTxtArea.setText(samlMessage.getSamlMessageString());
                    //todo check validity
                }
            });
            attribPanel.add(sPane);
        }
        reqAttribScrollPane.setViewportView(attribPanel);
    }

    /**
     * Initialize the action events for the buttons
     */
    private void initButtons() {
        resendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                try {
                    SAMLResender.resendMessage(samlMessage.getChangedMessage());
                    updateResponse(samlMessage.getChangedMessage());
                    resendButton.setEnabled(false);
                    resetButton.setEnabled(false);
                } catch (SAMLException e) {
                    JOptionPane.showMessageDialog(requestPanel, e.getMessage(), "Cannot resend request",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        resetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                samlMessage.resetChanges();
                initSAMLContents();
            }
        });
    }

    /**
     * Update the response using the response of the message
     *
     * @param msg The HttpMessage containing the response
     */
    private void updateResponse(HttpMessage msg) {
        responseBodyTextArea.setText(msg.getResponseBody().createCachedString("UTF-8"));
        responseHeaderTextArea.setText(msg.getResponseHeader().toString());
        tabbedPane1RequestResponse.setSelectedIndex(1);

    }

    /**
     * Shows the extension UI
     */
    public void showUI() {
        JFrame frame = new JFrame("SAML Request editor");
        frame.setSize(800, 700);
        frame.setLayout(new BorderLayout());
        initUIComponents();
        doLayout();
        initButtons();
        frame.setContentPane(samlEditorPanel);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

}
