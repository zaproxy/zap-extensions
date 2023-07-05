/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.addon.report2iriusrisk;

import java.awt.CardLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.JsonParser;
import org.jfree.data.json.impl.JSONArray;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.report2iriusrisk.ReportLastScan.ReportType;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

import net.sf.json.JSONException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;



/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionReport2IriusRisk extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionReport2IriusRisk";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "report2iriusrisk";

    // Define your desired add-on ID
    private static final String ADDON_ID = "report2iriusrisk";

   
	
    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final String EXAMPLE_FILE = "example/ExampleFile.txt";

    private ZapMenuItem menuExample;
    private RightClickMsgMenu popupMsgMenuExample;
    private AbstractPanel statusPanel;


    private static final Logger LOGGER = LogManager.getLogger(ExtensionReport2IriusRisk.class);

    private JTextField iriusRiskDomainInputField;
    private JComboBox<String> iriusRiskProjectIdSelector;
    private JTextField apiTokenInputField;
    private JTextArea outputTextArea;
    private JScrollPane scrollPane;
    private JButton checkConnectionButton;
    private JButton submitButton;
    private String homeUser = System.getProperty("user.home");

    public ExtensionReport2IriusRisk() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // As long as we're not running as a daemon
        if (hasView()) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
    }

    private static List<String> extractRefField(String responseBody) {
        // Implement your logic to extract the desired field from the response body
        // For example, if the response body is a JSON array containing objects with "ref" field:
        // You can use a JSON library like Jackson or Gson to parse the JSON and extract the field
        // Here's a simple example without using a JSON library:
        List<String> refs = new ArrayList<>();
        try {
            // Create a Gson instance
            Gson gson = new Gson();

            // Convert the JSON string to a JsonArray
            JsonArray jsonArray = gson.fromJson(responseBody, JsonArray.class);

            // Extract the ref values from the JsonArray
            for (JsonElement jsonElement : jsonArray) {
                JsonObject jsonObject = jsonElement.getAsJsonObject();
                String ref = jsonObject.get("ref").getAsString();
                refs.add(ref);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return refs;
    }

    private AbstractPanel getStatusPanel() {
        
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(null);
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(new ImageIcon(getClass().getResource(RESOURCES + "/cake.png")));


            // Create labels and inputs
            JLabel iriusRiskDomainLabel = new JLabel("IriusRisk Domain:");
            iriusRiskDomainInputField = new JTextField();
            JLabel iriusRiskProjectIdLabel = new JLabel("IriusRisk Project Reference ID:");
            iriusRiskProjectIdSelector = new JComboBox<>();
            JLabel apiTokenLabel = new JLabel("IriusRisk API Token:");
            apiTokenInputField = new JTextField();
            outputTextArea = new JTextArea();
            scrollPane = new JScrollPane(outputTextArea);
            outputTextArea.setEditable(false);
            outputTextArea.setWrapStyleWord(true); // Wrap at word boundaries
            checkConnectionButton = new JButton( new ImageIcon(getClass().getResource(RESOURCES + "/refresh.png")));
            submitButton = new JButton("Submit");

            // Check connection button event
            checkConnectionButton.addActionListener(new ActionListener(){ 
                @Override
                public void actionPerformed(ActionEvent e) {
                    String iriusRiskDomain = iriusRiskDomainInputField.getText().strip();
                    String apiToken = apiTokenInputField.getText().strip();

                    // Check if all fields are filled
                    if (iriusRiskDomain.isEmpty() || apiToken.isEmpty()) {
                        View.getSingleton().showWarningDialog("Please fill in all the required fields.");
                        return;
                    }

                    // Endpoint full path
                    String endpoint = iriusRiskDomain + "/api/v1/products";
                    outputTextArea.append("Trying to connect\n");

                    try {
                        // URL for the POST request
                        URI url = new URI(endpoint);
                        
                        HttpClient httpClient = HttpClientBuilder.create().build();
                        HttpGet httpGet = new HttpGet(endpoint);

                        // Set headers
                        httpGet.setHeader("api-token", apiToken);
                        httpGet.setHeader("Accept", "application/json");

                        // Execute the request
                        HttpResponse response = httpClient.execute(httpGet);
                        
                        // Get the response body
                        HttpEntity responseEntity = response.getEntity();
                        
                        String responseBody = EntityUtils.toString(responseEntity);
                        
                        List<String> refs = extractRefField(responseBody);
                        for (String str : refs) {iriusRiskProjectIdSelector.addItem(str);}

                        statusPanel.repaint();
                        // Get the response code
                        int statusCode = response.getStatusLine().getStatusCode();

                        if(statusCode==200 || statusCode==201){
                            outputTextArea.append("Connection successful\n");
                        }else{
                            outputTextArea.append("Failed to connect. " + responseBody+"\n");
                        }
                    } catch (Exception exc) {
                        outputTextArea.append("Failed to connect\n");
                        outputTextArea.append(exc.getMessage()+"\n");
                    }
                }
            });

            submitButton.addActionListener(new ActionListener() { // Submit button event
                @Override
                public void actionPerformed(ActionEvent e) {
                
                    String iriusRiskDomain = iriusRiskDomainInputField.getText().strip();
                    String iriusRiskProjectId = iriusRiskProjectIdSelector.getSelectedItem().toString();
                    String apiToken = apiTokenInputField.getText().strip();

                    // Check if all fields are filled
                    if (iriusRiskDomain.isEmpty() || iriusRiskProjectId.isEmpty() || apiToken.isEmpty()) {
                        View.getSingleton().showWarningDialog("Please fill in all the required fields.");
                        return;
                    }

                    File file = null;
                    outputTextArea.append("Generating XML."+ "\n");

                    ReportLastScan reportLastScan = new ReportLastScan();

                    // Genera el informe
                    try{
                        file = reportLastScan.generate(homeUser+"/Zap-Report.xml", ReportType.XML);
                    } catch(Exception exception){
                        exception.printStackTrace();
                        View.getSingleton().showWarningDialog("XML could not be generated.");
                    }
                    outputTextArea.append("XML was generated succesfully."+"\n");
                    
                    // Endpoint full path
                    String endpoint = iriusRiskDomain + "/api/v1/products/"+iriusRiskProjectId+"/tests/zap/upload";                    

                    try {
                        // URL for the POST request
                        URI url = new URI(endpoint);
                        
                        HttpClient httpClient = HttpClientBuilder.create().build();
                        HttpPost httpPost = new HttpPost(endpoint);

                        outputTextArea.append("Connection created\n");

                        // Set headers
                        httpPost.setHeader("api-token", apiToken);
                        httpPost.setHeader("Accept", "application/json");

                        outputTextArea.append("Connection configured\n");

                        String output= "Uploading XML to "+endpoint+"\n";
                        outputTextArea.append(output);
                        // Build multipart entity
                        HttpEntity entity = MultipartEntityBuilder.create()
                                .addPart("fileName", new FileBody(file, ContentType.APPLICATION_XML))
                                .build();

                        // Set entity to the request
                        httpPost.setEntity(entity);

                        // Execute the request
                        HttpResponse response = httpClient.execute(httpPost);
                        
                        // Get the response code
                        int statusCode = response.getStatusLine().getStatusCode();
                        // Get the response body
                        HttpEntity responseEntity = response.getEntity();
                        String responseBody = EntityUtils.toString(responseEntity);

                        // Print the response body
                        outputTextArea.append(responseBody+"\n");
                        
                        if(statusCode==200 || statusCode==201){
                            View.getSingleton().showMessageDialog("Report uploaded successfully.");
                        }else{
                            View.getSingleton().showWarningDialog("Failed to upload report: " + responseBody);
                        }
                    } catch (Exception exc) {
                        outputTextArea.append(exc.getMessage());
                        View.getSingleton().showWarningDialog("Failed to upload report");
                    }
                    // Delete the XML file
                    File fileReport = new File(homeUser+"/Zap-Report.xml");
                    outputTextArea.append("Trying to delete the report xml file.\n");
                    if (fileReport.exists()) {
                        if (fileReport.delete()) {
                            outputTextArea.append("The file was deleted succesfully.\n");
                        } else {
                            outputTextArea.append("File could not be deleted.\n");
                        }
                    } else {
                        outputTextArea.append("The file does not exist.\n");
                    }
                }
            });

            // Congifuration of the GUI
            int x = 20; // 350
            int y = 20;
            int labelWidth = 200;
            int inputWidth = 300;
            int height = 25;
            int gap = 10;
            
            iriusRiskDomainLabel.setBounds(x, y, labelWidth, height);
            iriusRiskDomainInputField.setBounds(x + labelWidth + gap, y, inputWidth, height);

            apiTokenLabel.setBounds(x, y + height + gap, labelWidth, height);
            apiTokenInputField.setBounds(x + labelWidth + gap, y + height + gap, inputWidth, height);
            
            iriusRiskProjectIdLabel.setBounds(x, y + (height + gap) * 2, labelWidth, height);
            iriusRiskProjectIdSelector.setBounds(x + labelWidth + gap, y + (height + gap) * 2, inputWidth, height);

            checkConnectionButton.setBounds( x + labelWidth + gap + inputWidth + gap, y + (height + gap)*2, height, height);
            submitButton.setBounds( x + (gap + inputWidth)/2, y + (height + gap) * 3, labelWidth, height);
            
            scrollPane.setBounds(x + labelWidth + gap + inputWidth + gap + 125, y, 600, 160);

            statusPanel.add(iriusRiskDomainLabel);
            statusPanel.add(iriusRiskDomainInputField);
            statusPanel.add(apiTokenLabel);
            statusPanel.add(apiTokenInputField);
            statusPanel.add(iriusRiskProjectIdLabel);
            statusPanel.add(iriusRiskProjectIdSelector);
            statusPanel.add(checkConnectionButton);
            statusPanel.add(submitButton);
            statusPanel.add(scrollPane);
        }
        return statusPanel;
    }

    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menuExample.addActionListener(
                    e -> {
                        // This is where you do what you want to do.
                        // In this case we'll just show a popup message.
                        View.getSingleton()
                                .showMessageDialog(
                                        Constant.messages.getString(PREFIX + ".topmenu.tools.msg"));
                        // And display a file included with the add-on in the Output tab
                        displayFile(EXAMPLE_FILE);
                    });
        }
        return menuExample;
    }

    private void displayFile(String file) {
        if (!View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            return;
        }
        try {
            File f = new File(Constant.getZapHome(), file);
            if (!f.exists()) {
                // This is something the user should know, so show a warning dialog
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        ExtensionReport2IriusRisk.PREFIX + ".error.nofile",
                                        f.getAbsolutePath()));
                return;
            }
            // Quick way to read a small text file
            String contents = new String(Files.readAllBytes(f.toPath()));
            // Write to the output panel
            View.getSingleton().getOutputPanel().append(contents);
            // Give focus to the Output tab
            View.getSingleton().getOutputPanel().setTabFocus();
        } catch (Exception e) {
            // Something unexpected went wrong, write the error to the log
            LOGGER.error(e.getMessage(), e);
        }
    }

    private RightClickMsgMenu getPopupMsgMenuExample() {
        if (popupMsgMenuExample == null) {
            popupMsgMenuExample =
                    new RightClickMsgMenu(
                            this, Constant.messages.getString(PREFIX + ".popup.title"));
        }
        return popupMsgMenuExample;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
