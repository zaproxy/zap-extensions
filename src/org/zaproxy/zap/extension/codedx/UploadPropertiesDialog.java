/*
 * Copyright (C) 2016 Code Dx, Inc. - http://www.codedx.com
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

package org.zaproxy.zap.extension.codedx;

import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.parosproxy.paros.Constant;

public class UploadPropertiesDialog {
	
	private static final Logger logger = Logger.getLogger(UploadPropertiesDialog.class);
	
	private static final String[] dialogButtons = { Constant.messages.getString("codedx.settings.upload"),
			Constant.messages.getString("codedx.settings.cancel") };
	
	public static final ImageIcon REFRESH_ICON = new ImageIcon(
			UploadPropertiesDialog.class.getResource( "/org/zaproxy/zap/extension/codedx/resources/refresh.png"));
	
	private JTextField serverUrl;
	private JTextField apiKey;
	private JComboBox<NameValuePair> projectBox;
	private JDialog dialog;
	
	private NameValuePair[] projectArr = new BasicNameValuePair[0];
	
	private CodeDxExtension extension;
	
	public UploadPropertiesDialog(CodeDxExtension extension){
		this.extension = extension;
	}
	
	public void openProperties(final UploadActionListener uploader){		
		JPanel message = new JPanel(new GridBagLayout());
		
		serverUrl = labelTextField(Constant.messages.getString("codedx.settings.serverurl"), message,
				CodeDxProperties.getServerUrl());
		apiKey = labelTextField(Constant.messages.getString("codedx.settings.apikey"), message,
				CodeDxProperties.getApiKey());
		projectBox = createProjectComboBox(message);
		
		final JOptionPane pane = new JOptionPane(message, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION, null,
				dialogButtons, null);
		dialog = pane.createDialog(Constant.messages.getString("codedx.settings.title"));
		
		Thread popupThread = new Thread(){
			@Override
			public void run(){								
				dialog.setVisible(true);
				if (dialogButtons[0].equals(pane.getValue())) {
					CodeDxProperties.setProperties(serverUrl.getText(), apiKey.getText());
					uploader.generateAndUploadReport();
				}
			}
		};
		Thread updateThread = new Thread(){
			@Override
			public void run(){
				if(!"".equals(serverUrl.getText()) && !"".equals(apiKey.getText())){
					updateProjects(true);
				}
			}
		};
		popupThread.start();
		updateThread.start();
	}
    
	private JTextField labelTextField(String label, Container cont, String base) {
		createSettingsLabel(label, cont);
    	
		JTextField textField = new JTextField(base, 30);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		cont.add(textField, gbc);

		return textField;
	}
	
	private JComboBox<NameValuePair> createProjectComboBox(Container cont){
		createSettingsLabel("Project: ", cont);
				
		JComboBox<NameValuePair> box = new JComboBox<NameValuePair>(projectArr);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		cont.add(box, gbc);

		JButton refresh = new JButton(REFRESH_ICON);
		refresh.setPreferredSize(new Dimension(REFRESH_ICON.getIconHeight()+6,REFRESH_ICON.getIconHeight()+6));
		refresh.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				dialog.setCursor(new Cursor(Cursor.WAIT_CURSOR));
				updateProjects();
				dialog.setCursor(Cursor.getDefaultCursor());
			}
		});
		gbc = new GridBagConstraints();
		gbc.gridx = 2;
		gbc.gridy = 2;
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(refresh, gbc);
		
		return box;
	}
	
	private void createSettingsLabel(String label, Container cont){
		JLabel labelField = new JLabel(label);
    	labelField.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = 1;
		gbc.gridx = 0;
		gbc.insets = new Insets(0, 10, 0, 0);
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(labelField, gbc);
	}

	public void updateProjects(){
		updateProjects(false);
	}
	
	public void updateProjects(boolean initialRefresh) {
		dialog.setCursor(new Cursor(Cursor.WAIT_CURSOR));
		CloseableHttpClient client = null;
		BufferedReader rd = null;
		projectArr = new BasicNameValuePair[0];
		try{
			client = extension.getHttpClient(getServerUrl());
			if(client != null){
				HttpGet get = new HttpGet(getServerUrl() + "/api/projects");
				get.setHeader("API-Key", getApiKey());
				HttpResponse response = client.execute(get);
				rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
		
				StringBuffer result = new StringBuffer();
				String line = "";
				while ((line = rd.readLine()) != null) {
					result.append(line);
				}
	
				if(!"".equals(result.toString().trim()) && !"Insufficient Permissions".equals(result.toString().trim())){
					JSONParser parser = new JSONParser();
					
					JSONObject obj = (JSONObject)parser.parse(result.toString());
					JSONArray projects = (JSONArray)obj.get("projects");
					
					projectArr = new NameValuePair[projects.size()];
					for(int i = 0; i < projectArr.length; i++){
						JSONObject project = (JSONObject)projects.get(i);
						int id = ((Long)project.get("id")).intValue();
						String name = (String)project.get("name");
						projectArr[i] = new ModifiedNameValuePair(name,Integer.toString(id));
					}
				}
				
				if(projectArr.length == 0 && !initialRefresh)
					warn(Constant.messages.getString("codedx.refresh.noproject"));
			}
		} catch (GeneralSecurityException | ParseException | IOException e){
			if(!initialRefresh){
				if(e instanceof MalformedURLException)
					error(Constant.messages.getString("codedx.error.client.invalid"));
				else
					error(Constant.messages.getString("codedx.refresh.failed"));
			}
			logger.error("Error refreshing project list: ", e);
		} finally {
			if(client != null)
				try {client.close();} catch (IOException e) {}
			if(rd != null)
				try {rd.close();} catch (IOException e) {}
		}
		updateProjectComboBox();
		dialog.setCursor(Cursor.getDefaultCursor());
	}
	
	public void updateProjectComboBox(){
		if(projectBox != null){
			projectBox.removeAllItems();
			for(NameValuePair p: projectArr)
				projectBox.addItem(p);
		}
	}
	
	public NameValuePair getProject(){
		return (NameValuePair)projectBox.getSelectedItem();
	}
	
	private void warn(String message){
		JOptionPane.showMessageDialog(dialog, message, Constant.messages.getString("codedx.warning"), JOptionPane.WARNING_MESSAGE);
	}
	
	private void error(String message){
		JOptionPane.showMessageDialog(dialog, message, Constant.messages.getString("codedx.error"), JOptionPane.ERROR_MESSAGE);
	}
	
	private String getServerUrl(){	
		String text = serverUrl.getText();
		if(text.endsWith("/"))
			return text.substring(0, text.length()-1);
		return text;
	}
	
	private String getApiKey(){
		return apiKey.getText();
	}
	
	private static class ModifiedNameValuePair extends BasicNameValuePair{
		private static final long serialVersionUID = -6671681121783779976L;
		public ModifiedNameValuePair(String name, String value) {
			super(name, value);
		}
		@Override
		public String toString(){
			return getName() + " (id: " + getValue() + ")";
		}
	}
}
