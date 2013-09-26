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
 */
package org.zaproxy.zap.extension.httpsInfo;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.util.*;

import javax.swing.*;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.PopupMenuHttpMessage;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.SiteNode;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages. 
 * 
 * This class is defines the popup menu item.
 */
public class MenuEntry extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private RightClickMenu extension = null;
    private SiteNode node = null;

    public MenuEntry(String label) {
	super(label);
	init();
    }
    public void init(){
	this.addActionListener(new java.awt.event.ActionListener() { 

	    @Override
	    public void actionPerformed(java.awt.event.ActionEvent e) {
		Thread bt = new Thread(new BackgroundThread(getHostName(node.getNodeName())));
		bt.start();
	    }
	});
    }
    @Override
    public boolean isEnableForComponent(Component invoker) {
	if (invoker instanceof JTree) {
	    JTree tree = (JTree) invoker;
	    if(tree.getLastSelectedPathComponent() instanceof SiteNode){
		node = (SiteNode) tree.getLastSelectedPathComponent();
		if (node.getNodeName().startsWith("https://")) {
		    this.setEnabled(true);
		    return true;
		}
	    }
	}
	return false;
    }
    public String getHostName(String name){
	String host = name;
	host = host.substring(8);
	while(!Character.isDigit(host.charAt(host.length()-1)) && !Character.isLetter(host.charAt(host.length()-1))){
	    host = host.substring(0, host.length()-1);
	}
	return host;
    }
    public void setExtension(RightClickMenu extension) {
	this.extension = extension;
    }

class BackgroundThread implements Runnable{
	 private String servername;
	 public BackgroundThread(String servername){
	  this.servername = servername;
	 }
	 
	 @Override
	 public void run() {
		SSLServer mServer = new SSLServer(servername);
		mDialog d = new mDialog(mServer);
		d.show();
	 }

	}
}

class mDialog {
    Map<String, Integer> versionStrings;
    SSLServer server;
    
    ArrayList<String> versionList;    
    SpinnerModel version;
    
    JTextArea general;
    JLabel spinnerPref;
    JTextArea cipherSuites;
    JSpinner suppVers;
    JButton refresh;
    
    public mDialog(SSLServer s){
	this.server = s;
    }
    
    public void show(){
        JFrame frame = new JFrame("HTTPS Information");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setBounds(100, 100, 800, 400);
        init();
        addComponentsToPane(frame.getContentPane());
        frame.pack();
        updateContent();
        frame.setVisible(true);
    }
    public void init(){
	general = new JTextArea();
	general.setEditable(false);
	general.setMinimumSize(new Dimension(600,150));
	spinnerPref = new JLabel("Supported Versions");
	cipherSuites = new JTextArea();
	cipherSuites.setEditable(false);
	cipherSuites.setMinimumSize(new Dimension(600,150));
	refresh = new JButton("Order");
	refresh.addActionListener(new ActionListener(){
	    @Override
	    public void actionPerformed(ActionEvent e){
		server.orderCertificates();
		updateContent();
	    }
	});
	
	versionStrings = new HashMap<String, Integer>();
	versionList = new ArrayList<String>();
	for(int v: server.getSupportedCipherSuites().keySet()){
	    versionList.add(server.versionString(v));
	    versionStrings.put(server.versionString(v), v);
	}
	
	version = new SpinnerListModel(versionList);
	version.addChangeListener(new ChangeListener(){
	    @Override
	    public void stateChanged(ChangeEvent e){
		updateContent();
	    }
	});
	suppVers = new JSpinner(version);
    }
    public void updateContent(){
	server.updateSupportedVersions();
	server.updateCertificate();
	server.updateCompress();
	server.updateSupportedCS();
	server.updateAttackVuln();
	server.updateStrength();
	StringBuffer gen = new StringBuffer("Deflate compression: " + (server.getDeflateCompression() ? "YES" : "no") + "\n");
        if (server.getCert().size() == 0) {
            gen.append("No server certificate !\n");
        } else {
            gen.append("Server certificate(s):\n");
            for (String cc : server.getCert()) {
        	gen.append("  " + cc + "\n");
            }
        }
        gen.append("Minimal encryption strength:     " + strengthString(server.getMinStrength()) + "\n");
        gen.append("Achievable encryption strength:  " + strengthString(server.getMaxStrength()) + "\n");
        gen.append("BEAST status: " + (server.getBeastVuln() ? "vulnerable" : "protected") + "\n");
        gen.append("CRIME status: " + (server.getCrimeVuln() ? "vulnerable" : "protected") + "\n");
	general.setText(gen.toString());
	
	StringBuffer cs = new StringBuffer();
	version.getValue();
	for(int c: server.getSupportedCipherSuites().get(versionStrings.get(version.getValue()))){
		cs.append("        " + server.cipherSuiteString(c) + "\n");
	    }
	cipherSuites.setText(cs.toString());
    }
    public void addComponentsToPane(Container pane) {
	pane.setLayout(new GridBagLayout());
	GridBagConstraints c = new GridBagConstraints();
	c.fill = GridBagConstraints.HORIZONTAL;
	c.gridwidth = 3;
	c.gridx = 0;
	c.gridy = 0;
	pane.add(general, c);
	c.gridwidth = 1;
	c.weightx = 0.5;
	c.gridx = 0;
	c.gridy = 1;
	pane.add(spinnerPref, c);
	
	c.weightx = 0.5;
	c.gridx = 1;
	c.gridy = 1;
	pane.add(suppVers, c);

	c.weightx = 0.1;
	c.gridx = 2;
	c.gridy = 1;
	pane.add(refresh, c);
	c.gridx = 0;
	c.gridy = 2;
	c.gridwidth = 3;
	pane.add(cipherSuites, c);
    }
    private String strengthString(int strength){
	switch (strength) {
	case 0: return "no encryption";
	case 1: return "weak encryption (40-bit)";
	case 2: return "medium encryption (56-bit)";
	case 3: return "strong encryption (96-bit or more)";
	default:
	    throw new Error("strange strength: " + strength);
	}
    }
}