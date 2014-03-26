package org.zaproxy.zap.extension.httpsInfo;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.parosproxy.paros.view.AbstractFrame;

public class MDialog extends AbstractFrame{
    boolean ordered = false;
    Map<String, Integer> versionStrings;
    SSLServer server;

    JTextArea general;
    JLabel spinnerPref;
    JTextArea cipherSuites;
    JComboBox<String> suppVers;
    JButton refresh;

    public MDialog(SSLServer s){
	super();
	this.server = s;
	this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
	int x = (d.width - getSize().width) / 2;
	int y = (d.height - getSize().height) / 2;
	this.setLocation(x, y);
	init();
	addComponentsToPane(getContentPane());
	this.pack();
	updateContent();
	this.setVisible(true);
    }

    public void init(){
	general = new JTextArea();
	general.setEditable(false);
	JScrollPane scroll = new JScrollPane(general);
	spinnerPref = new JLabel("Supported Versions");
	cipherSuites = new JTextArea();
	cipherSuites.setEditable(false);
	JScrollPane scroll2 = new JScrollPane(cipherSuites);
	scroll2.createVerticalScrollBar();
	refresh = new JButton("Determine Server Preference");
	refresh.addActionListener(new ActionListener(){
	    @Override
	    public void actionPerformed(ActionEvent e){
		new Thread(new Runnable(){
		    @Override
		    public void run() {
			refresh.setEnabled(false);
			server.orderCertificates();
			ordered = true;
			refresh.setVisible(false);
			updateContent();
		    }
		}).start();
	    }
	});
	versionStrings = new HashMap<String, Integer>();
	for(int v: server.getSupportedVersions()){
	    versionStrings.put(server.versionString(v), v);
	}
	Object[] list = versionStrings.keySet().toArray();
	String[] slist = new String[list.length];
	for (int i = 0; i < slist.length; i++) {
	    slist[i] = list[i].toString();
	}
	Arrays.sort(slist);
	suppVers = new JComboBox(slist);
	suppVers.addActionListener(new ActionListener() {
	    @Override
	    public void actionPerformed(ActionEvent arg0) {
		showCipherSuites();

	    }
	});
    }
    public void updateContent(){
	showGeneral();
	showCipherSuites();
    }
    public void showGeneral(){
	StringBuffer content = new StringBuffer("Server: " + server.getServerName() + "\n" );
	if (server.getCert().size() == 0) {
	    content.append("No server certificates found!\n");
	    new Thread(new Runnable(){
		@Override
		public void run(){
		    server.updateCertificate();
		    showGeneral();
		}
	    }).start();
	}
	else {
	    content.append("Server certificate(s):\n");
	    for (String cc : server.getCert()) {
		content.append("  " + cc + "\n");
	    }
	}
	content.append("Deflate compression: ");
	if(server.getDeflateCompression() == null){
	    content.append("Pending...\n");
	    new Thread(new Runnable(){
		@Override
		public void run(){
		    server.updateCompress();
		    showGeneral();
		}
	    }).start();
	}
	else{
	    content.append((server.getDeflateCompression() ? "yes" : "no") + "\n");
	}
	if(server.getMinStrength() == null){
	    content.append("Minimal encryption Strength: Pending...\n");
	}
	else{
	    content.append("Minimal encryption strength: " + strengthString(server.getMinStrength()) + "\n");
	}
	if(server.getMaxStrength() == null){
	    content.append("Achievable encryption Strength: Pending...\n");
	}
	else{
	    content.append("Achievable encryption strength:  " + strengthString(server.getMaxStrength()) + "\n");
	}
	if(server.getBeastVuln() == null){
	    content.append("BEAST status: Pending...\n");
	}
	else{
	    content.append("BEAST status: " + (server.getBeastVuln() ? "vulnerable" : "protected") + "\n");
	}
	if(server.getCrimeVuln() == null){
	    content.append("CRIME status: Pending...\n");
	}
	else{
	    content.append("CRIME status: " + (server.getCrimeVuln() ? "vulnerable" : "protected"));
	}

	general.setText(content.toString());
    }
    public void showCipherSuites(){
	StringBuffer cs = new StringBuffer("Ciphersuites supported under " + suppVers.getSelectedItem() + (ordered ? " (ordered by server preference):\n" : " (unordered):\n"));
	int x = 0;
	try {
	    for(int c: server.getSupportedCipherSuites().get(versionStrings.get(suppVers.getSelectedItem()))){
		cs.append((ordered ? x+"." : "  ") + "      " + server.cipherSuiteString(c) + "\n");
		x++;
	    }

	} catch (Exception e) {
	    cs.append("Pending...");
	    new Thread(new Runnable(){
		@Override
		public void run(){
		    server.updateSupportedCS();
		    server.updateAttackVuln();
		    server.updateStrength();
		    showGeneral();
		    showCipherSuites();
		}
	    }).start();
	}
	cipherSuites.setText(cs.toString());
    }

    public void addComponentsToPane(Container pane) {
	pane.setLayout(new GridBagLayout());
	pane.setPreferredSize(new Dimension(750,400));
	pane.setMinimumSize(new Dimension(750,400));
	GridBagConstraints c = new GridBagConstraints();
	c.fill = GridBagConstraints.BOTH;
	c.gridwidth = 3;
	c.anchor = GridBagConstraints.NORTH;
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
	c.weighty = 0.5;
	c.anchor = GridBagConstraints.SOUTH;
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
