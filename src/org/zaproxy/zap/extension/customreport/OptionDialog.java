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
package org.zaproxy.zap.extension.customreport;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractFrame;

public class OptionDialog extends AbstractFrame{
	
	private static final long serialVersionUID = 1L;
	private ExtensionCustomReport extension = null;
	
	public OptionDialog( ExtensionCustomReport extension, ScopePanel scopepanel, AlertsPanel alertspanel,
						 AlertDetailsPanel alertdetailspanel ){
		this.extension = extension;
		JPanel optiondialog = new JPanel();
		optiondialog.setLayout( new BorderLayout() );
		
		JTabbedPane mainpane = new JTabbedPane();
        mainpane.add(Constant.messages.getString("customreport.menu.scope"), scopepanel );
        mainpane.add(Constant.messages.getString("customreport.menu.alerts"), alertspanel );
        mainpane.add(Constant.messages.getString("customreport.menu.alertdetails"), alertdetailspanel );
         
        JPanel buttonpane = new JPanel( new FlowLayout( FlowLayout.RIGHT ));
        buttonpane.add( getCancelButton() );
        buttonpane.add( getHTMLButton() );
        
        optiondialog.add(mainpane, BorderLayout.NORTH );
        optiondialog.add(buttonpane, BorderLayout.SOUTH );
        
        this.setTitle(Constant.messages.getString("customreport.menu.title"));
        this.add(optiondialog);
        this.pack();

	}
	
	private JButton getCancelButton(){
		JButton cancelbutton = new JButton(Constant.messages.getString("customreport.cancel"));
		cancelbutton.addActionListener(
				new ActionListener() {
		            @Override
		            public void actionPerformed(ActionEvent e) {
		               extension.emitFrame();
		            }
		        });
		return cancelbutton;
	}
	
	private JButton getHTMLButton(){
		JButton generatebutton = new JButton(Constant.messages.getString("customreport.generate"));
		generatebutton.addActionListener(
				new ActionListener() {
		            @Override
		            public void actionPerformed(ActionEvent e) {
		                extension.generateReport();
		            }
		        });
		return generatebutton;
	}
	
}
