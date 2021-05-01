"""
Author: kamalpreetSec
"""

"""
Extender scripts allow you to add completely new functionality to ZAP.
The install function is called when the script is enabled and the uninstall function when it is disabled.
Any functionality added in the install function should be removed in the uninstall method.
See the other templates for examples on how to do add different functionality. 
"""

"""
This python script will take input values from user and set them as global variables
These variables can then be accessed by other ZAP scripts like HTTP Sender, authentication scripts, etc
"""
import java.awt.event;

from org.parosproxy.paros.view import AbstractFrame;
from javax.swing import JLabel;
from javax.swing import JMenuBar;
from javax.swing import JMenu;
from javax.swing import JMenuItem;
from javax.swing import JFrame;
from javax.swing import JTextField;
from javax.swing import JButton;
from org.zaproxy.zap.extension.script import ScriptVars;

def install(helper):
  	print('install called'); 
	
	frame = JFrame("Please Input Values")
	frame.setLocation(100,100)
	frame.setSize(500,400)
	frame.setLayout(None)

	lbl1 = JLabel("Input1: ")
	lbl1.setBounds(60,20,60,20)
	txt1 = JTextField(100)
	txt1.setBounds(130,20,200,20)
	lbl2 = JLabel("Input2: ")
	lbl2.setBounds(60,50,100,20)
	txt2 = JTextField(100)
	txt2.setBounds(130,50,200,20)
	lbl3 = JLabel("Input3: ")
	lbl3.setBounds(60,80,140,20)
	txt3 = JTextField(100)
	txt3.setBounds(130,80,200,20)
	lbl4 = JLabel("Input4: ")
	lbl4.setBounds(60,110,180,20)
	txt4 = JTextField(100)
	txt4.setBounds(130,110,200,20)
	
	def getValues(event):
		print "clicked"
		ScriptVars.setGlobalVar("Input1",str(txt1.getText()))
		print(ScriptVars.getGlobalVar("Input1"))
		ScriptVars.setGlobalVar("Input2",str(txt2.getText()))
		print(ScriptVars.getGlobalVar("Input2"))
		ScriptVars.setGlobalVar("Input3",str(txt3.getText()))
		print(ScriptVars.getGlobalVar("Input3"))
		ScriptVars.setGlobalVar("Input4",str(txt4.getText()))
		print(ScriptVars.getGlobalVar("Input4"))		
		
	btn = JButton("Submit", actionPerformed = getValues)
	btn.setBounds(160,150,100,20)
		
	frame.add(lbl1)
	frame.add(txt1)
	frame.add(lbl2)
	frame.add(txt2)
	frame.add(btn)
	frame.add(lbl3)
	frame.add(txt3)
	frame.add(lbl4)
	frame.add(txt4)
	frame.setVisible(True)

"""
This function is called when the script is disabled.

helper - a helper class which provides the methods:
getView() this returns a View object which provides an easy way to add graphical elements.
    It will be null is ZAP is running in daemon mode.
getApi() this returns an API object which provides an easy way to add new API calls.
"""
def uninstall(helper):
  print('uninstall called'); 
