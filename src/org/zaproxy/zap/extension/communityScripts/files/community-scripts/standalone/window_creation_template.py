"""
Template for GUI creation - ported for Python/Jython

""" 

from org.parosproxy.paros.view import AbstractFrame;
from javax.swing import JPanel;
from javax.swing import JLabel;
from javax.swing import JMenuBar;
from javax.swing import JMenu;
from javax.swing import JMenuItem;

class absframe (AbstractFrame):
    def __init__(self):
        self.setAlwaysOnTop(False);
        self.setSize(500, 500);
        menubar = JMenuBar();
        menu = JMenu("A Menu");
        menu_ac = menu.getAccessibleContext();
        menu_ac.setAccessibleDescription("The only menu in this program");
        menuitem = JMenuItem("A Menu Item");
        menu.add(menuitem);
        menubar.add(menu);
        self.setJMenuBar(menubar);
        lbl = JLabel("A Label");
        lbl.setHorizontalAlignment(JLabel.CENTER);
        lbl.setVerticalAlignment(JLabel.CENTER);
        self.setContentPane(lbl);
        self.setVisible(True);

window = absframe();