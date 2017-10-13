//Template for GUI creation

var absframe = Java.type("org.parosproxy.paros.view.AbstractFrame");
var jpanel = Java.type("javax.swing.JPanel");
var jlabel = Java.type("javax.swing.JLabel");
var jmenubar = Java.type("javax.swing.JMenuBar");
var jmenu = Java.type("javax.swing.JMenu");
var jmenuitem = Java.type("javax.swing.JMenuItem");
var window = new absframe(){};

init();

function init(){
    window.setAlwaysOnTop(false);
    window.setSize(500, 500);
    var menubar = new jmenubar();
    var menu = new jmenu("A Menu");
    var menu_ac = menu.getAccessibleContext();
    menu_ac.setAccessibleDescription("The only menu in this program");
    var menuitem = new jmenuitem("A Menu Item");
    menu.add(menuitem);
    menubar.add(menu);
    window.setJMenuBar(menubar);
    var lbl = new jlabel("A Label");
    lbl.setHorizontalAlignment(jlabel.CENTER);
    lbl.setVerticalAlignment(jlabel.CENTER);
    window.setContentPane(lbl);
    window.setVisible(true);
}
