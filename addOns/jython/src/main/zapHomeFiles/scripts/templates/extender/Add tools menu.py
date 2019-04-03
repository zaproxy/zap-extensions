"""
Add an example tool bar menu
Extender scripts allow you to add completely new functionality to ZAP.
The install function is called when the script is enabled and the uninstall function when it is disabled.
Any functionality added in the install function should be removed in the uninstall method.
See the other templates for examples on how to do add different functionality. 
"""


from javax.swing import JMenuItem
from java.awt.event import ActionListener

# Script variable to use when uninstalling
menuitem = JMenuItem("A menu item (py)")

class MenuListener(ActionListener):
  def actionPerformed(self,event):
    print("Example menu selected")
    self.helper.getView().showWarningDialog('Example tools menu selected!')
  def setHelper(self,helper):
    self.helper = helper


def install(helper):
  """
  This function is called when the script is enabled.
  
  helper - a helper class which provides the methods:
  getView() this returns a View object which provides an easy way to add graphical elements.
      It will be null is ZAP is running in daemon mode.
  getApi() this returns an API object which provides an easy way to add new API calls.
  Links to any functionality added should be held in script variables so that they can be removed in uninstall.
  """
  print('install called')
  if helper.getView():
    menulistener = MenuListener()
    menulistener.setHelper(helper)
    menuitem.addActionListener(menulistener)
    helper.getView().getMainFrame().getMainMenuBar().getMenuTools().add(menuitem)


"""
This function is called when the script is disabled.

helper - a helper class which provides the methods:
getView() this returns a View object which provides an easy way to add graphical elements.
    It will be null is ZAP is running in daemon mode.
getApi() this returns an API object which provides an easy way to add new API calls.
"""
def uninstall(helper):
  print('uninstall called'); 
  if helper.getView():
    helper.getView().getMainFrame().getMainMenuBar().getMenuTools().remove(menuitem)

