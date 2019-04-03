package org.zaproxy.zap.extension.spiderAjax;

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class AjaxSpiderMultipleOptionsPanel extends AbstractMultipleOptionsTablePanel<AjaxSpiderParamElem> {
    
    private static final long serialVersionUID = -115340627058929308L;
    
    private static final String REMOVE_DIALOG_TITLE = Constant.messages.getString("spiderajax.options.dialog.elem.remove.title");
    private static final String REMOVE_DIALOG_TEXT = Constant.messages.getString("spiderajax.options.dialog.elem.remove.text");
    
    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL = Constant.messages.getString("spiderajax.options.dialog.elem.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL = Constant.messages.getString("spiderajax.options.dialog.elem.remove.button.cancel");
    
    private static final String REMOVE_DIALOG_CHECKBOX_LABEL = Constant.messages.getString("spiderajax.options.dialog.elem.remove.checkbox.label");
    
    private DialogAddElem addDialog = null;
    private DialogModifyElem modifyDialog = null;
    
    private OptionsAjaxSpiderTableModel model;
    
    public AjaxSpiderMultipleOptionsPanel(OptionsAjaxSpiderTableModel model) {
        super(model);
        
        this.model = model;
        
        getTable().getColumnExt(0).setPreferredWidth(5);
        getTable().setSortOrder(1, SortOrder.ASCENDING);
        getTable().setVisibleRowCount(5);
    }

    @Override
    public AjaxSpiderParamElem showAddDialogue() {
        if (addDialog == null) {
            addDialog = new DialogAddElem(View.getSingleton().getOptionsDialog(null));
            addDialog.pack();
        }
        addDialog.setElems(model.getElements());
        addDialog.setVisible(true);
        
        AjaxSpiderParamElem elem = addDialog.getElem();
        addDialog.clear();
        
        return elem;
    }
    
    @Override
    public AjaxSpiderParamElem showModifyDialogue(AjaxSpiderParamElem e) {
        if (modifyDialog == null) {
            modifyDialog = new DialogModifyElem(View.getSingleton().getOptionsDialog(null));
            modifyDialog.pack();
        }
        modifyDialog.setElems(model.getElements());
        modifyDialog.setElem(e);
        modifyDialog.setVisible(true);
        
        AjaxSpiderParamElem elem = modifyDialog.getElem();
        modifyDialog.clear();
        
        if (!elem.equals(e)) {
            return elem;
        }
        
        return null;
    }
    
    @Override
    public boolean showRemoveDialogue(AjaxSpiderParamElem e) {
        JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
        Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
        int option = JOptionPane.showOptionDialog(View.getSingleton().getMainFrame(), messages, REMOVE_DIALOG_TITLE,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, new String[] { REMOVE_DIALOG_CONFIRM_BUTTON_LABEL, REMOVE_DIALOG_CANCEL_BUTTON_LABEL }, null);

        if (option == JOptionPane.OK_OPTION) {
            setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());
            
            return true;
        }
        
        return false;
    }
}
