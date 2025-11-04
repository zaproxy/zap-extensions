package org.zaproxy.zap.extension.foxhound.ui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import java.io.Serial;


public class FoxhoundLaunchButton extends JButton {

    @Serial
    private static final long serialVersionUID = 1L;

    public FoxhoundLaunchButton() {
        this.setIcon(createIcon(FoxhoundConstants.FOXHOUND_16));
        this.setToolTipText(Constant.messages.getString("foxhound.ui.launchTooltip"));
    }

    private ImageIcon createIcon(String path) {
        return new ImageIcon(FoxhoundLaunchButton.class.getResource(path));
    }

}
