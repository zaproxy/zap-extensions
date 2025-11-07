package org.zaproxy.zap.extension.foxhound.ui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundSeleniumProfile;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import java.io.Serial;


public class FoxhoundLaunchButton extends JButton {

    @Serial
    private static final long serialVersionUID = 1L;

    public FoxhoundLaunchButton(FoxhoundSeleniumProfile profile) {
        this.setIcon(createIcon(FoxhoundConstants.FOXHOUND_16));
        this.setToolTipText(Constant.messages.getString("foxhound.ui.launchTooltip"));
        this.addActionListener(
                e -> {
                    profile.launchFoxhound();
                }
        );
    }

    private ImageIcon createIcon(String path) {
        return new ImageIcon(FoxhoundLaunchButton.class.getResource(path));
    }

}
