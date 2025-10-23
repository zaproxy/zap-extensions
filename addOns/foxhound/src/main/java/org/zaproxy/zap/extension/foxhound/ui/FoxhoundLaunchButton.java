package org.zaproxy.zap.extension.foxhound.ui;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import java.io.Serial;

public class FoxhoundLaunchButton extends JButton {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final String RESOURCE = "/org/zaproxy/zap/extension/foxhound/resources";
    private static final String FOXHOUND_256 = RESOURCE + "/default256.png";
    private static final String FOXHOUND_16 = RESOURCE + "/default16.png";

    public FoxhoundLaunchButton() {
        this.setIcon(createIcon(FOXHOUND_16));
        this.setToolTipText("Launch Foxhound!");
    }

    private ImageIcon createIcon(String path) {
        return new ImageIcon(FoxhoundLaunchButton.class.getResource(path));
    }

}
