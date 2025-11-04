package org.zaproxy.zap.extension.foxhound.ui;

import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.extension.foxhound.ExtensionFoxhound;
import javax.swing.ImageIcon;
import java.awt.CardLayout;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

@SuppressWarnings("serial")
public class FoxhoundPanel extends AbstractPanel {
    private static final long serialVersionUID = 7L;
    public static final String FOXHOUND_PANEL_NAME = "Foxhound";

    private ExtensionFoxhound extension = null;

    public FoxhoundPanel(ExtensionFoxhound extension) {
        super();
        this.extension = extension;
        this.initialize();
    }

    private void initialize() {
        this.setLayout(new CardLayout());
        this.setSize(274, 251);
        this.setName("foxhound");
        this.setIcon(
                new ImageIcon(
                        FoxhoundPanel.class.getResource(FOXHOUND_16))); // 'flag' icon


        this.setShowByDefault(true);
    }
}

