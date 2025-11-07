package org.zaproxy.zap.extension.foxhound.ui;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.foxhound.ExtensionFoxhound;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.LayoutHelper;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import java.awt.GridBagLayout;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

@SuppressWarnings("serial")
public class FoxhoundPanel extends AbstractPanel implements EventConsumer {
    private static final long serialVersionUID = 7L;
    public static final String FOXHOUND_PANEL_NAME = "Foxhound";
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundPanel.class);

    private ExtensionFoxhound extension = null;
    private JScrollPane taintFlowScrollPane;
    private JToolBar toolbar;
    private JButton launchButton;
    private JButton clearAllButton;
    private TaintFlowTreeTable tree;


    public FoxhoundPanel(ExtensionFoxhound extension) {
        super();
        this.extension = extension;
        this.initialize();

        ZAP.getEventBus()
                .registerConsumer(this, FoxhoundEventPublisher.getPublisher().getPublisherName());
    }

    private void initialize() {
        this.setName(Constant.messages.getString("foxhound.panel.title"));
        this.setIcon(
                new ImageIcon(
                        FoxhoundPanel.class.getResource(FOXHOUND_16))); // 'flag' icon

        this.setLayout(new GridBagLayout());

        this.add(this.getToolbar(), LayoutHelper.getGBC(0, 0, 1, 1.0));
        this.add(this.getTaintFlowScrollPane(), LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0));

        this.setShowByDefault(true);

    }

    private JScrollPane getTaintFlowScrollPane() {
        if (taintFlowScrollPane == null) {
            taintFlowScrollPane = new JScrollPane();
            tree = new TaintFlowTreeTable();
            taintFlowScrollPane.setViewportView(tree);
        }
        return taintFlowScrollPane;
    }

    private JToolBar getToolbar() {
        if (toolbar == null) {
            toolbar = new JToolBar();
            toolbar.setFloatable(false);
            toolbar.add(getLaunchButton());
            toolbar.add(getClearAllButton());

        }
        return toolbar;
    }

    private JButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new FoxhoundLaunchButton(extension.getSeleniumProfile());
            launchButton.setText(Constant.messages.getString("foxhound.ui.launchText"));
        }
        return launchButton;
    }

    private JButton getClearAllButton() {
        if (clearAllButton == null) {
            clearAllButton = new JButton();
            clearAllButton.setText(Constant.messages.getString("foxhound.ui.clearAll"));
            clearAllButton.addActionListener(e -> {
                extension.getTaintStore().clearAll();
            });
        }
        return clearAllButton;
    }

    @Override
    public void eventReceived(Event event) {
        if (event.getEventType().equals(FoxhoundEventPublisher.TAINT_INFO_CREATED)) {
            String jobIdStr = event.getParameters().get(FoxhoundEventPublisher.JOB_ID);
            if (jobIdStr == null) {
                return;
            }
            int jobId;
            try {
                jobId = Integer.parseInt(jobIdStr);
            } catch (NumberFormatException e) {
                return;
            }
            TaintInfo taintInfo = this.extension.getTaintStore().getTaintInfo(jobId);
            if (taintInfo != null) {
                ThreadUtils.invokeLater(() -> {
                    this.tree.getTreeModel().taintInfoAdded(taintInfo);
                });
            }
        } else if (event.getEventType().equals(FoxhoundEventPublisher.TAINT_INFO_CLEARED)) {
            ThreadUtils.invokeLater(() -> {
                this.tree.getTreeModel().clear();
            });
        }
    }
}

