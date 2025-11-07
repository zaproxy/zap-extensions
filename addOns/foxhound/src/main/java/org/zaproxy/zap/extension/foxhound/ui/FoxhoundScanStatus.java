package org.zaproxy.zap.extension.foxhound.ui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.ScanStatus;

import javax.swing.ImageIcon;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

public class FoxhoundScanStatus extends ScanStatus  implements EventConsumer {

    public FoxhoundScanStatus() {
        super(new ImageIcon(FoxhoundScanStatus.class.getResource(FOXHOUND_16)),
                Constant.messages.getString("foxhound.footer.label"));

        ZAP.getEventBus()
                .registerConsumer(this, FoxhoundEventPublisher.getPublisher().getPublisherName());
    }

    @Override
    public void eventReceived(Event event) {
        if (event.getEventType().equals(FoxhoundEventPublisher.TAINT_INFO_CREATED)) {
            ThreadUtils.invokeLater(this::incScanCount);
        }
    }
}
