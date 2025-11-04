package org.zaproxy.zap.extension.foxhound.ui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.foxhound.ExtensionFoxhound;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintStoreEventListener;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.ScanStatus;

import javax.swing.ImageIcon;

import static org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants.FOXHOUND_16;

public class FoxhoundScanStatus extends ScanStatus implements TaintStoreEventListener {

    public FoxhoundScanStatus() {
        super(new ImageIcon(FoxhoundScanStatus.class.getResource(FOXHOUND_16)),
                Constant.messages.getString("foxhound.footer.label"));
    }

    @Override
    public void taintInfoAdded(TaintInfo taintInfo) {
        ThreadUtils.invokeLater(this::incScanCount);
    }
}
