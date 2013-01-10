package org.zaproxy.zap.extension.sse.ui;

import java.awt.GridBagConstraints;
import java.awt.Insets;

public class EventStreamUiHelper {

	public int getDialogWidth() {
		return 400;
	}

	public GridBagConstraints getLabelConstraints(int x, int y) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new java.awt.Insets(0,5,0,5);
        gbc.gridx = x;
        gbc.gridy = y;
        return gbc;
	}
	
	public GridBagConstraints getDescriptionConstraints(int x, int y) {
		GridBagConstraints gbc = getLabelConstraints(x, y);
		gbc.insets = new Insets(5, 5, 10, 5);
		gbc.gridwidth = 3;
		gbc.weightx = 1;
        return gbc;
	}
	
	public GridBagConstraints getFieldConstraints(int x, int y) {
        GridBagConstraints gbc = getLabelConstraints(x, y);
        gbc.anchor = GridBagConstraints.NORTHWEST;
		gbc.gridwidth = 2;
		gbc.weightx = 1;
        return gbc;
	}
}
