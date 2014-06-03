package org.zaproxy.zap.extension.accessControl;

import java.awt.Dimension;
import java.awt.Frame;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zap.view.widgets.ContextSelectComboBox;

public class AccessControlScanOptionsDialog extends StandardFieldsDialog {

	private static final long serialVersionUID = -4540976404891062951L;

	private static final String FIELD_CONTEXT = "accessControl.scanOptions.label.context";

	private ExtensionAccessControl extension;

	public AccessControlScanOptionsDialog(ExtensionAccessControl extension, Frame owner, Dimension dim) {
		super(owner, "accessControl.scanOptions.title", dim);
		this.extension = extension;
	}

	public void init(Context context) {
		this.removeAllFields();

		Logger.getRootLogger().info("Initing for: " + context);
		this.addContextSelectField(FIELD_CONTEXT, context);
		this.addPadding();
	}

	@Override
	public String getSaveButtonText() {
		return Constant.messages.getString("accessControl.scanOptions.button.scan");
	}

	@Override
	public void save() {
		// In this case, the 'Save' action corresponds to starting a scan with the specified options
	}

	@Override
	public String validateFields() {
		Context selectedContext = ((ContextSelectComboBox) getField(FIELD_CONTEXT)).getSelectedContext();
		if (selectedContext == null) {
			return Constant.messages.getString("accessControl.scanOptions.error.noContext");
		}
		return null;
	}
}
