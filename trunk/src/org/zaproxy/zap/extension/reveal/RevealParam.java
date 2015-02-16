/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2014 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.reveal;

import org.apache.commons.configuration.ConversionException;
import org.apache.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class RevealParam extends VersionedAbstractParam {

	private static final Logger logger = Logger.getLogger(RevealParam.class);

	/**
	 * The version of the configurations. Used to keep track of configurations changes between releases, if updates are needed.
	 * <p>
	 * It only needs to be updated for configurations changes (not releases of the add-on).
	 * </p>
	 */
	private static final int PARAM_CURRENT_VERSION = 1;

	/**
	 * The base configuration key for all "reveal" configurations.
	 */
	private static final String PARAM_BASE_KEY = "reveal";

	/**
	 * The configuration key for the state of reveal functionality.
	 */
	private static final String PARAM_REVEAL_STATE = PARAM_BASE_KEY + ".enabled";

	private static final boolean PARAM_REVEAL_STATE_DEFAULT_VALUE = false;

	private boolean reveal = PARAM_REVEAL_STATE_DEFAULT_VALUE;

	@Override
	protected int getCurrentVersion() {
		return PARAM_CURRENT_VERSION;
	}

	@Override
	protected String getConfigVersionKey() {
		return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
	}

	@Override
	protected void parseImpl() {
		try {
			reveal = getConfig().getBoolean(PARAM_REVEAL_STATE, PARAM_REVEAL_STATE_DEFAULT_VALUE);
		} catch (ConversionException e) {
			logger.error("Error while loading the reveal state: " + e.getMessage(), e);
		}
	}

	@Override
	protected void updateConfigsImpl(int fileVersion) {
		// When in ZAP "core"
		if (fileVersion == NO_CONFIG_VERSION) {
			try {
				final String oldKey = "view.reveal";
				boolean oldValue = getConfig().getBoolean(oldKey, false);
				getConfig().clearProperty(oldKey);

				getConfig().setProperty(PARAM_REVEAL_STATE, Boolean.valueOf(oldValue));
			} catch (ConversionException e) {
				logger.error("Error while updating the reveal state from old version [" + fileVersion + "]", e);
			}
		}
	}

	public boolean isReveal() {
		return reveal;
	}

	public void setReveal(boolean reveal) {
		if (this.reveal != reveal) {
			this.reveal = reveal;

			saveRevealStateParam();
		}
	}

	private void saveRevealStateParam() {
		getConfig().setProperty(PARAM_REVEAL_STATE, Boolean.valueOf(reveal));
	}

}
