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
import org.parosproxy.paros.common.AbstractParam;

public class RevealParam extends AbstractParam {

	private static final Logger logger = Logger.getLogger(RevealParam.class);

	/**
	 * The version of the configurations. Used to keep track of configurations changes between releases, if updates are needed.
	 * <p>
	 * It only needs to be updated for configurations changes (not releases of the add-on).
	 * </p>
	 */
	private static final long PARAM_CURRENT_VERSION = 1;

	/**
	 * The base configuration key for all "reveal" configurations.
	 */
	private static final String PARAM_BASE_KEY = "reveal";

	/**
	 * The configuration key for the version of the reveal configurations.
	 */
	private static final String PARAM_REVEAL_VERSION = PARAM_BASE_KEY + "@version";

	/**
	 * The configuration key for the state of reveal functionality.
	 */
	private static final String PARAM_REVEAL_STATE = PARAM_BASE_KEY + ".enabled";

	private static final boolean PARAM_REVEAL_STATE_DEFAULT_VALUE = false;

	private boolean reveal = PARAM_REVEAL_STATE_DEFAULT_VALUE;

	@Override
	protected void parse() {
		long version = getConfig().getLong(PARAM_REVEAL_VERSION, 0);

		if (!isCurrentParamVersion(version)) {
			update(version);
		}

		try {
			reveal = getConfig().getBoolean(PARAM_REVEAL_STATE, PARAM_REVEAL_STATE_DEFAULT_VALUE);
		} catch (ConversionException e) {
			logger.error("Error while loading the reveal state: " + e.getMessage(), e);
		}
	}

	private static boolean isCurrentParamVersion(long version) {
		return version != PARAM_CURRENT_VERSION;
	}

	private void update(long oldVersion) {
		// When in ZAP "core"
		if (oldVersion == 0) {
			try {
				final String oldKey = "view.reveal";
				boolean oldValue = getConfig().getBoolean(oldKey, false);
				getConfig().clearProperty(oldKey);

				getConfig().setProperty(PARAM_REVEAL_STATE, Boolean.valueOf(oldValue));
			} catch (ConversionException e) {
				logger.error(
						"Error while updating the reveal state from old version [" + oldVersion + "], " + e.getMessage(),
						e);
			}
		}

		getConfig().setProperty(PARAM_REVEAL_VERSION, Long.valueOf(PARAM_CURRENT_VERSION));
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
