package org.zaproxy.zap.extension.aem.yaml;

import org.parosproxy.paros.core.scanner.Alert;

public enum ConfidenceEnumYAML {
	FALSE_POSITIVE(Alert.CONFIDENCE_FALSE_POSITIVE), LOW(Alert.CONFIDENCE_LOW), MEDIUM(Alert.CONFIDENCE_MEDIUM),
	HIGH(Alert.CONFIDENCE_HIGH), USER_CONFIRMED(Alert.CONFIDENCE_USER_CONFIRMED);

	private final int value;

	private ConfidenceEnumYAML(int value) {
		this.value = value;
	}

	public int getValue() {
		return this.value;
	}
}
