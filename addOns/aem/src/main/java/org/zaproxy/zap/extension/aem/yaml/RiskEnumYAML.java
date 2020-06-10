package org.zaproxy.zap.extension.aem.yaml;

import org.parosproxy.paros.core.scanner.Alert;

public enum RiskEnumYAML {
	INFO(Alert.RISK_INFO), LOW(Alert.RISK_LOW), MEDIUM(Alert.RISK_MEDIUM), HIGH(Alert.RISK_HIGH);

	private final int value;

	private RiskEnumYAML(int value) {
		this.value = value;
	}

	public int getValue() {
		return this.value;
	}
}
