package org.zaproxy.zap.extension.aem.yaml;

import org.parosproxy.paros.core.scanner.Category;

public enum CategoryEnumYAML {
	INFO_GATHER(Category.INFO_GATHER), BROWSER(Category.BROWSER), SERVER(Category.SERVER), MISC(Category.MISC),
	INJECTION(Category.INJECTION);

	private final int value;

	private CategoryEnumYAML(int value) {
		this.value = value;
	}

	public int getValue() {
		return this.value;
	}
}
