package org.zaproxy.zap.extension.aem.yaml;

public enum HttpMethodEnumYAML {
	CONNECT("CONNECT"), DELETE("DELETE"), GET("GET"), HEAD("HEAD"), OPTIONS("OPTIONS"), PATCH("PATCH"), POST("POST"),
	PUT("PUT"), TRACE("TRACE"), TRACK("TRACK");

	private final String value;

	private HttpMethodEnumYAML(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}
