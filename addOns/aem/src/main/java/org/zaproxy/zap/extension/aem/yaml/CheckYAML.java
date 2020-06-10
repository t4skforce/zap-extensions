package org.zaproxy.zap.extension.aem.yaml;

public class CheckYAML {

	private String name;

	private Integer alertId;

	private Integer cweId;

	private Integer wacsId;

	private RiskEnumYAML risk;

	private ConfidenceEnumYAML confidence;

	private String attack;

	private String param;

	private RequestYAML request;

	private ResponseYAML response;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Integer getAlertId() {
		return alertId;
	}

	public void setAlertId(Integer alertId) {
		this.alertId = alertId;
	}

	public Integer getCweId() {
		return cweId;
	}

	public void setCweId(Integer cweId) {
		this.cweId = cweId;
	}

	public Integer getWacsId() {
		return wacsId;
	}

	public void setWacsId(Integer wacsId) {
		this.wacsId = wacsId;
	}

	public RiskEnumYAML getRisk() {
		return risk;
	}

	public void setRisk(RiskEnumYAML risk) {
		this.risk = risk;
	}

	public ConfidenceEnumYAML getConfidence() {
		return confidence;
	}

	public void setConfidence(ConfidenceEnumYAML confidence) {
		this.confidence = confidence;
	}

	public String getAttack() {
		return attack;
	}

	public void setAttack(String attack) {
		this.attack = attack;
	}

	public String getParam() {
		return param;
	}

	public void setParam(String param) {
		this.param = param;
	}

	public RequestYAML getRequest() {
		return request;
	}

	public void setRequest(RequestYAML request) {
		this.request = request;
	}

	public ResponseYAML getResponse() {
		return response;
	}

	public void setResponse(ResponseYAML response) {
		this.response = response;
	}

}
