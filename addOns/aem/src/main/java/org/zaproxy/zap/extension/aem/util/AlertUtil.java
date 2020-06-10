package org.zaproxy.zap.extension.aem.util;

import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.AbstractPlugin.AlertBuilder;
import org.zaproxy.zap.extension.aem.yaml.CheckYAML;
import org.zaproxy.zap.extension.aem.yaml.VulnerabilityYAML;

public abstract class AlertUtil {

	public static void addVulnerabilityInfo(VulnerabilityYAML alert, final AlertBuilder alertBuilder) {
		Optional.ofNullable(alert.getRisk()).ifPresent(r -> {
			alertBuilder.setRisk(r.getValue());
		});

		Optional.ofNullable(alert.getConfidence()).ifPresent(c -> {
			alertBuilder.setConfidence(c.getValue());
		});

		Optional.ofNullable(alert.getName()).filter(StringUtils::isNoneBlank).ifPresent(name -> {
			alertBuilder.setName(name);
		});

		Optional.ofNullable(alert.getDescription()).filter(StringUtils::isNoneBlank).ifPresent(description -> {
			alertBuilder.setDescription(description);
		});

		Optional.ofNullable(alert.getDescription()).filter(StringUtils::isNoneBlank).ifPresent(description -> {
			alertBuilder.setDescription(description);
		});

		Optional.ofNullable(alert.getParam()).filter(StringUtils::isNoneBlank).ifPresent(param -> {
			alertBuilder.setParam(param);
		});

		Optional.ofNullable(alert.getAttack()).filter(StringUtils::isNoneBlank).ifPresent(attack -> {
			alertBuilder.setAttack(attack);
		});

		Optional.ofNullable(alert.getOtherInfo()).filter(StringUtils::isNoneBlank).ifPresent(oinfo -> {
			alertBuilder.setOtherInfo(oinfo);
		});

		Optional.ofNullable(alert.getSolution()).filter(StringUtils::isNoneBlank).ifPresent(solution -> {
			alertBuilder.setSolution(solution);
		});

		Optional.ofNullable(alert.getSolution()).filter(StringUtils::isNoneBlank).ifPresent(solution -> {
			alertBuilder.setSolution(solution);
		});

		Optional.ofNullable(alert.getCweId()).filter(cweId -> cweId > -1).ifPresent(cweId -> {
			alertBuilder.setCweId(cweId);
		});

		Optional.ofNullable(alert.getWacsId()).filter(wacsId -> wacsId > -1).ifPresent(wacsId -> {
			alertBuilder.setWascId(wacsId);
		});

		Optional.ofNullable(alert.getAlertId()).filter(alertId -> alertId > -1).ifPresent(alertId -> {
			alertBuilder.setAlertId(alertId);
		});
	}

	public static void addVulnerabilityInfo(CheckYAML check, final AlertBuilder alertBuilder) {
		Optional.ofNullable(check.getRisk()).ifPresent(r -> {
			alertBuilder.setRisk(r.getValue());
		});

		Optional.ofNullable(check.getConfidence()).ifPresent(c -> {
			alertBuilder.setConfidence(c.getValue());
		});

		Optional.ofNullable(check.getName()).filter(StringUtils::isNoneBlank).ifPresent(name -> {
			alertBuilder.setName(name);
		});

		Optional.ofNullable(check.getParam()).filter(StringUtils::isNoneBlank).ifPresent(param -> {
			alertBuilder.setParam(param);
		});

		Optional.ofNullable(check.getAttack()).filter(StringUtils::isNoneBlank).ifPresent(attack -> {
			alertBuilder.setAttack(attack);
		});

		Optional.ofNullable(check.getCweId()).filter(cweId -> cweId > -1).ifPresent(cweId -> {
			alertBuilder.setCweId(cweId);
		});

		Optional.ofNullable(check.getWacsId()).filter(wacsId -> wacsId > -1).ifPresent(wacsId -> {
			alertBuilder.setWascId(wacsId);
		});

		Optional.ofNullable(check.getAlertId()).filter(alertId -> alertId > -1).ifPresent(alertId -> {
			alertBuilder.setAlertId(alertId);
		});
	}
}
