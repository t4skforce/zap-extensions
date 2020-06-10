package org.zaproxy.zap.extension.aem.base;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.zaproxy.zap.extension.aem.util.AlertUtil;
import org.zaproxy.zap.extension.aem.util.HistoryUtil;
import org.zaproxy.zap.extension.aem.yaml.CategoryEnumYAML;
import org.zaproxy.zap.extension.aem.yaml.CheckYAML;
import org.zaproxy.zap.extension.aem.yaml.ProductYAML;
import org.zaproxy.zap.extension.aem.yaml.RequestYAML;
import org.zaproxy.zap.extension.aem.yaml.ResponseBodyYAML;
import org.zaproxy.zap.extension.aem.yaml.ResponseHeaderYAML;
import org.zaproxy.zap.extension.aem.yaml.ResponseYAML;
import org.zaproxy.zap.extension.aem.yaml.VulnerabilityYAML;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;
import org.zaproxy.zap.network.HttpResponseBody;

public abstract class YAMLThingyAbstractActiveHostScanner extends AbstractHostPlugin {
	private static Logger log = Logger.getLogger(YAMLThingyAbstractActiveHostScanner.class);

	private String name;

	private String description;

	private int category = Category.MISC;

	private String solution;

	private String reference;

	protected ProductYAML product;

	protected Path basePath;

	public YAMLThingyAbstractActiveHostScanner() {
		super();
		loadDefaults(getConfigPath());
	}

	protected abstract Path getConfigPath();

	private void loadDefaults(Path path) {
		if (product == null) {
			try {
				if (Files.exists(path) && Files.isRegularFile(path)) {
					basePath = path.getParent();
					if (!Files.isDirectory(basePath)) {
						throw new FileNotFoundException(basePath.toString());
					}

					product = new Yaml().loadAs(new FileInputStream(path.toFile()), ProductYAML.class);
					if (product.getWacsId() > -1) {
						Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_" + product.getWacsId());
						if (vuln != null) {
							name = vuln.getAlert();
							description = vuln.getDescription();
							solution = vuln.getSolution();
							reference = vuln.getReferences().stream().collect(Collectors.joining("\n"));
						}
					}
					name = Optional.ofNullable(product.getName()).orElse(this.getClass().getCanonicalName());
					category = Optional.ofNullable(product.getCategory()).map(CategoryEnumYAML::getValue)
							.orElse(category);
				}
			} catch (FileNotFoundException e) {
				log.error(e.getMessage(), e);
			}
		}
	}

	@Override
	public abstract int getId();

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public int getCategory() {
		return category;
	}

	@Override
	public String getSolution() {
		return solution;
	}

	@Override
	public String getReference() {
		return reference;
	}

	@Override
	public boolean targets(TechSet technologies) {
		return product != null && product.getTechList() != null
				&& product.getTechList().stream().anyMatch(t -> technologies.includes(t));
	}

	@Override
	public AttackStrength[] getAttackStrengthsSupported() {
		return new AttackStrength[] { AttackStrength.LOW, AttackStrength.MEDIUM, AttackStrength.HIGH,
				AttackStrength.INSANE };
	}

	@Override
	public AlertThreshold[] getAlertThresholdsSupported() {
		return new AlertThreshold[] { AlertThreshold.LOW, AlertThreshold.MEDIUM };
	}

	protected List<VulnerabilityYAML> getVulnerabilities() throws IOException {
		Path rulesPath = Paths.get(basePath.toString(), "active");

		if (Files.exists(rulesPath) && Files.isDirectory(rulesPath)) {
			PathMatcher ymlMatcher = FileSystems.getDefault().getPathMatcher("glob:*.yml");
			Yaml yml = new Yaml(new Constructor(VulnerabilityYAML.class));
			return Files.walk(rulesPath)
					.filter(filePath -> Files.isRegularFile(filePath) && ymlMatcher.matches(filePath)).map(filePath -> {
						try {
							return StreamSupport
									.stream(yml.loadAll(new FileInputStream(filePath.toFile())).spliterator(), false)
									.map(obj -> (VulnerabilityYAML) obj).collect(Collectors.toList());
						} catch (FileNotFoundException e) {
							log.error(e.getMessage(), e);
						}
						return null;
					}).filter(Objects::nonNull).flatMap(List::stream).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	@Override
	public void scan() {

	}

	public void scan2() {
		try {
			URI originalURI = getBaseMsg().getRequestHeader().getURI();

			for (VulnerabilityYAML alert : getVulnerabilities()) {
				for (CheckYAML check : alert.getChecks()) {
					RequestYAML request = check.getRequest();
					ResponseYAML response = check.getResponse();

					for (String path : request.getPaths()) {
						HttpRequestHeader reqheader = new HttpRequestHeader(
								request.getMethod().getValue(), new URI(originalURI.getScheme(),
										originalURI.getAuthority(), path, request.getQuery(), request.getFragment()),
								HttpHeader.HTTP11);

						if (MapUtils.isNotEmpty(request.getHeaders())) {
							for (Entry<String, String> entry : request.getHeaders().entrySet()) {
								reqheader.setHeader(entry.getKey(), entry.getValue());
							}
						}

						HttpMessage reqMsg = new HttpMessage(reqheader);
						this.sendAndReceive(reqMsg, request.isFollow());

						String evidence = null;
						boolean headerAlert = response.getHeader() == null;
						if (!headerAlert) {
							HttpResponseHeader header = reqMsg.getResponseHeader();
							ResponseHeaderYAML rheader = response.getHeader();
							headerAlert = rheader.alert(header);
							if (headerAlert) {
								evidence = rheader.evidence(header);
							}

						}
						boolean bodyAlert = response.getBody() == null;
						if (!bodyAlert) {
							HttpResponseBody body = reqMsg.getResponseBody();
							ResponseBodyYAML rbody = response.getBody();
							bodyAlert = rbody.alert(body);
							if (bodyAlert) {
								evidence = rbody.evidence(body);
							}
						}
						boolean raiseAlert = headerAlert && bodyAlert;

						if (raiseAlert) {
							final AlertBuilder alertBuilder = newAlert()
									.setUri(reqMsg.getRequestHeader().getURI().getURI()).setMessage(reqMsg);
							Optional.ofNullable(evidence).filter(StringUtils::isNoneBlank).ifPresent(ev -> {
								alertBuilder.setEvidence(ev);
							});
							AlertUtil.addVulnerabilityInfo(alert, alertBuilder);
							AlertUtil.addVulnerabilityInfo(check, alertBuilder);

							HistoryUtil.add(reqMsg, HistoryReference.TYPE_SPIDER, null, "AEM")
									.ifPresent(href -> alertBuilder.setHistoryRef(href));

							alertBuilder.raise();

							if (BooleanUtils.isTrue(request.isFirstMatch())) {

							}
						}
						if (isStop()) {
							return;
						}
					}
				}
			}

		} catch (IOException e) {
			log.error("Error scanning a Host with " + product.getName() + ": " + e.getMessage(), e);
		}
	}

}
