package org.zaproxy.zap.extension.aem.yaml;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.zaproxy.zap.model.Tech;

public class ProductYAML {
	private String name;

	private int id;

	private Integer wacsId;

	private CategoryEnumYAML category;

	private List<String> tech = new ArrayList<>();

	private List<Tech> techList = new ArrayList<>();

	private RiskEnumYAML risk;

	private ConfidenceEnumYAML confidence;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public Integer getWacsId() {
		return wacsId;
	}

	public void setWacsId(Integer wacsId) {
		this.wacsId = wacsId;
	}

	public CategoryEnumYAML getCategory() {
		return category;
	}

	public void setCategory(CategoryEnumYAML category) {
		this.category = category;
	}

	public List<String> getTech() {
		return tech;
	}

	public void setTech(List<String> tech) {
		this.tech = tech;
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

	public void setTechList(List<Tech> techList) {
		this.techList = techList;
	}

	public List<Tech> getTechList() {
		if (CollectionUtils.isEmpty(techList)) {
			getTech().stream().forEach(str -> {
				try {
					Tech tech = (Tech) Tech.class.getField(str).get(null);
					techList.add(tech);
				} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException
						| SecurityException e) {
					e.printStackTrace();
				}
			});
		}
		return techList;
	}

}
