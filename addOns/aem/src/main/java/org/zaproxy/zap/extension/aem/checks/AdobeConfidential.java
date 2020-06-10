package org.zaproxy.zap.extension.aem.checks;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.aem.util.HistoryUtil;
import org.zaproxy.zap.extension.aem.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.network.HttpResponseBody;

public class AdobeConfidential extends AbstractHostScan {
	private static final String JCR_REPOSITORY = "JCR repository";

	private static final String ADOBE_CONFIDENTIAL = "ADOBE CONFIDENTIAL";

	private static final String MESSAGE_PREFIX = "aem.static.files";

	// TODO: more files ?
	private static final List<String> PATHS = Arrays.asList("/libs/clientlibs/granite/richtext.js",
			"/libs/commerce/gui/components/admin/collections/addcollectiontoproduct/clientlibs.js",
			"/libs/commerce/gui/components/admin/orders/clientlibs3.js",
			"/libs/commerce/gui/components/admin/products/clientlibs.js",
			"/libs/commerce/gui/components/admin/products/images/clientlibs.js",
			"/libs/commerce/gui/components/common/assetpicker/clientlibs.js",
			"/libs/commerce/gui/components/common/collectionfield/clientlibs.js",
			"/libs/commerce/gui/components/common/productfield/clientlibs.js",
			"/libs/commerce/gui/components/common/promotionfield/clientlibs.js", "/libs/commerce/widgets.js",
			"/libs/cq/adobeims-configuration/components/admin/clientlibs/console.js", "/libs/cq/analytics/widgets.js",
			"/libs/cq/cloudservicesprovisioning/clientlibs/optinwizard.js",
			"/libs/cq/contentinsight/clientlibs/editor.js", "/libs/cq/contexthub/components/new-segment/clientlib.js",
			"/libs/cq/experience-fragments/components/admin/clientlib.js",
			"/libs/cq/experience-fragments/components/experiencefragment/clientlibs/xfconsole.js",
			"/libs/cq/experiencelog/clientlibs/optinwizard.js",
			"/libs/cq/gui/components/authoring/allowedcomponents/assettocomponent/mapper/clientlibs.js",
			"/libs/cq/gui/components/authoring/allowedcomponents/clientlib.js",
			"/libs/cq/gui/components/authoring/dialog/clientlibs/dialog.js",
			"/libs/cq/gui/components/authoring/dialog/fileupload/clientlibs/fileupload.js",
			"/libs/cq/gui/components/authoring/dialog/inplaceediting/configuration/clientlibs.js",
			"/libs/cq/gui/components/authoring/dialog/policy/clientlibs.js",
			"/libs/cq/gui/components/authoring/dialog/richtext/clientlibs/rte/coralui3.js",
			"/libs/cq/gui/components/authoring/dialog/slideshow/slideshow/slideshow.js",
			"/libs/cq/gui/components/authoring/dialog/style/clientlibs/editor.js",
			"/libs/cq/gui/components/authoring/rte/coralui3.js",
			"/libs/cq/gui/components/authoring/scaffolding/clientlibs.js",
			"/libs/cq/gui/components/authoring/searchfield/clientlibs/searchfield.js",
			"/libs/cq/gui/components/common/admin/csvexport/omnisearchlibs.js",
			"/libs/cq/gui/components/common/admin/customsearch/facetconfiguration/clientlibs/facetconfiguration.js",
			"/libs/cq/gui/components/common/admin/customsearch/searchpredicates/hiddenpredicate/clientlibs/hiddenpredicate.js",
			"/libs/cq/gui/components/common/admin/diffservice/clientlibs/diffservice.js",
			"/libs/cq/gui/components/common/clientlibs/common.js",
			"/libs/cq/gui/components/common/tagspicker/clientlibs.js",
			"/libs/cq/gui/components/common/wcm/clientlibs/wcm.js",
			"/libs/cq/gui/components/coral/common/admin/clientlibs/mediaportal.js",
			"/libs/cq/gui/components/coral/common/admin/customsearch/searchpredicates/daterangepredicate/clientlibs/daterangepredicate.js",
			"/libs/cq/gui/components/coral/common/admin/customsearch/searchpredicates/fulltextpredicate/clientlibs.js",
			"/libs/cq/gui/components/coral/common/admin/customsearch/searchpredicates/hiddenpredicate/clientlibs/hiddenpredicate.js",
			"/libs/cq/gui/components/coral/common/admin/timeline/alerts/workflow/clientlibs/workflow.js",
			"/libs/cq/gui/components/coral/common/admin/timeline/clientlibs/timeline.js",
			"/libs/cq/gui/components/coral/common/admin/timeline/events/comment/clientlibs/comment.js",
			"/libs/cq/gui/components/coral/common/admin/timeline/events/version/clientlibs/version.js",
			"/libs/cq/gui/components/coral/common/admin/timeline/events/workflow/clientlibs/workflow.js",
			"/libs/cq/gui/components/coral/common/form/tagfield/clientlibs/tagfield.js",
			"/libs/cq/gui/components/projects/admin/actions/delete/project/clientlibs.js",
			"/libs/cq/gui/components/projects/admin/card/projectcard/clientlib.js",
			"/libs/cq/gui/components/projects/admin/clientlibs/forms.js",
			"/libs/cq/gui/components/projects/admin/clientlibs/projects.js",
			"/libs/cq/gui/components/projects/admin/historytimeline/clientlibs.js",
			"/libs/cq/gui/components/projects/admin/inbox/inboxintegration.js",
			"/libs/cq/gui/components/projects/admin/properties/clientlibs.js",
			"/libs/cq/gui/components/siteadmin/admin/clientlibs/collectionpage.js",
			"/libs/cq/gui/components/siteadmin/admin/components/clientlibs.js",
			"/libs/cq/gui/components/siteadmin/admin/listview/coral/analytics/clientlibs/analytics.js",
			"/libs/cq/gui/components/siteadmin/admin/listview/coral/columns/clientlibs/columns.js",
			"/libs/cq/gui/components/siteadmin/admin/pagepreview/clientlibs/pagepreview.js",
			"/libs/cq/gui/components/siteadmin/admin/templates/clientlibs.js",
			"/libs/cq/inbox/gui/components/inbox/clientlibs/commons.js",
			"/libs/cq/inbox/gui/components/inbox/clientlibs/inbox.js",
			"/libs/cq/tagging/gui/components/admin/clientlibs/actions.js",
			"/libs/cq/tagging/gui/components/sidepanels/taginfo/clientlibs/taginfo.js",
			"/libs/cq/tagging/gui/layouts/column/tagcolumnpreview/clientlibs/tagcolumnpreview.js",
			"/libs/cq/testandtarget/clientlibs/properties-interceptor.js",
			"/libs/cq/translation/translationrules/clientlibs/contexts.js", "/libs/cq/ui/rte.js",
			"/libs/cq/ui/widgets.js", "/libs/cq/ui/widgets/themes/default.js",
			"/libs/cq/workflow/admin/console/components/clientlibs.js",
			"/libs/cq/workflow/admin/console/components/launchers/clientlibs.js",
			"/libs/dam/cfm/admin/clientlibs/admin.js", "/libs/dam/cfm/admin/clientlibs/api.js",
			"/libs/dam/cfm/admin/clientlibs/api/constants.js", "/libs/dam/cfm/admin/clientlibs/diffhighlighting.js",
			"/libs/dam/cfm/admin/clientlibs/versioncomparison.js", "/libs/dam/cfm/components/download/clientlib.js",
			"/libs/dam/cfm/models/console/clientlibs/actions.js",
			"/libs/dam/components/scene7/dynamicmedia/clientlibs/editor.js",
			"/libs/dam/components/scene7/panoramicmedia/clientlibs/editor.js",
			"/libs/dam/components/scene7/video360media/clientlibs/editor.js", "/libs/dam/components/scene7/widgets.js",
			"/libs/dam/gui/components/admin/clientlibs/damutil.js",
			"/libs/dam/gui/components/admin/clientlibs/uploadstatus.js",
			"/libs/dam/gui/components/s7dam/assetviewer/clientlibs/assetviewer.js",
			"/libs/dam/gui/components/s7dam/profiles/types/metadataprofiles/profilelist/clientlibs/profilelist.js",
			"/libs/dam/gui/coral/components/admin/assetdetails/assetnavigator/clientlibs/common.js",
			"/libs/dam/gui/coral/components/admin/assetdetails/assetnavigator/clientlibs/layout.js",
			"/libs/dam/gui/coral/components/admin/assetinsights/clientlibs/configurationwizard.js",
			"/libs/dam/gui/coral/components/admin/asyncjobs/clientlibs/actions.js",
			"/libs/dam/gui/coral/components/admin/asyncjobs/jobdetails/metadataexportfield/clientlib.js",
			"/libs/dam/gui/coral/components/admin/clientlibs/actions.js",
			"/libs/dam/gui/coral/components/admin/clientlibs/admin.js",
			"/libs/dam/gui/coral/components/admin/clientlibs/assetviewer.js",
			"/libs/dam/gui/coral/components/admin/clientlibs/damutil.js",
			"/libs/dam/gui/coral/components/admin/clientlibs/desktop.js",
			"/libs/dam/gui/coral/components/admin/clientlibs/lightbox.js",
			"/libs/dam/gui/coral/components/admin/collections/clientlibs/admin.js",
			"/libs/dam/gui/coral/components/admin/folderschemaforms/clientlibs/folderschemaforms.js",
			"/libs/dam/gui/coral/components/admin/metadataeditorcollection/clientlibs.js",
			"/libs/dam/gui/coral/components/admin/publish/clientlibs/publishasset.js",
			"/libs/dam/gui/coral/components/admin/references/clientlibs/references.js",
			"/libs/dam/gui/coral/components/admin/relateasset/clientlibs/relateasset.js",
			"/libs/dam/gui/coral/components/admin/reports/clientlibs/reportproperties.js",
			"/libs/dam/gui/coral/components/admin/schemaforms/clientlibs/schemaforms.js",
			"/libs/dam/gui/coral/components/admin/stock/clientlibs/actions.js",
			"/libs/dam/gui/coral/components/admin/timeline/events/version/clientlibs/version.js",
			"/libs/dam/gui/coral/components/admin/timeline/events/workflow/clientlibs/workflow.js",
			"/libs/dam/gui/coral/components/admin/unpublish/clientlibs/unpublishasset.js",
			"/libs/dam/gui/coral/components/commons/backhref/clientlibs.js",
			"/libs/dam/gui/coral/components/commons/navigationpanel/clientlibs/navigationpanel.js",
			"/libs/dam/gui/coral/components/s7dam/metadataprofiles/formselector/copymetadataform/clientlibs/copymetadataform.js",
			"/libs/dam/gui/coral/components/s7dam/profiles/generic/profilelist/clientlibs/profilelist.js",
			"/libs/dam/remoteassets/components/config/ui/clientlibs.js",
			"/libs/fd/fm/base/components/clientlibs/services.js", "/libs/fd/fm/base/components/clientlibs/util.js",
			"/libs/fd/fm/base/components/copyasset/clientlibs/copyasset.js",
			"/libs/fd/fm/base/components/deleteasset/clientlibs/deleteasset.js",
			"/libs/fd/fm/base/components/managefolder/clientlibs/managefolder.js",
			"/libs/fd/fm/gui/components/admin/adddictionary/clientlibs.js",
			"/libs/fd/fm/gui/components/admin/clientlibs/action.js",
			"/libs/fd/fm/gui/components/admin/clientlibs/admin.js",
			"/libs/fd/fm/gui/components/admin/copypaste/clientlibs/copypaste.js",
			"/libs/fd/fm/gui/components/admin/timeline/events/comment/clientlibs/comment.js",
			"/libs/fd/fm/gui/components/admin/util/clientlibs/util.js",
			"/libs/granite/author/deviceemulator/clientlibs.js", "/libs/granite/backup/clientlibs.js",
			"/libs/granite/cloudsettings/components/clientlibs.js",
			"/libs/granite/configurations/clientlibs/confbrowser.js", "/libs/granite/core/content/login/clientlib.js",
			"/libs/granite/datavisualization/clientlibs/cloudviz.js",
			"/libs/granite/distribution/clientlibs/distribution.js", "/libs/granite/oauth/clientlibs/clientlist.js",
			"/libs/granite/oauth/clientlibs/oauth.js", "/libs/granite/offloading/clientlibs/offloading.js",
			"/libs/granite/operations/clientlibs/diagnosis.js", "/libs/granite/operations/clientlibs/explain-query.js",
			"/libs/granite/operations/clientlibs/healthreports.js",
			"/libs/granite/operations/clientlibs/maintenance.js", "/libs/granite/operations/clientlibs/monitoring.js",
			"/libs/granite/operations/clientlibs/oak-index-manager.js",
			"/libs/granite/operations/clientlibs/sysoverview.js",
			"/libs/granite/security/clientlibs/authorizablelist.js", "/libs/granite/security/clientlibs/commons.js",
			"/libs/granite/security/clientlibs/sslconfig.js", "/libs/granite/security/clientlibs/v2/commons.js",
			"/libs/granite/security/clientlibs/v2/keystore.js", "/libs/granite/security/clientlibs/v2/usereditor.js",
			"/libs/granite/testing/components/testrunner/clientlibs.js", "/libs/granite/ui/clientlibs/annotations.js",
			"/libs/granite/ui/clientlibs/notifications.js", "/libs/granite/ui/components/shell/clientlibs/shell.js",
			"/libs/granite/ui/references/clientlibs/coral/references.js", "/libs/launches/components/clientlibs.js",
			"/libs/mcm/campaign/clientlibs/utils.js", "/libs/mcm/campaign/clientlibs/widgets.js",
			"/libs/mcm/widgets.js", "/libs/mcm/widgets/themes/default.js",
			"/libs/screens/clientlibs/tests/hobbes-extensions.js",
			"/libs/screens/core/components/dialogschedule/clientlibs/all.js",
			"/libs/screens/dcc/components/clientlibs.js", "/libs/screens/dcc/components/clientlibs/actions.js",
			"/libs/screens/dcc/components/clientlibs/dcc.js", "/libs/screens/player/browser/firmware.js",
			"/libs/social/commons/components/ugcparbase/clientlibs.js",
			"/libs/social/console/components/clientlibs/consoleinit/clientlibs.js",
			"/libs/social/console/components/hbs/defaultsrp/clientlibs.js",
			"/libs/social/console/components/hbs/grouptemplates/clientlibs.js",
			"/libs/social/console/components/hbs/sitecollection/clientlibs.js",
			"/libs/social/diagnostics/base/clientlibs-framework.js",
			"/libs/social/diagnostics/scenarios/user-group-sync-diagnostics/clientlibs.js",
			"/libs/social/gamification/components/hbs/badgecollection/clientlibs.js",
			"/libs/social/integrations/livefyre/cloudconfig/conf/components/admin/clientlibs.js",
			"/libs/social/integrations/livefyre/components/authorcomponents/authorclientlibs.js",
			"/libs/social/integrations/livefyre/components/authorcomponents/shared.js",
			"/libs/wcm/core/components/coral/references/borrowedcontent/clientlibs/borrowedcontent.js",
			"/libs/wcm/core/components/coral/references/languagecopy/clientlibs/languagecopy.js",
			"/libs/wcm/core/components/coral/references/shortenedlinks/clientlibs/shortenedlinks.js",
			"/libs/wcm/msm/components/coral/references/clientlibs/livecopy.js",
			"/libs/wcm/msm/content/touch-ui/authoring/commons.js", "/libs/wcm/msm/gui/components/clientlibs.js",
			"/system/sling.js");

	public static final int ID = 5001;

	@Override
	public int getId() {
		return ID;
	}

	@Override
	public int getCweId() {
		// CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
		// http://cwe.mitre.org/data/definitions/200.html
		return 200;
	}

	@Override
	public int getWascId() {
		return 1;
	}

	@Override
	public int getCategory() {
		return Category.INFO_GATHER;
	}

	@Override
	public int getRisk() {
		return Alert.RISK_INFO;
	}

	@Override
	public String getMessagePrefix() {
		return MESSAGE_PREFIX;
	}

	@Override
	public void doScan(HttpMessage baseMessage) throws Exception {
		PATHS.stream()
				.map(path -> HttpMessageWrapperUtil.get(getBaseMsg(), path).orElse(null))
				.filter(Objects::nonNull)
				.filter(sendAndReceive(msg -> {
					HttpResponseHeader header = msg.getResponseHeader();
					int statusCode = header.getStatusCode();
					if (header.getStatusCode() == 200 && header.isText()) {
						HttpResponseBody body = msg.getResponseBody();
						String bodyStr = body.toString();
						if (StringUtils.containsIgnoreCase(bodyStr, ADOBE_CONFIDENTIAL)) {
							msg.setNote(ADOBE_CONFIDENTIAL);
							return true;
						} else if (StringUtils.containsIgnoreCase(bodyStr, JCR_REPOSITORY)) {
							msg.setNote(JCR_REPOSITORY);
							return true;
						}
					} else if (statusCode >= 500) {
						// this could be interesting for passive rules
						HistoryUtil.addForPassiveScan(msg, "error");
					}
					return false;
				}, false))
				.forEach(msg -> {
					newAlert().setEvidence(msg.getNote()).setMessage(msg).setRisk(Alert.RISK_INFO).raise();
				});
	}

}
