/crx/de/nodetypes.jsp
/libs/granite/csrf/token.json
/crx/server/crx.default/jcr%3aroot/.1.json
/crx/packmgr/index.jsp


https://www.json2yaml.com/
https://jsoup.org/cookbook/extracting-data/selector-syntax

# Exploit Talks Examples
https://github.com/0ang3el/aem-hacker/blob/master/aem_discoverer.py
https://github.com/0ang3el/aem-hacker/blob/master/aem_hacker.py
https://www.kernelpicnic.net/2016/07/24/Microsoft-signout.live.com-Remote-Code-Execution-Write-Up.html

# LineBreak
https://adapt.to/2019/en/schedule/securing-aem-webapps-by-hacking-them.html


# CVE-2016-0957
?.css

# SecureAEM
https://github.com/Cognifide/SecureAEM/blob/master/src/main/aem/jcr_root/etc/secureaem/content-grabbing/.content.xml
https://github.com/Cognifide/SecureAEM/blob/master/src/main/aem/jcr_root/etc/secureaem/feed-selector/.content.xml
https://github.com/Cognifide/SecureAEM/blob/master/src/main/aem/jcr_root/etc/secureaem/default-passwords/.content.xml
https://github.com/Cognifide/SecureAEM/blob/master/src/main/aem/jcr_root/etc/secureaem/dispatcher-access/.content.xml


# Sec Checklist
https://docs.adobe.com/content/help/de-DE/experience-manager-64/administering/security/security-checklist.translate.html
https://docs.adobe.com/content/help/en/experience-manager-dispatcher/using/getting-started/security-checklist.html


# Groovy Console
- download [aem-groovy-console](https://github.com/icfnext/aem-groovy-console)
- upload & install http://localhost:4502/crx/packmgr/index.jsp
- http://localhost:4502/system/console/configMgr -> "Groovy Console Configuration Service" -> Allowed Group + Vanity Path Enabled?

POST auf console -> kapsch pdf

DELETE http://localhost:4502/bin/groovyconsole/audit.json ???


# Configuring Dispatcher, Author and Publish Instance of Adobe Experience Manager (AEM)

AEM Author: The Author instance is used to design, create and review the content which will be published on the application in the future. The instance is located inside the organization’s firewall under full protection of the internal network. It provides an easy GUI for the tasks and uses the port 4502 by default.
AEM Publish: The Publish instance is used to make the designed application available to the public and is located in a demilitarized zone. The default port used by the instance is 4503.
AEM Dispatcher: The Dispatcher is another instance used in AEM which handles instance security, load balancing, and caching from the Publish instance.

https://www.tothenew.com/blog/configuring-dispatcher-author-and-publish-instance-of-adobe-experience-manager-aem/#:~:text=AEM%20Author%3A%20The%20Author%20instance,the%20application%20in%20the%20future.&text=AEM%20Publish%3A%20The%20Publish%20instance,located%20in%20a%20demilitarized%20zone.

# Apache Sling Framework v2.3.6 (Adobe AEM) [CVE-2016-0956] - Information Disclosure Vulnerability
Done: org.zaproxy.zap.extension.aem.checks.DefaultPostServlet


# CVE-2019-7964 SAML Bypass
## TODO
authentication bypass vulnerability in the Security Assertion Markup Language (SAML) handler in AEM versions 6.4 and 6.5.  Successful exploitation could result in unauthorized access to the AEM environment. 
https://pysaml2.readthedocs.io/en/latest/examples/idp.html


# Account Bruteforce (csrf/token)?
Wenn nanonymous user keinen Token bekommt und angemelderter user einen Token bekommt -> Bruteforce möglich
http://localhost:4502/libs/granite/csrf/token.json

https://docs.adobe.com/content/help/en/experience-manager-65/forms/administrator-help/configure-user-management/preventing-csrf-attacks.html -> Referer Header

https://docs.adobe.com/content/help/en/experience-manager-65/developing/introduction/csrf-protection.html
https://docs.adobe.com/content/help/en/experience-manager-dispatcher/using/configuring/configuring-dispatcher-to-prevent-csrf.html
https://experienceleaguecommunities.adobe.com/t5/adobe-experience-manager/libs-granite-csrf-token-json-query/td-p/324742

# User info?
http://localhost:4502/libs/cq/security/userinfo.json
{
	"userID": "admin",
	"userName": "Administrator",
	"userName_xss": "Administrator",
	"home": "/home/users/V/VvzHoqjYcjpbijKWoopJ",
	"impersonated": false,
	"allowedApps": [{
		"appName": "Websites",
		"appDescription": "Create and manage multiple websites.",
		"iconClass": "siteadmin",
		"path": "/libs/wcm/core/content/siteadmin",
		"vanityPath": "/siteadmin"
	}, {
		"appName": "Digital Assets",
		"appDescription": "Organize your various digital assets.",
		"iconClass": "damadmin",
		"path": "/libs/wcm/core/content/damadmin",
		"vanityPath": "/damadmin"
	}, {
		"appName": "Campaigns",
		"appDescription": "Manage your marketing campaigns.",
		"iconClass": "mcmadmin",
		"path": "/libs/mcm/content/admin",
		"vanityPath": "/mcmadmin"
	}, {
		"appName": "Inbox",
		"appDescription": "Manage your inbox items.",
		"iconClass": "inbox",
		"path": "/libs/cq/workflow/content/inbox",
		"vanityPath": "/inbox"
	}, {
		"appName": "Users",
		"appDescription": "Manage your users and groups.",
		"iconClass": "useradmin",
		"path": "/libs/cq/security/content/admin",
		"vanityPath": "/useradmin"
	}, {
		"appName": "Tools",
		"appDescription": "Maintain and configure your system.",
		"iconClass": "misc",
		"path": "/libs/wcm/core/content/misc",
		"vanityPath": "/miscadmin"
	}, {
		"appName": "Tagging",
		"appDescription": "Organize your tags and their namespaces.",
		"iconClass": "tagadmin",
		"path": "/libs/cq/tagging/content/tagadmin",
		"vanityPath": "/tagging"
	}],
	"preferences": {
		"granite.shell.showonboarding620": "false",
		"cq.authoring.editor.page.showOnboarding62": "true"
	}
}
http://localhost:4502/libs/granite/security/currentuser.json
{
	"type": "user",
	"authorizableId_xss": "admin",
	"authorizableId": "admin",
	"name_xss": "Administrator",
	"name": "Administrator",
	"home": "/home/users/V/VvzHoqjYcjpbijKWoopJ",
	"isImpersonated": false
}