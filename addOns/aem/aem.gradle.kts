import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Product Scanner"

zapAddOn {
    addOnName.set("Adobe AEM Scanner")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("Florian Neumair")
        url.set("https://www.zaproxy.org/docs/desktop/addons/dom-xss-active-scan-rule/")
        // Don't search the add-on classes to prevent the inclusion
        // of the scanner, it's added/removed by the extension.
        //classpath.setFrom(files())
        bundle {
        	baseName.set("org.zaproxy.zap.extension.aem.resources.Messages")
            prefix.set("aem")
        }
        extensions {
            //register("org.zaproxy.zap.extension.productScanner.ExtensionProductScanner")
        }
        dependencies {
            addOns {
                //register("selenium") {
                //    version.set("15.*")
                //}
            }
        }
    }
}

dependencies {
	// tests
	testImplementation(project(":testutils"))
	
    //compileOnly(parent!!.childProjects.get("selenium")!!)
	implementation("org.yaml:snakeyaml:1.26")
	// json query
	implementation("net.thisptr:jackson-jq:1.0.0-preview.20191208")
    // html query
    implementation("org.jdom:jdom:1.1.3")
    implementation("org.jsoup:jsoup:1.7.2")
    // reflections
    implementation("org.reflections:reflections:0.9.12")
}
