import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Product Scanner"

zapAddOn {
    addOnName.set("Product Scanner - Adobe AEM")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("Florian Neumair")
        url.set("")
        notBeforeVersion.set("2.10.0")
        extensions {
            register("org.zaproxy.zap.extension.prodscan.aem.ExtensionProdScanAdobeAEM")
        }
        bundle {
            baseName.set("org.zaproxy.zap.extension.prodScanAEM.resources.Messages")
            prefix.set("prodScanAEM")
        }
        dependencies {
            addOns {
                register("prodScan") {
                    version.set("1.*")
                }
            }
        }
    }
}

dependencies {
	compileOnly(parent!!.childProjects.get("prodScan")!!)
	
    // tests
    testImplementation(project(":testutils"))
    // reflections
    implementation("org.reflections:reflections:0.9.12")
    // commons collection
    implementation("org.apache.commons:commons-collections4:4.4")
}
