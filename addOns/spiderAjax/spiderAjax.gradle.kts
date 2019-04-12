import org.zaproxy.gradle.addon.AddOnStatus

version = "23.0.0"
description = "Allows you to spider sites that make heavy use of JavaScript using Crawljax"

zapAddOn {
    addOnName.set("Ajax Spider")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsSpiderAjaxConcepts")
        dependencies {
            addOns {
                register("selenium") {
                    semVer.set("2.*")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.spiderAjax.AjaxSpiderAPI")
        options.set("org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/spiderAjax/resources/Messages.properties"))
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("selenium")!!)
    implementation(files("lib/crawljax-core-3.7.jar"))
    implementation("commons-math:commons-math:1.2")
    implementation("com.codahale.metrics:metrics-core:3.0.2")
    implementation("com.google.code.findbugs:jsr305:3.0.0")
    implementation("com.google.inject.extensions:guice-assistedinject:3.0") {
        // Not needed.
        exclude(group = "org.sonatype.sisu.inject", module = "cglib")
    }
    implementation("net.jcip:jcip-annotations:1.0")
    implementation("net.sourceforge.nekohtml:nekohtml:1.9.21") {
        // Not needed.
        exclude(group = "xerces", module = "xercesImpl")
    }
    implementation("org.slf4j:jcl-over-slf4j:1.7.6")
    implementation("org.slf4j:jul-to-slf4j:1.7.6")
    implementation("org.slf4j:slf4j-log4j12:1.7.6") {
        // Provided by ZAP.
        exclude(group = "log4j", module = "log4j")
    }
    implementation("xmlunit:xmlunit:1.5")
}
