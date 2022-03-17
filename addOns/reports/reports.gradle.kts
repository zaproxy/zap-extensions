import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    id("com.diffplug.spotless")
}

description = "Official ZAP Reports."

zapAddOn {
    addOnName.set("Report Generation")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/report-generation/")
        extensions {
            register("org.zaproxy.addon.reports.automation.ExtensionReportAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.reports.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.12.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.reports.ReportApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/reports/resources/Messages.properties"))
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    implementation("org.thymeleaf:thymeleaf:3.0.12.RELEASE")
    implementation("org.xhtmlrenderer:flying-saucer-pdf:9.1.22")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.13.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.0")
    implementation("org.snakeyaml:snakeyaml-engine:2.3")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.17.2") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(project(":testutils"))
}

spotless {
    format("html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(fileTree(projectDir) {
            include("src/**/*.html")
            exclude("src/main/zapHomeFiles/reports/risk-confidence-html/report.html")
            exclude("src/test/**/*.html")
        })
    })
    format("xml", {
        eclipseWtp(EclipseWtpFormatterStep.XML)
        target(fileTree(projectDir) {
            include("src/**/*.xml")
            exclude("src/test/**/*.xml")
        })
    })
}
