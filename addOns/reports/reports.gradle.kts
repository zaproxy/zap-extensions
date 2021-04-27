import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep

plugins {
    id("com.diffplug.spotless")
}

version = "0.3.0"
description = "Official ZAP Reports."

zapAddOn {
    addOnName.set("Report Generation")
    zapVersion.set("2.10.0")

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
                            version.set(">=0.2.0")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    implementation("org.thymeleaf:thymeleaf:3.0.12.RELEASE")
    implementation("org.xhtmlrenderer:flying-saucer-pdf:9.1.20")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.12.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.0")
    implementation("org.snakeyaml:snakeyaml-engine:2.2.1")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.14.1") {
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
