import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    id("eclipse")
}

eclipse {
    classpath {
        minusConfigurations.plusAssign(
            configurations.detachedConfiguration(
                dependencies.create("net.bytebuddy:byte-buddy:1.8.15"),
            ),
        )
    }
}

description = "Allows you to spider sites that make heavy use of JavaScript using Crawljax"

zapAddOn {
    addOnName.set("Ajax Spider")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/ajax-spider/")
        extensions {
            register("org.zaproxy.zap.extension.spiderAjax.automation.ExtensionAjaxAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.spiderAjax.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.42.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.23.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">=0.11.0")
                }
                register("selenium") {
                    version.set("15.*")
                }
            }
        }
    }

    val apiGenClasspath =
        configurations.detachedConfiguration(
            dependencies.create("org.zaproxy:zap:${zapVersion.get()}"),
            dependencies.create(parent!!.childProjects.get("selenium")!!),
        )

    apiClientGen {
        api.set("org.zaproxy.zap.extension.spiderAjax.AjaxSpiderAPI")
        options.set("org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/spiderAjax/resources/Messages.properties"))
        classpath.run {
            setFrom(apiGenClasspath)
            from(tasks.named(JavaPlugin.JAR_TASK_NAME))
        }
    }
}

dependencies {
    zapAddOn("selenium")
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("network")

    compileOnly(libs.log4j.core)

    implementation(files("lib/crawljax-core-3.7.1.jar"))
    implementation(libs.log4j.slf4j2)
    implementation(libs.spiderAjax.apache.commons.math)
    implementation(libs.spiderAjax.metricsCore)
    implementation(libs.spiderAjax.findBugsAnnotations)
    implementation(libs.spiderAjax.guiceAssistedInject) {
        // Not needed.
        exclude(group = "org.sonatype.sisu.inject", module = "cglib")
    }
    implementation(libs.spiderAjax.jcipAnnotations)
    implementation(libs.spiderAjax.nekohtml)
    implementation(libs.spiderAjax.julToSlf4j)
    implementation(libs.spiderAjax.xmlunit)

    testImplementation(libs.log4j.core)
    testImplementation(project(":testutils"))
}
