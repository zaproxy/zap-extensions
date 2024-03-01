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
                            version.set(">=0.31.0")
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

    val apiGenClasspath = configurations.detachedConfiguration(
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
    implementation("commons-math:commons-math:1.2")
    implementation("com.codahale.metrics:metrics-core:3.0.2")
    implementation("com.google.code.findbugs:jsr305:3.0.2")
    implementation("com.google.inject.extensions:guice-assistedinject:5.0.1") {
        // Not needed.
        exclude(group = "org.sonatype.sisu.inject", module = "cglib")
    }
    implementation("net.jcip:jcip-annotations:1.0")
    implementation("net.sourceforge.nekohtml:nekohtml:1.9.22")
    implementation("org.slf4j:jcl-over-slf4j:1.7.32")
    implementation("org.slf4j:jul-to-slf4j:1.7.32")
    implementation("org.slf4j:slf4j-log4j12:1.7.32") {
        // Provided by ZAP.
        exclude(group = "log4j", module = "log4j")
    }
    implementation("xmlunit:xmlunit:1.6")

    testImplementation(libs.log4j.core)
    testImplementation(project(":testutils"))
}
