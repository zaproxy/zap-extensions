package org.zaproxy.gradle

data class WebDriverData(val os: OS, val browser: Browser, val arch: Arch, val zipped: Boolean = true) {
    enum class OS(val str: String) {
        LINUX("linux"),
        MAC("macos"),
        WIN("windows"),
    }

    enum class Browser(val webdriver: String) {
        CHROME("chromedriver"),
        FIREFOX("geckodriver"),
    }

    enum class Arch(val str: String) {
        X32("32"),
        X64("64"),
        ARM64("arm64"),
    }
}
