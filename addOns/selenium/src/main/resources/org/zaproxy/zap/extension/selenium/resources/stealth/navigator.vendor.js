vendor = ''
if (navigator.userAgent.match('Chrom')) {
    vendor = 'Google Inc.'
}

utils.replaceGetterWithProxy(
    Object.getPrototypeOf(navigator),
    'vendor',
    utils.makeHandler().getterValue(vendor)
)
