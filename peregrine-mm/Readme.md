Add to file vendor/cm/config/common.mk
PRODUCT_PROPERTY_OVERRIDES += ro.config.low_ram=true

or to a ROM
Edit /system/build.prop
ro.config.low_ram=true
