Add to file vendor/cm/config/common.mk
PRODUCT_PROPERTY_OVERRIDES += ro.config.low_ram=true

or to a ROM
Edit /system/build.prop
ro.config.low_ram=true



    ldpi (low) ~120dpi
    mdpi (medium) ~160dpi
    hdpi (high) ~240dpi
    xhdpi (extra-high) ~320dpi
    xxhdpi (extra-extra-high) ~480dpi
    xxxhdpi (extra-extra-extra-high) ~640dpi

condor    256dpi 
peregrine 326dpi


We need wallpapers 1440x1280 drawable-xhdpi




Copy TheLonelyShepherd.ogg frameworks/base/data/sounds/ringtones/ogg/
