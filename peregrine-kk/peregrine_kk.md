Running Moto G LTE for kitkat only

use.dedicated.device.for.voip=false
use.voice.path.for.pcm.voip=false

or 
---> peregrine-kk/out/target/product/peregrine/recovery/root/default.prop
---> peregrine-kk/out/target/product/peregrine/system/build.prop
or 
--> msm8226-common/system_prop.mk


    replaced 720.zip by aosp-caf bootanimation.zip from
    https://github.com/AOSP-CAF/platform_vendor_aosp/blob/mm6.0/prebuilt/common/media/bootanimation.zip

to change languages:
build/target/product/full_base.mk

device/motorola/msm8226-common/msm8226.mk
PRODUCT_AAPT_PREF_CONFIG := xhdpi
