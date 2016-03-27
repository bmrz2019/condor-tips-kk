    <!-- Lockscreen falsing threshold for quick settings. -->
    <dimen name="qs_falsing_threshold">60dp</dimen>


frameworks/base/packages/SystemUI/res/values$ vi dimens.xml


Ideally change this
statusbar/phone/NotificationPanelView.java

    private boolean flingExpandsQs(float vel) {
        if (isBelowFalsingThreshold()) {
            return false;
        }
        if (Math.abs(vel) < mFlingAnimationUtils.getMinVelocityPxPerSecond()) {
            return getQsExpansionFraction() > 0.5f;
        } else {
            return vel > 0;
        }
    }
