/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.browser;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Picture;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.text.TextUtils;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewStub;
import android.webkit.ClientCertRequest;
import android.webkit.ConsoleMessage;
import android.webkit.CookieManager;
import android.webkit.GeolocationPermissions;
import android.webkit.GeolocationPermissions.Callback;
import android.webkit.HttpAuthHandler;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebBackForwardList;
import android.webkit.WebChromeClient;
import android.webkit.WebChromeClient.FileChooserParams;
import android.webkit.WebHistoryItem;
import android.webkit.WebResourceResponse;
import android.webkit.WebStorage;
import android.webkit.WebView;
import android.webkit.WebView.PictureListener;
import android.webkit.WebViewClient;
import android.widget.CheckBox;
import android.widget.Toast;

import com.android.browser.TabControl.OnThumbnailUpdatedListener;
import com.android.browser.homepages.HomeProvider;
import com.android.browser.provider.SnapshotProvider.Snapshots;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.util.LinkedList;
import java.util.Map;
import java.util.UUID;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

/**
 * Class for maintaining Tabs with a main WebView and a subwindow.
 */
class Tab implements PictureListener {

    // Log Tag
    private static final String LOGTAG = "Tab";
    private static final boolean LOGD_ENABLED = com.android.browser.Browser.LOGD_ENABLED;
    // Special case the logtag for messages for the Console to make it easier to
    // filter them and match the logtag used for these messages in older versions
    // of the browser.
    private static final String CONSOLE_LOGTAG = "browser";

    private static final int MSG_CAPTURE = 42;
    private static final int CAPTURE_DELAY = 100;
    private static final int INITIAL_PROGRESS = 5;

    private static Bitmap sDefaultFavicon;

    private static Paint sAlphaPaint = new Paint();
    static {
        sAlphaPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
        sAlphaPaint.setColor(Color.TRANSPARENT);
    }

    public enum SecurityState {
        // The page's main resource does not use SSL. Note that we use this
        // state irrespective of the SSL authentication state of sub-resources.
        SECURITY_STATE_NOT_SECURE,
        // The page's main resource uses SSL and the certificate is good. The
        // same is true of all sub-resources.
        SECURITY_STATE_SECURE,
        // The page's main resource uses SSL and the certificate is good, but
        // some sub-resources either do not use SSL or have problems with their
        // certificates.
        SECURITY_STATE_MIXED,
        // The page's main resource uses SSL but there is a problem with its
        // certificate.
        SECURITY_STATE_BAD_CERTIFICATE,
    }

    Context mContext;
    protected WebViewController mWebViewController;

    // The tab ID
    private long mId = -1;

    // The Geolocation permissions prompt
    private GeolocationPermissionsPrompt mGeolocationPermissionsPrompt;
    // The permissions prompt
    private PermissionsPrompt mPermissionsPrompt;
    // Main WebView wrapper
    private View mContainer;
    // Main WebView
    private WebView mMainView;
    // Subwindow container
    private View mSubViewContainer;
    // Subwindow WebView
    private WebView mSubView;
    // Saved bundle for when we are running low on memory. It contains the
    // information needed to restore the WebView if the user goes back to the
    // tab.
    private Bundle mSavedState;
    // Parent Tab. This is the Tab that created this Tab, or null if the Tab was
    // created by the UI
    private Tab mParent;
    // Tab that constructed by this Tab. This is used when this Tab is
    // destroyed, it clears all mParentTab values in the children.
    private Vector<Tab> mChildren;
    // If true, the tab is in the foreground of the current activity.
    private boolean mInForeground;
    // If true, the tab is in page loading state (after onPageStarted,
    // before onPageFinsihed)
    private boolean mInPageLoad;
    private boolean mDisableOverrideUrlLoading;
    // If true, the current page is the most visited page
    private boolean mInMostVisitedPage;
    // The last reported progress of the current page
    private int mPageLoadProgress;
    // The time the load started, used to find load page time
    private long mLoadStartTime;
    // Application identifier used to find tabs that another application wants
    // to reuse.
    private String mAppId;
    // flag to indicate if tab should be closed on back
    private boolean mCloseOnBack;
    // Keep the original url around to avoid killing the old WebView if the url
    // has not changed.
    // Error console for the tab
    private ErrorConsoleView mErrorConsole;
    // The listener that gets invoked when a download is started from the
    // mMainView
    private final BrowserDownloadListener mDownloadListener;
    // Listener used to know when we move forward or back in the history list.
    private final WebBackForwardListClient mWebBackForwardListClient;
    private DataController mDataController;
    // State of the auto-login request.
    private DeviceAccountLogin mDeviceAccountLogin;

    // AsyncTask for downloading touch icons
    DownloadTouchIcon mTouchIconLoader;

    private BrowserSettings mSettings;
    private int mCaptureWidth;
    private int mCaptureHeight;
    private Bitmap mCapture;
    private Handler mHandler;
    private boolean mUpdateThumbnail;

    /**
     * See {@link #clearBackStackWhenItemAdded(String)}.
     */
    private Pattern mClearHistoryUrlPattern;

    private static synchronized Bitmap getDefaultFavicon(Context context) {
        if (sDefaultFavicon == null) {
            sDefaultFavicon = BitmapFactory.decodeResource(
                    context.getResources(), R.drawable.app_web_browser_sm);
        }
        return sDefaultFavicon;
    }

    // All the state needed for a page
    protected static class PageState {
        String mUrl;
        String mOriginalUrl;
        String mTitle;
        SecurityState mSecurityState;
        // This is non-null only when mSecurityState is SECURITY_STATE_BAD_CERTIFICATE.
        SslError mSslCertificateError;
        Bitmap mFavicon;
        boolean mIsBookmarkedSite;
        boolean mIncognito;

        PageState(Context c, boolean incognito) {
            mIncognito = incognito;
            if (mIncognito) {
                mOriginalUrl = mUrl = "browser:incognito";
                mTitle = c.getString(R.string.new_incognito_tab);
            } else {
                mOriginalUrl = mUrl = "";
                mTitle = c.getString(R.string.new_tab);
            }
            mSecurityState = SecurityState.SECURITY_STATE_NOT_SECURE;
        }

        PageState(Context c, boolean incognito, String url, Bitmap favicon) {
            mIncognito = incognito;
            mOriginalUrl = mUrl = url;
            if (URLUtil.isHttpsUrl(url)) {
                mSecurityState = SecurityState.SECURITY_STATE_SECURE;
            } else {
                mSecurityState = SecurityState.SECURITY_STATE_NOT_SECURE;
            }
            mFavicon = favicon;
        }

    }

    // The current/loading page's state
    protected PageState mCurrentState;

    // Used for saving and restoring each Tab
    static final String ID = "ID";
    static final String CURRURL = "currentUrl";
    static final String CURRTITLE = "currentTitle";
    static final String PARENTTAB = "parentTab";
    static final String APPID = "appid";
    static final String INCOGNITO = "privateBrowsingEnabled";
    static final String USERAGENT = "useragent";
    static final String CLOSEFLAG = "closeOnBack";

    // Container class for the next error dialog that needs to be displayed
    private class ErrorDialog {
        public final int mTitle;
        public final String mDescription;
        public final int mError;
        ErrorDialog(int title, String desc, int error) {
            mTitle = title;
            mDescription = desc;
            mError = error;
        }
    }

    private void processNextError() {
        if (mQueuedErrors == null) {
            return;
        }
        // The first one is currently displayed so just remove it.
        mQueuedErrors.removeFirst();
        if (mQueuedErrors.size() == 0) {
            mQueuedErrors = null;
            return;
        }
        showError(mQueuedErrors.getFirst());
    }

    private DialogInterface.OnDismissListener mDialogListener =
            new DialogInterface.OnDismissListener() {
                public void onDismiss(DialogInterface d) {
                    processNextError();
                }
            };
    private LinkedList<ErrorDialog> mQueuedErrors;

    private void queueError(int err, String desc) {
        if (mQueuedErrors == null) {
            mQueuedErrors = new LinkedList<ErrorDialog>();
        }
        for (ErrorDialog d : mQueuedErrors) {
            if (d.mError == err) {
                // Already saw a similar error, ignore the new one.
                return;
            }
        }
        ErrorDialog errDialog = new ErrorDialog(
                err == WebViewClient.ERROR_FILE_NOT_FOUND ?
                R.string.browserFrameFileErrorLabel :
                R.string.browserFrameNetworkErrorLabel,
                desc, err);
        mQueuedErrors.addLast(errDialog);

        // Show the dialog now if the queue was empty and it is in foreground
        if (mQueuedErrors.size() == 1 && mInForeground) {
            showError(errDialog);
        }
    }

    private void showError(ErrorDialog errDialog) {
        if (mInForeground) {
            AlertDialog d = new AlertDialog.Builder(mContext)
                    .setTitle(errDialog.mTitle)
                    .setMessage(errDialog.mDescription)
                    .setPositiveButton(R.string.ok, null)
                    .create();
            d.setOnDismissListener(mDialogListener);
            d.show();
        }
    }

    // -------------------------------------------------------------------------
    // WebViewClient implementation for the main WebView
    // -------------------------------------------------------------------------

    private final WebViewClient mWebViewClient = new WebViewClient() {
        private Message mDontResend;
        private Message mResend;

        private boolean providersDiffer(String url, String otherUrl) {
            Uri uri1 = Uri.parse(url);
            Uri uri2 = Uri.parse(otherUrl);
            return !uri1.getEncodedAuthority().equals(uri2.getEncodedAuthority());
        }

        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            mInPageLoad = true;
            mUpdateThumbnail = true;
            mPageLoadProgress = INITIAL_PROGRESS;
            mCurrentState = new PageState(mContext,
                    view.isPrivateBrowsingEnabled(), url, favicon);
            mLoadStartTime = SystemClock.uptimeMillis();

            if (isPrivateBrowsingEnabled()) {
                // Ignore all the cookies while an incognito tab has activity
                CookieManager.getInstance().setAcceptCookie(false);
            }

            // If we start a touch icon load and then load a new page, we don't
            // want to cancel the current touch icon loader. But, we do want to
            // create a new one when the touch icon url is known.
            if (mTouchIconLoader != null) {
                mTouchIconLoader.mTab = null;
                mTouchIconLoader = null;
            }

            // reset the error console
            if (mErrorConsole != null) {
                mErrorConsole.clearErrorMessages();
                if (mWebViewController.shouldShowErrorConsole()) {
                    mErrorConsole.showConsole(ErrorConsoleView.SHOW_NONE);
                }
            }

            // Cancel the auto-login process.
            if (mDeviceAccountLogin != null) {
                mDeviceAccountLogin.cancel();
                mDeviceAccountLogin = null;
                mWebViewController.hideAutoLogin(Tab.this);
            }

            // finally update the UI in the activity if it is in the foreground
            mWebViewController.onPageStarted(Tab.this, view, favicon);

            updateBookmarkedStatus();
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            mDisableOverrideUrlLoading = false;
            if (!isPrivateBrowsingEnabled()) {
                LogTag.logPageFinishedLoading(
                        url, SystemClock.uptimeMillis() - mLoadStartTime);
            } else {
                // Ignored all the cookies while an incognito tab had activity,
                // restore default after completion
                CookieManager.getInstance().setAcceptCookie(mSettings.acceptCookies());
            }
            syncCurrentState(view, url);
            mWebViewController.onPageFinished(Tab.this);

            if (mCurrentState.mUrl.equals(HomeProvider.MOST_VISITED_URL)) {
                if (!mInMostVisitedPage) {
                    loadUrl(HomeProvider.MOST_VISITED, null);
                    mInMostVisitedPage = true;
                }
                view.clearHistory();
            } else {
                mInMostVisitedPage = false;
            }
        }

        // return true if want to hijack the url to let another app to handle it
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (!mDisableOverrideUrlLoading && mInForeground) {
                return mWebViewController.shouldOverrideUrlLoading(Tab.this,
                        view, url);
            } else {
                return false;
            }
        }

        /**
         * Updates the security state. This method is called when we discover
         * another resource to be loaded for this page (for example,
         * javascript). While we update the security state, we do not update
         * the lock icon until we are done loading, as it is slightly more
         * secure this way.
         */
        @Override
        public void onLoadResource(WebView view, String url) {
            if (url != null && url.length() > 0) {
                // It is only if the page claims to be secure that we may have
                // to update the security state:
                if (mCurrentState.mSecurityState == SecurityState.SECURITY_STATE_SECURE) {
                    // If NOT a 'safe' url, change the state to mixed content!
                    if (!(URLUtil.isHttpsUrl(url) || URLUtil.isDataUrl(url)
                            || URLUtil.isAboutUrl(url))) {
                        mCurrentState.mSecurityState = SecurityState.SECURITY_STATE_MIXED;
                    }
                }
            }
        }

        /**
         * Show a dialog informing the user of the network error reported by
         * WebCore if it is in the foreground.
         */
        @Override
        public void onReceivedError(WebView view, int errorCode,
                String description, String failingUrl) {
            if (errorCode != WebViewClient.ERROR_HOST_LOOKUP &&
                    errorCode != WebViewClient.ERROR_CONNECT &&
                    errorCode != WebViewClient.ERROR_BAD_URL &&
                    errorCode != WebViewClient.ERROR_UNSUPPORTED_SCHEME &&
                    errorCode != WebViewClient.ERROR_FILE) {
                queueError(errorCode, description);

                // Don't log URLs when in private browsing mode
                if (!isPrivateBrowsingEnabled()) {
                    Log.e(LOGTAG, "onReceivedError " + errorCode + " " + failingUrl
                        + " " + description);
                }
            }
        }

        /**
         * Check with the user if it is ok to resend POST data as the page they
         * are trying to navigate to is the result of a POST.
         */
        @Override
        public void onFormResubmission(WebView view, final Message dontResend,
                                       final Message resend) {
            if (!mInForeground) {
                dontResend.sendToTarget();
                return;
            }
            if (mDontResend != null) {
                Log.w(LOGTAG, "onFormResubmission should not be called again "
                        + "while dialog is still up");
                dontResend.sendToTarget();
                return;
            }
            mDontResend = dontResend;
            mResend = resend;
            new AlertDialog.Builder(mContext).setTitle(
                    R.string.browserFrameFormResubmitLabel).setMessage(
                    R.string.browserFrameFormResubmitMessage)
                    .setPositiveButton(R.string.ok,
                            new DialogInterface.OnClickListener() {
                                public void onClick(DialogInterface dialog,
                                        int which) {
                                    if (mResend != null) {
                                        mResend.sendToTarget();
                                        mResend = null;
                                        mDontResend = null;
                                    }
                                }
                            }).setNegativeButton(R.string.cancel,
                            new DialogInterface.OnClickListener() {
                                public void onClick(DialogInterface dialog,
                                        int which) {
                                    if (mDontResend != null) {
                                        mDontResend.sendToTarget();
                                        mResend = null;
                                        mDontResend = null;
                                    }
                                }
                            }).setOnCancelListener(new OnCancelListener() {
                        public void onCancel(DialogInterface dialog) {
                            if (mDontResend != null) {
                                mDontResend.sendToTarget();
                                mResend = null;
                                mDontResend = null;
                            }
                        }
                    }).show();
        }

        /**
         * Insert the url into the visited history database.
         * @param url The url to be inserted.
         * @param isReload True if this url is being reloaded.
         * FIXME: Not sure what to do when reloading the page.
         */
        @Override
        public void doUpdateVisitedHistory(WebView view, String url,
                boolean isReload) {
            mWebViewController.doUpdateVisitedHistory(Tab.this, isReload);
        }

        /**
         * Displays SSL error(s) dialog to the user.
         */
        @Override
        public void onReceivedSslError(final WebView view,
                final SslErrorHandler handler, final SslError error) {
            if (!mInForeground) {
                handler.cancel();
                setSecurityState(SecurityState.SECURITY_STATE_NOT_SECURE);
                return;
            }
            if (mSettings.showSecurityWarnings()) {
                new AlertDialog.Builder(mContext)
                    .setTitle(R.string.security_warning)
                    .setMessage(R.string.ssl_warnings_header)
                    .setIconAttribute(android.R.attr.alertDialogIcon)
                    .setPositiveButton(R.string.ssl_continue,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog,
                                    int whichButton) {
                                handler.proceed();
                                handleProceededAfterSslError(error);
                            }
                        })
                    .setNeutralButton(R.string.view_certificate,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog,
                                    int whichButton) {
                                mWebViewController.showSslCertificateOnError(
                                        view, handler, error);
                            }
                        })
                    .setNegativeButton(R.string.ssl_go_back,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog,
                                    int whichButton) {
                                dialog.cancel();
                            }
                        })
                    .setOnCancelListener(
                        new DialogInterface.OnCancelListener() {
                            @Override
                            public void onCancel(DialogInterface dialog) {
                                handler.cancel();
                                setSecurityState(SecurityState.SECURITY_STATE_NOT_SECURE);
                                mWebViewController.onUserCanceledSsl(Tab.this);
                            }
                        })
                    .show();
            } else {
                handler.proceed();
                handleProceededAfterSslError(error);
            }
        }

        /**
         * Displays client certificate request to the user.
         */
        @Override
        public void onReceivedClientCertRequest(final WebView view,
                final ClientCertRequest request) {
            if (!mInForeground) {
                request.ignore();
                return;
            }
            KeyChain.choosePrivateKeyAlias(
                    mWebViewController.getActivity(), new KeyChainAliasCallback() {
                @Override public void alias(String alias) {
                    if (alias == null) {
                        request.cancel();
                        return;
                    }
                    new KeyChainLookup(mContext, request, alias).execute();
                }
            }, request.getKeyTypes(), request.getPrincipals(), request.getHost(),
                request.getPort(), null);
        }

       /**
         * Handles an HTTP authentication request.
         *
         * @param handler The authentication handler
         * @param host The host
         * @param realm The realm
         */
        @Override
        public void onReceivedHttpAuthRequest(WebView view,
                final HttpAuthHandler handler, final String host,
                final String realm) {
            mWebViewController.onReceivedHttpAuthRequest(Tab.this, view, handler, host, realm);
        }

// add blocking here
//
        protected boolean isBlockedSite(String url) {
      // 	String url = uri.toString();
        Uri uri = Uri.parse(url);
		String host = uri.getHost();
//            	boolean useMostVisited = BrowserSettings.getInstance().useMostVisitedHomepage();
//     		String[] GS = GeneralPreferencesFragment.getInstance().mGoogleSites();
		String[] blockedSites = {"2mdn.net", "doubleclick.net",
				"0stats.com",
				"0tracker.com",
				"100im.info",
				"103bees.com",
				"11nux.com",
				"123compteur.com",
				"123count.com",
				"123-counter.de",
				"12mnkys.com",
				"149.13.65.144",
				"195.10.245.55",
				"1-cl0ud.com",
				"1freecounter.com",
				"1pel.com",
				"200summit.com",
				"204st.us",
				"206solutions.com",
				"212.227.100.108",
				"247ilabs.com",
				"24counter.com",
				"24log.com",
				"24log.de",
				"24log.ru",
				"2cnt.net",
				"2o7.net",
				"33across.com",
				"360i.com",
				"360tag.com",
				"360tag.net",
				"3dlivestats.com",
				"3dstats.com",
				"3gl.net",
				"4stats.de",
				"50bang.org",
				"51network.com",
				"51yes.com",
				"55labs.com",
				"62.160.52.73",
				"66.228.52.30",
				"67.228.151.70",
				"72.172.88.25",
				"74.55.82.102",
				"77tracking.com",
				"7bpeople.com",
				"8020solutions.net",
				"99click.com",
				"99counters.com",
				"99stats.com",
				"9nl.eu",
				"a013.com",
				"a8.net",
				"a8ww.net",
				"aaddzz.com",
				"aan.amazon.com",
				"abc.hearst.co.uk",
				"abcompteur.com",
				"abcounter.de",
				"abcstats.com",
				"abmr.net",
				"absolstats.co.za",
				"a-cast.jp",
				"access-analyze.org",
				"accessi.it",
				"accessintel.com",
				"access-traffic.com",
				"acecounter.com",
				"acestats.net",
				"acetrk.com",
				"acint.net",
				"acount.alley.ws",
				"a-counter.com.ua",
				"a-counter.kiev.ua",
				"a-counters.com",
				"acq.io",
				"acs86.com",
				"actionallocator.com",
				"active24stats.nl",
				"activeconversion.com",
				"activemeter.com",
				"activeprospects.com",
				"activetracker.activehotels.com",
				"active-tracking.de",
				"active-trk7.com",
				"acxiom-online.com",
				"adchemy.com",
				"adchemy-content.com",
				"adclear.net",
				"adclickstats.net",
				"adc-serv.net",
				"addcontrol.net",
				"addfreestats.com",
				"addlvr.com",
				"adelixir.com",
				"adgreed.com",
				"adinsight.com",
				"adinsight.eu",
				"adition.com",
				"adku.co",
				"adku.com",
				"admaster.com.cn",
				"admeld.com",
				"admob.com",
				"adnxs.com",
				"adobedtm.com",
				"adobetag.com",
				"adoftheyear.com",
				"adprotraffic.com",
				"adrank24.de",
				"adsensedetective.com",
				"adsettings.com",
				"adstat.4u.pl",
				"adtarget.me",
				"adtrack.calls.net",
				"adtraction.com",
				"adtraxx.de",
				"adultblogtoplist.com",
				"advanced-web-analytics.com",
				"advconversion.com",
				"adwords.google.com",
				"adzoe.de",
				"affilae.com",
				"affiliateedge.eu",
				"affiliates.minglematch.com",
				"affiliates-pro.com",
				"affiliates.spark.net",
				"affiliatetrackingsetup.com",
				"affiliation.planethoster.info",
				"affinesystems.com",
				"affinitymatrix.com",
				"affistats.com",
				"agencytradingdesk.net",
				"agentinteractive.com",
				"agillic.eu",
				"agilone.com",
				"agkn.com",
				"aimediagroup.com",
				"akstat.com",
				"alenty.com",
				"alexametrics.com",
				"alkemics.com",
				"alltagcloud.info",
				"alltracked.com",
				"alnera.eu",
				"altastat.com",
				"alvenda.com",
				"alzexa.com",
				"amadesa.com",
				"amazingcounters.com",
				"ambercrow.com",
				"amctp.net",
				"amikay.com",
				"a.mobify.com",
				"amung.us",
				"amxdt.com",
				"analoganalytics.com",
				"analysistools.net",
				"analytics.cnd-motionmedia.de",
				"analytics-egain.com",
				"analytics-engine.net",
				"analytics.loop-cloud.de",
				"analytics.twitter.com",
				"analyticswizard.com",
				"analytic.xingcloud.com",
				"analytk.com",
				"anametrix.com",
				"anametrix.net",
				"anatid3.com",
				"andersenit.dk",
				"andyhoppe.com",
				"angelfishstats.com",
				"announcement.ru",
				"anonymousdmp.com",
				"anormal-tracker.de",
				"anti-cheat.info",
				"a-pagerank.net",
				"apexstats.com",
				"apextwo.com",
				"apicit.net",
				"apkonline.ru",
				"apollofind.com",
				"aqtracker.com",
				"arcadeweb.com",
				"arena-quantum.co.uk",
				"arkayne.com",
				"arpuonline.com",
				"arturtrack.com",
				"assoctrac.com",
				"astro-way.com",
				"athenainstitute.biz",
				"atoshonetwork.com",
				"atraxio.com",
				"atsfi.de",
				"attracta.com",
				"audienceamplify.com",
				"audienceapi.newsdiscover.com.au",
				"audienceinsights.net",
				"audienceiq.com",
				"audiencerate.com",
				"audience.visiblemeasures.com",
				"audrte.com",
				"authorinsights.com",
				"autoaffiliatenetwork.com",
				"auto-ping.com",
				"avantlink.com",
				"avastats.com",
				"avazudsp.net",
				"avencio.de",
				"avmws.com",
				"avstat.it",
				"awasete.com",
				"axf8.net",
				"backlinkdino.de",
				"backlinkprofi.info",
				"backlinks.li",
				"backlinktausch.biz",
				"backlink-test.de",
				"backlink-umsonst.de",
				"baifendian.com",
				"baptisttop1000.com",
				"barilliance.net",
				"basicstat.com",
				"basilic.io",
				"baynote.net",
				"bbtrack.net",
				"beacon2.indieclicktv.com",
				"beacon.kmi-us.com",
				"beanscattering.jp",
				"bebj.com",
				"beemrdwn.com",
				"beencounter.com",
				"behavioralengine.com",
				"bekannt-im-web.de",
				"beliebtestewebseite.de",
				"belstat.at",
				"belstat.be",
				"belstat.ch",
				"belstat.com",
				"belstat.de",
				"belstat.fr",
				"belstat.nl",
				"benchit.com",
				"bestcontactform.com",
				"best-top.de",
				"best-top.ro",
				"bestweb2013stat.lk",
				"besucherstats.de",
				"besucherzaehler-counter.de",
				"besucherzaehler-homepage.de",
				"besucherzaehler.org",
				"besucherzaehler-zugriffszaehler.de",
				"besucherzahlen.com",
				"betarget.com",
				"betarget.de",
				"betarget.net",
				"bfoleyinteractive.com",
				"bhs4.com",
				"bidswitch.net",
				"bigmir.net",
				"bigstats.net",
				"bigtracker.com",
				"bionicclick.com",
				"bizible.com",
				"bizo.com",
				"bizspring.net",
				"bkrtx.com",
				"bkvtrack.com",
				"blizzardcheck.com",
				"blockmetrics.com",
				"blog104.com",
				"blogcounter.com",
				"blogcounter.de",
				"bloggeramt.de",
				"bloggerei.de",
				"blogmeetsbrand.com",
				"blog-o-rama.de",
				"blogpatrol.com",
				"blogrankers.com",
				"blogranking.net",
				"blogreaderproject.com",
				"blogscounter.com",
				"blogsontop.com",
				"blog-stat.com",
				"blogtoplist.com",
				"blogtraffic.de",
				"blogtraffic.sg",
				"blogtw.net",
				"blogverzeichnis.eu",
				"blog-webkatalog.de",
				"bluecava.com",
				"bluecounter.de",
				"bluekai.com",
				"blvdstatus.com",
				"bm23.com",
				"bm324.com",
				"bmlmedia.com",
				"bmmetrix.com",
				"bonitrust.de",
				"bonuscounter.de",
				"boomerang.com.au",
				"botscanner.com",
				"botsvisit.com",
				"bounceexchange.com",
				"brat-online.ro",
				"brcdn.com",
				"bridgevine.com",
				"brightedge.com",
				"brilig.com",
				"bronto.com",
				"browser-statistik.de",
				"brsrvr.com",
				"bstk.co",
				"btbuckets.com",
				"btstatic.com",
				"bttrack.com",
				"bubblestat.com",
				"bugherd.com",
				"bugsnag.com",
				"burstbeacon.com",
				"burt.io",
				"business.sharedcount.com",
				"bux1le001.com",
				"buzzdeck.com",
				"bytemgdd.com",
				"c3metrics.com",
				"c3tag.com",
				"c4tracking01.com",
				"cache.am",
				"cache.fm",
				"cadreon.com",
				"callisto.fm",
				"callmeasurement.com",
				"callrail.com",
				"call-tracking.co.uk",
				"calotag.com",
				"campaigncog.com",
				"canalstat.com",
				"caphyon-analytics.com",
				"cashburners.com",
				"cashcount.com",
				"castelein.nu",
				"cc-dt.com",
				"cdn.hiido.cn",
				"cdn.trafficexchangelist.com",
				"cedexis.com",
				"cedexis.net",
				"celebros-analytics.com",
				"centraltag.com",
				"certifica.com",
				"cetrk.com",
				"cftrack.com",
				"chartaca.com",
				"chartbeat.com",
				"chartbeat.net",
				"chart.dk",
				"checkeffect.at",
				"checkmypr.net",
				"checkstat.nl",
				"cheezburger-analytics.com",
				"c.hit.ua",
				"christiantop1000.com",
				"christmalicious.com",
				"chrumedia.com",
				"circle.am",
				"circular-counters.com",
				"cityua.net",
				"claritytag.com",
				"cleananalytics.com",
				"clearviewstats.com",
				"cleveritics.com",
				"clevi.com",
				"click1.email.nymagazine.com",
				"click2meter.com",
				"click4assistance.co.uk",
				"clickable.net",
				"clickaider.com",
				"clickalyzer.com",
				"clickanalyzer.jp",
				"click.aristotle.net",
				"clickclick.net",
				"clickcloud.info",
				"clickconversion.net",
				"clickdensity.com",
				"clickdimensions.com",
				"clickening.com",
				"clickforensics.com",
				"clicki.cn",
				"clickigniter.io",
				"clickinc.com",
				"click-linking.com",
				"clickmanage.com",
				"clickmap.ch",
				"clickmeter.com",
				"clickonometrics.pl",
				"clickpathmedia.com",
				"clickreport.com",
				"click.rssfwd.com",
				"clicksagent.com",
				"clicksen.se",
				"clickshift.com",
				"clickstream.co.za",
				"clicktale.net",
				"clickthru.lefbc.com",
				"clicktrack1.com",
				"clicktracks.com",
				"click-url.com",
				"clickzs.com",
				"clickzzs.nl",
				"client.tahono.com",
				"clixcount.com",
				"clixpy.com",
				"cloud-exploration.com",
				"clubcollector.com",
				"clustrmaps.com",
				"cmcore.com",
				"cmmeglobal.com",
				"cmptch.com",
				"cms.grandcloud.cn",
				"cms.lv",
				"cnstats.ru",
				"cnt1.net",
				"cnxweb.com",
				"cnzz.com",
				"cnzz.net",
				"codata.ru",
				"cogmatch.net",
				"cognitivematch.com",
				"collarity.com",
				"collserve.com",
				"company-target.com",
				"compteur.cc",
				"compteur.com",
				"compteur-gratuit.org",
				"confirmational.com",
				"confirmit.com",
				"contactmonkey.com",
				"contadordevisitas.es",
				"contadorgratis.com",
				"contadorgratis.es",
				"contadorweb.com",
				"contatoreaccessi.com",
				"contemporaryceremonies.ca",
				"contentspread.net",
				"contextly.com",
				"continue.com",
				"control.cityofcairns.com",
				"convergetrack.com",
				"conversionly.com",
				"conversionruler.com",
				"convertexperiments.com",
				"convertglobal.com",
				"convertmarketing.net",
				"convertro.com",
				"cooladata.com",
				"copacast.net",
				"copperegg.com",
				"coremetrics.com",
				"coremotives.com",
				"cormce.com",
				"cosmi.io",
				"count24.de",
				"countar.de",
				"countby.com",
				"c-o-u-n-t.com",
				"counted.at",
				"counter160.com",
				"counter27.ch",
				"counter4all.de",
				"counterbot.com",
				"countercentral.com",
				"counter-city.de",
				"countercity.de",
				"countercity.net",
				"counter.de",
				"counter.gd",
				"countergeo.com",
				"counter-go.de",
				"counter-gratis.com",
				"counter-kostenlos.info",
				"counter-kostenlos.net",
				"counterland.com",
				"counterlevel.de",
				"counter.nope.dk",
				"counter.ok.ee",
				"counteronline.de",
				"counter-pagerank.de",
				"counters4u.com",
				"counterseite.de",
				"counterserver.de",
				"counterservis.com",
				"countersforlife.com",
				"counterstation.de",
				"counterstatistik.de",
				"counter.top.ge",
				"counter.top.kg",
				"countertracker.com",
				"counter-treff.de",
				"counterviews.net",
				"counter.zone.ee",
				"count.fr",
				"counthis.com",
				"counti.de",
				"count.im",
				"countimo.de",
				"counting4free.com",
				"countingbiz.info",
				"countino.de",
				"countit.ch",
				"countnow.de",
				"counto.de",
				"countok.de",
				"countomat.com",
				"countus.fr",
				"countyou.de",
				"countz.com",
				"cpcmanager.com",
				"cqcounter.com",
				"craftkeys.com",
				"craktraffic.com",
				"crashlytics.com",
				"crazyegg.com",
				"criteo.net",
				"cr.loszona.com",
				"crmmetrix.fr",
				"crmmetrixwris.com",
				"crosspixel.net",
				"crosswalkmail.com",
				"crowdscience.com",
				"crowdtwist.com",
				"crsspxl.com",
				"crwdcntrl.net",
				"csbew.com",
				"csdata1.com",
				"csi-tracking.com",
				"css.aliyun.com",
				"ct.eid.co.nz",
				"ct.itbusinessedge.com",
				"ctnsnet.com",
				"ctr.nmg.de",
				"cts.businesswire.com",
				"cts.channelintelligence.com",
				"cts-log.channelintelligence.com",
				"cts-secure.channelintelligence.com",
				"ct.thegear-box.com",
				"cuntador.com",
				"customerconversio.com",
				"customerdiscoverytrack.com",
				"customer.io",
				"c-webstats.de",
				"cxense.com",
				"cxt.ms",
				"cya1t.net",
				"cya2.net",
				"cybermonitor.com",
				"cytoclause.com",
				"dacounter.com",
				"dailycaller-alerts.com",
				"dashboard.io",
				"data-analytics.jp",
				"data.beyond.com",
				"databrain.com",
				"datacaciques.com",
				"datafeedfile.com",
				"data.imakenews.com",
				"datam8.co.nz",
				"data.marketgid.com",
				"datamaster.com.cn",
				"datam.com",
				"datvantage.com",
				"daylife-analytics.com",
				"daylogs.com",
				"dc-storm.com",
				"dc.tremormedia.com",
				"de17a.com",
				"decdna.net",
				"decibelinsight.net",
				"decideinteractive.com",
				"dejavu.mlapps.com",
				"deliv.lexpress.fr",
				"demandbase.com",
				"demandmedia.s3.amazonaws.com",
				"demdex.net",
				"deqwas.net",
				"destinationurl.com",
				"dgmsearchlab.com",
				"dhmtracking.co.za",
				"did-it.com",
				"didit.com",
				"die-rankliste.com",
				"diffusion-tracker.com",
				"digidip.net",
				"digitaltarget.ru",
				"digits.com",
				"dignow.org",
				"dimestore.com",
				"dinkstat.com",
				"directcounter.de",
				"directrdr.com",
				"discover-path.com",
				"discovertrail.net",
				"displaymarketplace.com",
				"disquscdn.com",
				"disqus.com",
				"distralytics.com",
				"divolution.com",
				"djers.com",
				"dk-statistik.de",
				"dlrowehtfodne.com",
				"dmanalytics1.com",
				"dmclick.cn",
				"dmd53.com",
				"dmtracker.com",
				"dmtry.com",
				"doclix.com",
				"dominocounter.net",
				"domodomain.com",
				"dotmetrics.net",
				"doubleclick.net",
				"downture.in",
				"dreamcounter.de",
				"dsmmadvantage.com",
				"dsparking.com",
				"dsply.com",
				"d-stats.com",
				"dstrack2.info",
				"dti-ranker.com",
				"du8783wkf05yr.cloudfront.net",
				"dummy-domain-do-not-change.com",
				"durocount.com",
				"dv0.info",
				"dw.cbsi.com.cn",
				"dwin1.com",
				"dwin2.com",
				"dyntrk.com",
				"eanalyzer.de",
				"earnitup.com",
				"easycounter.com",
				"easy-hit-counters.com",
				"easyhitcounters.com",
				"easy.lv",
				"easyresearch.se",
				"easytracking.de",
				"ecn5.com",
				"ecommstats.com",
				"ecommstats.s3.amazonaws.com",
				"econda-monitor.de",
				"eco-tag.jp",
				"ec-track.com",
				"ecustomeropinions.com",
				"edgeadx.net",
				"edge.bredg.com",
				"edococounter.de",
				"edt02.net",
				"edtp.de",
				"edw.insideline.com",
				"effectivemeasure.net",
				"e.funnymel.com",
				"e-kaiseki.com",
				"ekmpinpoint.com",
				"ekmpinpoint.co.uk",
				"e-kuzbass.ru",
				"elitics.com",
				"eloqua.com",
				"email-match.com",
				"email-reflex.com",
				"emailretargeting.com",
				"emediatrack.com",
				"emltrk.com",
				"en25.com",
				"enectoanalytics.com",
				"enecto.com",
				"engine212.com",
				"engine64.com",
				"enhance.com",
				"enquisite.com",
				"ensighten.com",
				"enter-system.com",
				"enticelabs.com",
				"e-pagerank.net",
				"eperfectdata.com",
				"epilot.com",
				"epitrack.com",
				"eproof.com",
				"eps-analyzer.de",
				"e-referrer.com",
				"ereportz.com",
				"eresmas.net",
				"erotikcounter.org",
				"erotop.lv",
				"esearchvision.com",
				"esm1.net",
				"esomniture.com",
				"estadisticasgratis.com",
				"estadisticasgratis.es",
				"estara.com",
				"estat.com",
				"estrack.net",
				"etahub.com",
				"etherealhakai.com",
				"ethn.io",
				"ethnio.com",
				"etracker.com",
				"etracker.de",
				"etracking24.de",
				"etrafficcounter.com",
				"etrafficstats.com",
				"etrigue.com",
				"etyper.com",
				"euleriancdn.net",
				"eulerian.net",
				"eum-appdynamics.com",
				"euroads.dk",
				"eurocounter.com",
				"europagerank.com",
				"euro-pr.eu",
				"europuls.eu",
				"europuls.net",
				"eu-survey.com",
				"evanetpro.com",
				"eventtracker.videostrip.com",
				"everestjs.net",
				"everesttech.net",
				"evergage.com",
				"evisitanalyst.com",
				"evisitcs2.com",
				"evisitcs.com",
				"evolvemediametrics.com",
				"evyy.net",
				"ewebanalytics.com",
				"ewebcounter.com",
				"exactag.com",
				"exacttarget.com",
				"exapxl.de",
				"exclusiveclicks.com",
				"exelator.com",
				"exitmonitor.com",
				"exmarkt.de",
				"explore-123.com",
				"extole.com",
				"extreme-dm.com",
				"eyeota.net",
				"ezakus.net",
				"ezec.co.uk",
				"e-zeeinternet.com",
				"ezytrack.com",
				"fabricww.com",
				"facebook.com",
				"facebook.net",
				"factortg.com",
				"faibl.org",
				"farmer.wego.com",
				"fastanalytic.com",
				"fastonlineusers.com",
				"faststart.ru",
				"fastwebcounter.com",
				"fathomseo.com",
				"fbcdn.net",
				"fb.com",
				"fcstats.altervista.org",
				"fc.webmasterpro.de",
				"feedcat.net",
				"feedjit.com",
				"feedperfect.com",
				"ferank.fr",
				"fetchback.com",
				"filitrac.com",
				"finalid.com",
				"finderlocator.com",
				"find-ip-address.org",
				"fishhoo.com",
				"fixcounter.com",
				"flagcounter.com",
				"flashadengine.com",
				"flash-counter.com",
				"flashgamestats.com",
				"flash-stat.com",
				"flcounter.com",
				"flix360.com",
				"flixcar.com",
				"flixfacts.com",
				"flixfacts.co.uk",
				"flixsyndication.net",
				"flowstats.net",
				"fls-na.amazon.com",
				"fluctuo.com",
				"fluencymedia.com",
				"flurry.com",
				"flxpxl.com",
				"flyingpt.com",
				"followercounter.com",
				"footprintlive.com",
				"force24.co.uk",
				"foreseeresults.com",
				"formalyzer.com",
				"formisimo.com",
				"foundry42.com",
				"fout.jp",
				"fpctraffic2.com",
				"fprnt.com",
				"freebloghitcounter.com",
				"freecountercode.com",
				"free-counter.com",
				"free-counter.co.uk",
				"freecounter.it",
				"free-counters.co.uk",
				"free-counters.net",
				"freecounterstat.com",
				"freegeoip.net",
				"freehitscounter.org",
				"freelogs.com",
				"freeonlineusers.com",
				"freesitemapgenerator.com",
				"freestats.biz",
				"freestats.com",
				"freestats.me",
				"freestats.net",
				"freestats.org",
				"freestats.tk",
				"freestats.tv",
				"freestats.ws",
				"freestat.ws",
				"freetracker.biz",
				"freetrafficsystem.com",
				"freeusersonline.com",
				"freeweblogger.com",
				"free-website-hit-counters.com",
				"free-website-statistics.com",
				"freihit.de",
				"fremaks.net",
				"freshcounter.com",
				"freshplum.com",
				"frosmo.com",
				"fruitflan.com",
				"fshka.com",
				"fun-hits.com",
				"funneld.com",
				"funstage.com",
				"fusestats.com",
				"fuziontech.net",
				"fyreball.com",
				"gacela.eu",
				"gallupnet.fi",
				"gaug.es",
				"gbotvisit.com",
				"g.delivery.net",
				"gemius.pl",
				"gemtrackers.com",
				"generaltracking.de",
				"geobytes.com",
				"geocompteur.com",
				"geocontatore.com",
				"geoplugin.net",
				"getbackstory.com",
				"getclicky.com",
				"getcounter.de",
				"getfreebacklinks.com",
				"getfreebl.com",
				"getsidecar.com",
				"getsmartcontent.com",
				"getstatistics.se",
				"gezaehlt.de",
				"gigcount.com",
				"gixmo.dk",
				"glanceguide.com",
				"glbtracker.com",
				"globalviptraffic.com",
				"globase.com",
				"globel.co.uk",
				"globetrackr.com",
				"gmodmp.jp",
				"goaltraffic.com",
				"godhat.com",
				"goingup.com",
				"goldstats.com",
				"go-mpulse.net",
				"goneviral.com",
				"goodcounter.org",
				"googleadservices.com",
				"google-analytics.com",
				"googleapis.com",
				"google.com",
				"google-pr7.de",
				"googlerank.info",
				"google-rank.org",
				"googlesyndication.com",
				"googletagservices.com",
				"gooo.al",
				"gosquared.com",
				"gostats.com",
				"gostats.de",
				"go-stats.dlinkddns.com",
				"gostats.pl",
				"gostats.ro",
				"gostats.ru",
				"gostats.vn",
				"go.toutapp.com",
				"govmetric.com",
				"gpr.hu",
				"grapheffect.com",
				"graphinsider.com",
				"gratisbacklink.de",
				"gratis-besucherzaehler.de",
				"gratis-counter-gratis.de",
				"greatviews.de",
				"grepdata.com",
				"grfz.de",
				"gridsum.com",
				"gsimedia.net",
				"gstats.cn",
				"gtop.ro",
				"gtopstats.com",
				"guanoo.net",
				"gu-pix.appspot.com",
				"gvisit.com",
				"h4k5.com",
				"halldata.com",
				"halstats.com",
				"haveamint.com",
				"haymarket.com",
				"heals.msgfocus.com",
				"heapanalytics.com",
				"heatmap.it",
				"hellosherpa.com",
				"hentaicounter.com",
				"hetchi.com",
				"heystaks.com",
				"hiconversion.com",
				"hiddencounter.de",
				"higherengine.com",
				"highmetrics.com",
				"hiperstat.com",
				"hirmatrix.hu",
				"histats.com",
				"hit100.ro",
				"hit2map.com",
				"hitbox.com",
				"hit.copesa.cl",
				"hitcount.dk",
				"hit-counter-download.com",
				"hit-counter.info",
				"hit-counters.net",
				"hitcountersonline.com",
				"hitcounterstats.com",
				"hit-counts.com",
				"hitfarm.com",
				"hitgraph.jp",
				"hitmaster.de",
				"hitmatic.com",
				"hitmaze-counters.net",
				"hitmir.ru",
				"hit-parade.com",
				"hits2u.com",
				"hits.e.cl",
				"hitslink.com",
				"hitslog.com",
				"hitsniffer.com",
				"hitsprocessor.com",
				"hittail.com",
				"hittracker.com",
				"hitwake.com",
				"hitwebcounter.com",
				"hlserve.com",
				"hm.baidu.com",
				"homechader.com",
				"hopurl.org",
				"hostip.info",
				"hoststats.info",
				"host-tracker.com",
				"hot-count.com",
				"hotcounter.de",
				"hotlog.ru",
				"hotrank.com.tw",
				"hotstats.gr",
				"hottraffic.nl",
				"hqhrt.com",
				"hs-analytics.net",
				"hsdn.org",
				"hubrus.com",
				"humanclick.com",
				"hung.ch",
				"hunt-leads.com",
				"hurra.com",
				"hwpub.com",
				"hxtrack.com",
				"hyfntrak.com",
				"hypestat.com",
				"ib-ibi.com",
				"ibillboard.com",
				"ibpxl.com",
				"ibpxl.net",
				"ic-live.com",
				"iclive.com",
				"ics0.com",
				"icstats.nl",
				"ideoclick.com",
				"idio.co",
				"idot.cz",
				"idtargeting.com",
				"iesnare.com",
				"ifactz.com",
				"igaming.biz",
				"ihstats.cloudapp.net",
				"iivt.com",
				"iljmp.com",
				"illumenix.com",
				"ilogbox.com",
				"imcht.net",
				"imetrix.it",
				"imgstat.ameba.jp",
				"imp.affiliator.com",
				"imp.clickability.com",
				"imp.constantcontact.com",
				"impcounter.com",
				"imrtrack.com",
				"imrworldwide.com",
				"inboxtag.com",
				"incentivesnetwork.net",
				"indexstats.com",
				"indextools.com",
				"indicia.com",
				"individuad.net",
				"ineedhits.com",
				"inet-tracker.de",
				"inferclick.com",
				"infinity-tracking.net",
				"inflectionpointmedia.com",
				"infocollect.dk",
				"info.elba.at",
				"infostroy.nnov.ru",
				"ingenioustech.biz",
				"innovateads.com",
				"inphonic.com",
				"inpref.com",
				"inpref.s3.amazonaws.com",
				"inpwrd.com",
				"inside-graph.com",
				"insightera.com",
				"insightgrit.com",
				"insight.mintel.com",
				"insitemetrics.com",
				"inspectlet.com",
				"instadia.net",
				"instore.biz",
				"intelevance.com",
				"intelimet.com",
				"intelliad.de",
				"intelliad-tracking.com",
				"intelli-direct.com",
				"intelligencefocus.com",
				"intelli-tracker.com",
				"intentmedia.net",
				"interaktiv-net.de",
				"interceptum.com",
				"intergid.ru",
				"interhits.de",
				"interia.pl",
				"intermundomedia.com",
				"intervigil.com",
				"intrastats.com",
				"invitemedia.com",
				"invodo.com",
				"ip2location.com",
				"ip2map.com",
				"ip2phrase.com",
				"ip-adress.com",
				"ip-api.com",
				"ipcatch.com",
				"ipcounter.de",
				"ipcounter.net",
				"ipcount.net",
				"iperceptions.com",
				"ipfingerprint.com",
				"ipfrom.com",
				"ipinfodb.com",
				"ipinfo.info",
				"ipinfo.io",
				"ipinyou.com.cn",
				"ip-label.net",
				"iplocationtools.com",
				"ipro.com",
				"ipstat.com",
				"iptrack.biz",
				"ipv6monitoring.eu",
				"iraiser.eu",
				"irelandmetrix.ie",
				"irs09.com",
				"iryazan.ru",
				"i-stats.com",
				"istats.nl",
				"istrack.com",
				"ist-track.com",
				"italianadirectory.com",
				"itop.cz",
				"itrackerpro.com",
				"ivwbox.de",
				"iwebtrack.com",
				"ixiaa.com",
				"iyi.net",
				"izea.com",
				"izearanks.com",
				"japanmetrix.jp",
				"jetcounter.ru",
				"jiankongbao.com",
				"jimdo-stats.com",
				"jirafe.com",
				"jscounter.com",
				"jsid.info",
				"jstracker.com",
				"jumptime.com",
				"jump-time.net",
				"jwmstats.com",
				"kameleoon.com",
				"kampyle.com",
				"kavijaseuranta.fi",
				"keen.io",
				"keymetric.net",
				"keytrack.de",
				"keywordmax.com",
				"keywordstrategy.org",
				"kieden.com",
				"killerwebstats.com",
				"kissmetrics.com",
				"kisstesting.com",
				"kitcode.net",
				"klamm-counter.de",
				"klert.com",
				"klldabck.com",
				"kmindex.ru",
				"komtrack.com",
				"kono-research.de",
				"kontagent.net",
				"kopsil.com",
				"kostenlose-counter.com",
				"kupona.de",
				"landingpg.com",
				"laserstat.com",
				"lct.salesforce.com",
				"lddt.de",
				"lead-123.com",
				"lead-converter.com",
				"leadforce1.com",
				"leadforensics.com",
				"leadformix.com",
				"leadintelligence.co.uk",
				"leadium.com",
				"leadlife.com",
				"leadmanagerfx.com",
				"leadsius.com",
				"lead-tracking.biz",
				"leadvision.dotmailer.co.uk",
				"leadzu.com",
				"legenhit.com",
				"legolas-media.com",
				"leserservice-tracking.de",
				"les-experts.com",
				"letterboxtrail.com",
				"levexis.com",
				"lexity.com",
				"lfov.net",
				"liadm.com",
				"libstat.com",
				"linezing.com",
				"linkedin.com",
				"link-empfehlen24.de",
				"link.huffingtonpost.com",
				"linkpulse.com",
				"link-smart.com",
				"linktausch.li",
				"linktausch-pagerank.de",
				"linkxchanger.com",
				"listrakbi.com",
				"listtop.ru",
				"livecounter.dk",
				"livecount.fr",
				"livehit.net",
				"liverank.org",
				"livestat.com",
				"livestats.fr",
				"livewebstats.dk",
				"lloogg.com",
				"localytics.com",
				"lockview.cn",
				"log000.goo.ne.jp",
				"logaholic.com",
				"logcounter.com",
				"logdy.com",
				"logger.co.kr",
				"logger.su",
				"loggly.com",
				"log.kukuplay.com",
				"lognormal.net",
				"logua.com",
				"logxp.ru",
				"logz.ru",
				"lookery.com",
				"lookit.cz",
				"lookmy.info",
				"look.urs.tw",
				"loop11.com",
				"loopfuse.net",
				"lopley.com",
				"losecounter.de",
				"losstrack.com",
				"loyalty.bigdoor.com",
				"lp4.io",
				"lpbeta.com",
				"lporirxe.com",
				"lsfinteractive.com",
				"lucidel.com",
				"luckyorange.com",
				"lugansk-info.ru",
				"lumatag.co.uk",
				"lxtrack.com",
				"lypn.com",
				"lypn.net",
				"lytics.io",
				"lytiks.com",
				"m.addthisedge.com",
				"magiq.com",
				"magnetmail1.net",
				"magnify360.com",
				"mailstat.us",
				"maploco.com",
				"mapmyuser.com",
				"marinsm.com",
				"market015.com",
				"market2lead.com",
				"marketing-page.de",
				"marketo.net",
				"marktest.pt",
				"martianstats.com",
				"masterstats.com",
				"matheranalytics.com",
				"mathtag.com",
				"maxtracker.net",
				"maxymiser.com",
				"maxymiser.net",
				"mbotvisit.com",
				"m-brain.fi",
				"mbsy.co",
				"md-ia.info",
				"mdotlabs.com",
				"measure.ly",
				"measuremap.com",
				"mediaarmor.com",
				"mediaforgews.com",
				"mediagauge.com",
				"mediaindex.ee",
				"mediametrics.ru",
				"mediapartner.bigpoint.net",
				"mediaplan.ru",
				"mediaseeding.com",
				"meetrics.net",
				"megastat.net",
				"mega-stats.com",
				"melatstat.com",
				"memecounter.com",
				"mengis-linden.org",
				"mercadoclics.com",
				"mercent.com",
				"metalyzer.com",
				"meteorsolutions.com",
				"metering.pagesuite.com",
				"metricsdirect.com",
				"metriweb.be",
				"metro-trending-*.amazonaws.com",
				"mezzobit.com",
				"mialbj6.com",
				"micodigo.com",
				"microcounter.de",
				"midas-i.com",
				"midkotatraffic.net",
				"millioncounter.com",
				"minewhat.com",
				"mitmeisseln.de",
				"mixpanel.com",
				"mkt3261.com",
				"mkt51.net",
				"mkt941.com",
				"mktoresp.com",
				"ml314.com",
				"mlclick.com",
				"mletracker.com",
				"mlno6.com",
				"mlstat.com",
				"mm7.net",
				"mmetrix.mobi",
				"mmi-agency.com",
				"mmstat.com",
				"mmtro.com",
				"mobalyzer.net",
				"mobylog.jp",
				"mochibot.com",
				"modernus.is",
				"mokuz.ru",
				"monetate.net",
				"mongoosemetrics.com",
				"monitis.com",
				"monitus.net",
				"moreusers.info",
				"morevisits.info",
				"motorpresse-statistik.de",
				"motrixi.com",
				"mouseflow.com",
				"mousestats.com",
				"mousetrace.com",
				"movable-ink-6710.com",
				"m-pathy.com",
				"mplxtms.com",
				"mpstat.us",
				"mpwe.net",
				"mr-rank.de",
				"msgapp.com",
				"msgtag.com",
				"mstracker.net",
				"mtracking.com",
				"mtrack.nl",
				"mtrics.cdc.gov",
				"mts.mansion.com",
				"multicounter.de",
				"musiccounter.ru",
				"mvilivestats.com",
				"mvtracker.com",
				"mxcdn.net",
				"mxpnl.com",
				"mxptint.net",
				"myaffiliateprogram.com",
				"myaudience.de",
				"mybloglog.com",
				"mycounter.com.ua",
				"mycounter.ua",
				"myfastcounter.com",
				"mynewcounter.com",
				"myomnistar.com",
				"mypagerank.net",
				"my-ranking.de",
				"myreferer.com",
				"myroitracking.com",
				"myscoop-tracking.googlecode.com",
				"myseostats.com",
				"mysitetraffic.net",
				"mystat.hu",
				"mystat-in.net",
				"mystat.it",
				"my-stats.info",
				"mystats.nl",
				"mysumo.de",
				"mytictac.com",
				"myusersonline.com",
				"mywebstats.com.au",
				"mywebstats.org",
				"naayna.com",
				"naj.sk",
				"nakanohito.jp",
				"nalook.com",
				"natpal.com",
				"navdmp.com",
				"navegg.com",
				"navrcholu.cz",
				"naytev.com",
				"ncom.dk",
				"neatstats.com",
				"nedstatbasic.net",
				"nedstat.com",
				"nedstat.net",
				"nedstatpro.net",
				"neon-lab.com",
				"nestedmedia.com",
				"netagent.cz",
				"netcounter.de",
				"netdebit-counter.de",
				"net-filter.com",
				"netflame.cc",
				"netgraviton.net",
				"netminers.dk",
				"netmining.com",
				"netmng.com",
				"netmonitor.fi",
				"netratings.com",
				"netstats.dk",
				"netupdater.info",
				"netzaehler.de",
				"netzstat.ch",
				"newpoints.info",
				"newrelic.com",
				"newsanalytics.com.au",
				"newscurve.com",
				"newstatscounter.info",
				"newtrackmedia.com",
				"nextstat.com",
				"ngacm.com",
				"ngastatic.com",
				"ngmco.net",
				"nicewii.com",
				"niftymaps.com",
				"nik.io",
				"ninestats.com",
				"nonxt1.c.youtube.com",
				"noowho.com",
				"nordicresearch.com",
				"northclick-statistiken.de",
				"nowinteract.com",
				"npario-inc.net",
				"nprove.com",
				"nr7.us",
				"nstracking.com",
				"ntlab.org",
				"nuconomy.com",
				"numerino.cz",
				"nytlog.com",
				"oadz.com",
				"observare.de",
				"observerapp.com",
				"octopart-analytics.com",
				"odoscope.com",
				"oewabox.at",
				"offermatica.com",
				"offerpoint.net",
				"offers.keynote.com",
				"offerstrategy.com",
				"ogt.jp",
				"ohmystats.com",
				"oidah.com",
				"ojrq.net",
				"omeda.com",
				"ometria.com",
				"omnitagjs.com",
				"omtrdc.net",
				"onefeed.co.uk",
				"onestat.com",
				"ongsono.com",
				"on-line.lv",
				"online-media-stats.com",
				"online-metrix.net",
				"online-right-now.net",
				"onlinewebstat.com",
				"onlysix.co.uk",
				"opbandit.com",
				"openclick.com",
				"openhit.com",
				"openstat.net",
				"opentracker.net",
				"openvenue.com",
				"openxtracker.com",
				"oproi.com",
				"optify.net",
				"optimierung-der-website.de",
				"optimix.asia",
				"optimizely.appspot.com",
				"optimizely.com",
				"optimost.com",
				"optin-machine.com",
				"optorb.com",
				"optreadetrus.info",
				"oranges88.com",
				"orcapia.com",
				"org-dot-com.com",
				"orts.wixawin.com",
				"ospserver.net",
				"osxau.de",
				"otoshiana.com",
				"otracking.com",
				"ournet-analytics.com",
				"ourstats.de",
				"outboundlink.me",
				"overstat.com",
				"owldata.com",
				"oxidy.com",
				"p0.raasnet.com",
				"pagefair.com",
				"page-hit.de",
				"pagerank4you.eu",
				"pagerank-backlink.eu",
				"pagerankfree.com",
				"pagerank-hamburg.de",
				"pageranking-counter.de",
				"pageranking.li",
				"pagerank-linkverzeichnis.de",
				"pagerank-online.eu",
				"pagerank-suchmaschine.de",
				"pages05.net",
				"paidstats.com",
				"pa-oa.com",
				"parameter.dk",
				"pardot.com",
				"parklogic.com",
				"pass-1234.com",
				"pathful.com",
				"pc-agency24.de",
				"pclicks.com",
				"pcspeedup.com",
				"p.delivery.net",
				"peakcounter.dk",
				"peerius.com",
				"percentmobile.com",
				"perfectaudience.com",
				"perfiliate.com",
				"performancerevenues.com",
				"performtracking.com",
				"perion.com",
				"persianstat.com",
				"persianstat.ir",
				"personage.name",
				"personyze.com",
				"petametrics.com",
				"pf.aclst.com",
				"phonalytics.com",
				"phone-analytics.com",
				"phpstat.com",
				"pickzor.com",
				"pikzor.com",
				"pimpmypr.de",
				"pingagenow.com",
				"pingdom.net",
				"ping-fast.com",
				"pingomatic.com",
				"pixanalytics.com",
				"pixeleze.com",
				"pixelinteractivemedia.com",
				"pixel.parsely.com",
				"pixelrevenue.com",
				"pixelsnippet.com",
				"pixels.youknowbest.com",
				"pixel.xmladfeed.com",
				"piximedia.com",
				"pix.speedbit.com",
				"p.l1v.ly",
				"placemypixel.com",
				"platform.communicatorcorp.com",
				"plecki.com",
				"pleisty.com",
				"plexop.com",
				"plexworks.de",
				"plugin.ws",
				"pm0.net",
				"pm14.com",
				"pmbox.biz",
				"pocitadlo.cz",
				"pocitadlo.sk",
				"pointomatic.com",
				"polarmobile.com",
				"popsample.com",
				"popstats.com.br",
				"porngraph.com",
				"posst.co",
				"postaffiliatepro.com",
				"postclickmarketing.com",
				"postrank.com",
				"powerbar-pagerank.de",
				"powercount.com",
				"ppclocation.biz",
				"ppctracking.net",
				"p.raasnet.com",
				"pr-chart.com",
				"pr-chart.de",
				"prchecker.info",
				"precisioncounter.com",
				"predicta.net",
				"predictivedna.com",
				"predictiveresponse.net",
				"pr-link.eu",
				"pr-linktausch.de",
				"prnetwork.de",
				"prnx.net",
				"proclivitysystems.com",
				"productsup.com",
				"proext.com",
				"profilertracking3.com",
				"profilesnitch.com",
				"projecthaile.com",
				"projectsunblock.com",
				"projop.dnsalias.com",
				"propagerank.de",
				"prospecteye.com",
				"prostats.it",
				"provenpixel.com",
				"providence.voxmedia.com",
				"proxad.net",
				"pr-rang.de",
				"pr-sunshine.de",
				"pr-textlink.de",
				"prtracker.com",
				"pr-update.biz",
				"pstats.com",
				"psyma-statistics.com",
				"p-td.com",
				"ptp123.com",
				"publishflow.com",
				"publish.pizzazzemail.com",
				"pulleymarketing.com",
				"pulselog.com",
				"pulsemaps.com",
				"puls.lv",
				"pureairhits.com",
				"purevideo.com",
				"putags.com",
				"px.dynamicyield.com",
				"qbaka.net",
				"qbop.com",
				"q-counter.com",
				"qdtracking.com",
				"qsstats.com",
				"q-stats.nl",
				"qualtrics.com",
				"qubitproducts.com",
				"questionpro.com",
				"questradeaffiliates.com",
				"quick-counter.net",
				"quillion.com",
				"quintelligence.com",
				"qzlog.com",
				"r7ls.net",
				"radarstats.com",
				"radarurl.com",
				"rampmetrics.com",
				"rank4all.eu",
				"rankchamp.de",
				"rank-hits.com",
				"ranking-charts.de",
				"ranking-counter.de",
				"ranking-hits.de",
				"ranking-it.de",
				"ranking-links.de",
				"rankingpartner.com",
				"rankings24.de",
				"rankinteractive.com",
				"ranklink.de",
				"rank-power.com",
				"rapidcounter.com",
				"rapidstats.net",
				"rating.in",
				"reachforce.com",
				"reachsocket.com",
				"reactful.com",
				"readertracking.com",
				"readnotify.com",
				"real5traf.ru",
				"realcounter.eu",
				"realcounters.com",
				"realist.gen.tr",
				"realtimeplease.com",
				"realtimewebstats.net",
				"realtracker.com",
				"recoset.com",
				"recs.atgsvcs.com",
				"redcounter.net",
				"redir.widdit.com",
				"redstatcounter.com",
				"reedbusiness.net",
				"reedge.com",
				"referer.org",
				"referforex.com",
				"referlytics.com",
				"referrer.org",
				"refersion.com",
				"refinedads.com",
				"reinvigorate.net",
				"reitingas.lt",
				"reitingi.lv",
				"rejestr.org",
				"relead.com",
				"relmaxtop.com",
				"remarketstats.com",
				"reporting.reactlite.com",
				"research-artisan.com",
				"research.de.com",
				"researchintel.com",
				"research-int.se",
				"researchnow.co.uk",
				"research-tool.com",
				"reseau-pub.com",
				"reson8.com",
				"responsetap.com",
				"res-x.com",
				"retags.us",
				"revenuepilot.com",
				"revenuescience.com",
				"revenuewire.net",
				"revolvermaps.com",
				"revsw.net",
				"rewardtv.com",
				"reztrack.com",
				"rfihub.com",
				"rhinoseo.com",
				"riastats.com",
				"richard-group.com",
				"richmetrics.com",
				"rightstats.com",
				"ritecounter.com",
				"rkdms.com",
				"rktu.com",
				"rlcdn.com",
				"r.movad.de",
				"rnengage.com",
				"rnlabs.com",
				"roia.biz",
				"roi-pro.com",
				"roi-rocket.net",
				"roiservice.com",
				"roispy.com",
				"roitesting.com",
				"roitracking.net",
				"roivista.com",
				"rollingcounters.com",
				"royalcount.de",
				"rrimpl.com",
				"rs0.co.uk",
				"rs6.net",
				"rsvpgenius.com",
				"rtfn.net",
				"rtoaster.jp",
				"rumanalytics.com",
				"rztrkr.com",
				"s3s-main.net",
				"sadv.dadapro.com",
				"sageanalyst.net",
				"saletrack.co.uk",
				"sapha.com",
				"sarevtop.com",
				"sarov.ws",
				"sayutracking.co.uk",
				"sayyac.com",
				"sayyac.net",
				"sbdtds.com",
				"scastnet.com",
				"schoolyeargo.com",
				"sciencerevenue.com",
				"scorecardresearch.com",
				"scoutanalytics.net",
				"scout.haymarketmedia.com",
				"scrippscontroller.com",
				"scriptil.com",
				"scripts21.com",
				"scriptshead.com",
				"searchfeed.com",
				"searchignite.com",
				"search.mediatarget.net",
				"searchplow.com",
				"secure.ifbyphone.com",
				"securepaths.com",
				"secure-pixel.com",
				"sedotracker.com",
				"sedotracker.de",
				"seehits.com",
				"seewhy.com",
				"segment-analytics.com",
				"segment.io",
				"segments.adap.tv",
				"seitwert.de",
				"selaris.com",
				"sellpoints.com",
				"semanticverses.com",
				"semasio.net",
				"semtracker.de",
				"sendtraffic.com",
				"sensic.net",
				"sensor.org.ua",
				"seo-master.net",
				"seomonitor.ro",
				"seomoz.org",
				"seoparts.net",
				"seoradar.ro",
				"sepyra.com",
				"serating.ru",
				"serious-partners.com",
				"servestats.com",
				"servustats.com",
				"sessioncam.com",
				"sexcounter.com",
				"sexystat.com",
				"shinystat.com",
				"shinystat.it",
				"shippinginsights.com",
				"shrinktheweb.com",
				"siftscience.com",
				"sig.gamerdna.com",
				"signup-way.com",
				"silverpop.com",
				"simplehitcounter.com",
				"simplereach.com",
				"simpli.fi",
				"simplycast.us",
				"singlefeed.com",
				"siteapps.com",
				"sitebot.cn",
				"sitebro.com",
				"sitebro.de",
				"sitebro.net",
				"sitebro.tw",
				"sitechart.dk",
				"sitecompass.com",
				"siteimprove.com",
				"sitelinktrack.com",
				"sitemeter.com",
				"sitereport.org",
				"sitestat.com",
				"site-submit.com.ua",
				"sitetagger.co.uk",
				"sitetag.us",
				"sitetistik.com",
				"sitetracker.com",
				"sitetraq.nl",
				"skyglue.com",
				"skylog.kz",
				"slingpic.com",
				"slogantrend.de",
				"smallseotools.com",
				"smartadserver.com",
				"smarterremarketer.net",
				"smart-ip.net",
				"smartracker.net",
				"smfsvc.com",
				"smileyhost.net",
				"smrtlnks.com",
				"smtad.net",
				"snaps.vidiemi.com",
				"sniphub.com",
				"snoobi.com",
				"snowsignal.com",
				"socialtrack.net",
				"socketanalytics.com",
				"sodoit.com",
				"softonic-analytics.net",
				"softonic.com",
				"sokrati.com",
				"sometrics.com",
				"sophus3.com",
				"spacehits.net",
				"space-link.de",
				"specialstat.com",
				"spectate.com",
				"speedcount.de",
				"speedcounter.net",
				"speedtracker.de",
				"speed-trap.com",
				"spelar.org",
				"spider-mich.com",
				"splittag.com",
				"splurgi.com",
				"splyt.com",
				"spn.ee",
				"sponsorcounter.de",
				"spotmx.com",
				"spring.de",
				"springmetrics.com",
				"spring-tns.net",
				"sptag1.com",
				"sptag2.com",
				"sptag3.com",
				"sptag.com",
				"spycounter.net",
				"spylog.com",
				"spylog.ru",
				"spywords.com",
				"squidanalytics.com",
				"srpx.net",
				"ssl4stats.de",
				"stat08.com",
				"stat24.com",
				"stat24.ru",
				"stat.4u.pl",
				"statcount.com",
				"statcounter.com",
				"statcounterfree.com",
				"statcounters.info",
				"stathat.com",
				"stathound.com",
				"static.parsely.com",
				"statisfy.net",
				"statistiche-free.com",
				"statistichegratis.net",
				"statistiche.it",
				"statistiche-web.com",
				"statistiche.ws",
				"statistics.m0lxcdn.kukuplay.com",
				"statistics.ro",
				"statistika.lv",
				"statistik-gallup.net",
				"statistik.motorpresse.de",
				"statistiq.com",
				"statistx.com",
				"statowl.com",
				"stat.pl",
				"stat.ringier.cz",
				"stats21.com",
				"stats2513.com",
				"stats2.algo.at",
				"stats2.com",
				"stats4all.com",
				"stats4free.de",
				"stats4u.lv",
				"stats4you.com",
				"statsadvance-01.net",
				"statsadv.dadapro.com",
				"stats-analytics.info",
				"statsbox.nl",
				"stats.clipprtv.com",
				"stats.cz",
				"stats.de",
				"statsforever.com",
				"stats.fr",
				"statsimg.com",
				"statsinsight.com",
				"statsit.com",
				"stats.lt",
				"statsmachine.com",
				"stats.nekapuzer.at",
				"statsrely.com",
				"statssheet.com",
				"statsview.it",
				"statswave.com",
				"stats.webstarts.com",
				"stats.whicdn.com",
				"stat.to.cupidplc.com",
				"stattooz.com",
				"stattrax.com",
				"statun.com",
				"statuncore.com",
				"statuscake.com",
				"stat.www.fi",
				"stcllctrs.com",
				"stcounter.com",
				"st.dynamicyield.com",
				"stealth.nl",
				"steelhousemedia.com",
				"stippleit.com",
				"stormcontainertag.com",
				"stormiq.com",
				"stroeerdigitalmedia.de",
				"strs.jp",
				"sub2tech.com",
				"submitnet.net",
				"suchmaschinen-ranking-hits.de",
				"sundaysky.com",
				"sunios.de",
				"supercounters.com",
				"superstat.info",
				"superstats.com",
				"surfcounters.com",
				"surfertracker.com",
				"surveyscout.com",
				"surveywriter.com",
				"survicate.com",
				"svtrd.com",
				"swfstats.com",
				"swiss-counter.com",
				"swoopgrid.com",
				"sxtracking.com",
				"synergy-e.com",
				"synthasite.net",
				"sysomos.com",
				"t4ft.de",
				"taboola.com",
				"tag4arm.com",
				"tagcommander.com",
				"tailtarget.com",
				"tamedia.ch",
				"t-analytics.com",
				"taps.io",
				"tapstream.com",
				"targetfuel.com",
				"tausch-link.de",
				"tbex.ru",
				"tcactivity.net",
				"tcimg.com",
				"t.devnet.com",
				"t.dgm-au.com",
				"tdstats.com",
				"tealiumiq.com",
				"telemetrytaxonomy.net",
				"telize.com",
				"teljari.is",
				"tellapart.com",
				"tendatta.com",
				"tentaculos.net",
				"terabytemedia.com",
				"teracent.com",
				"teracent.net",
				"teriotracker.de",
				"tetigi.com",
				"tetoolbox.com",
				"theadex.com",
				"thebestlinks.com",
				"thebrighttag.com",
				"thecounter.com",
				"thefreehitcounter.com",
				"thermstats.com",
				"thesearchagency.net",
				"thespecialsearch.com",
				"thestat.net",
				"tinycounter.com",
				"tinystat.ir",
				"tiser.com.au",
				"titag.com",
				"tmpjmp.com",
				"tmvtp.com",
				"tns-counter.ru",
				"tns-cs.net",
				"tns-gallup.dk",
				"tnsinternet.be",
				"toc.io",
				"top100bloggers.com",
				"top100webshops.com",
				"topblogarea.com",
				"top-bloggers.com",
				"topblogging.com",
				"top.chebra.lt",
				"top.dating.lt",
				"topdepo.com",
				"top.dkd.lt",
				"tophits4u.de",
				"toplist.cz",
				"toplist.eu",
				"toplist.sk",
				"top.lv",
				"topmalaysia.com",
				"topofblogs.com",
				"top-ro.ro",
				"topsite.lv",
				"topstat.com",
				"toptracker.ru",
				"torbit.com",
				"touchclarity.com",
				"tovery.net",
				"t.planvip.fr",
				"t.powerreviews.com",
				"trace-2000.com",
				"tracelytics.com",
				"tracemyip.org",
				"trace.qq.com",
				"tracer.jp",
				"tracetracking.net",
				"traceworks.com",
				"track2.me",
				"trackalyzer.com",
				"track.atgstores.com",
				"trackbar.info",
				"track.byzon.swelen.net",
				"trackcdn.com",
				"trackcmp.net",
				"trackconsole.com",
				"trackdiscovery.net",
				"trackedlink.net",
				"trackedweb.net",
				"track.effiliation.com",
				"tracker.myseofriend.net",
				"tracker.seoboost.net",
				"tracker.stats.in.th",
				"tracker.u-link.me",
				"trackfeed.com",
				"trackfreundlich.de",
				"trackicollect.ibase.fr",
				"tracking100.com",
				"tracking202.com",
				"tracking2.interweave.com",
				"tracking.badgeville.com",
				"tracking.bidmizer.com",
				"tracking.drsfostersmith.com",
				"tracking.edvisors.com",
				"tracking*.euroads.fi",
				"tracking.fccinteractive.com",
				"tracking.fits.me",
				"tracking.interweave.com",
				"trackinglabs.com",
				"tracking.maxcdn.com",
				"tracking.plattformad.com",
				"tracking.practicefusion.com",
				"tracking.sembox.it",
				"tracking.skyword.com",
				"tracking.sponsorpay.com",
				"tracking.worldmedia.net",
				"trackmyweb.net",
				"trackset.com",
				"trackset.it",
				"tracksy.com",
				"tracktrk.net",
				"trackword.biz",
				"trackyourstats.com",
				"tradelab.fr",
				"tradescape.biz",
				"traffic4u.nl",
				"traffic.belaydevelopment.com",
				"trafficby.net",
				"trafficengine.net",
				"trafficfacts.com",
				"trafficjoint.com",
				"trafficmaxx.de",
				"trafficregenerator.com",
				"traffikcntr.com",
				"trafic.ro",
				"trafikkfondet.no",
				"trafinfo.info",
				"trafit.com",
				"trafix.ro",
				"trafiz.net",
				"trailheadapp.com",
				"trail-web.com",
				"trakken.de",
				"trakksocial.googlecode.com",
				"trakzor.com",
				"treehousei.com",
				"trekmedia.net",
				"trendcounter.com",
				"trendcounter.de",
				"triggeredmessaging.com",
				"triggertag.gorillanation.com",
				"triggit.com",
				"trkme.net",
				"trk.pswec.com",
				"trovus.co.uk",
				"truehits3.gits.net.th",
				"truehits.in.th",
				"truehits.net",
				"tscapeplay.com",
				"tscounter.com",
				"tsk4.com",
				"tsk5.com",
				"tstlabs.co.uk",
				"tsw0.com",
				"ttwbs.channelintelligence.com",
				"tubetrafficcash.com",
				"twcount.com",
				"tylere.net",
				"t.ymlp275.net",
				"tynt.com",
				"tyxo.bg",
				"u5e.com",
				"uadx.com",
				"uapoisk.net",
				"uarating.com",
				"ubertags.com",
				"ubertracking.info",
				"ugdturner.com",
				"ukrre-tea.info",
				"ultrastats.it",
				"umbel.com",
				"unicaondemand.com",
				"universaltrackingcontainer.com",
				"up-rank.com",
				"upstats.ru",
				"uptimeviewer.com",
				"uptracs.com",
				"uralweb.ru",
				"urlbrief.com",
				"urlself.com",
				"urstats.de",
				"usabilitytools.com",
				"usabilla.com",
				"userchecker.info",
				"usercycle.com",
				"userdive.com",
				"userlook.com",
				"userneeds.dk",
				"useronlinecounter.com",
				"userreport.com",
				"users.51.la",
				"userzoom.com",
				"usuarios-online.com",
				"uzrating.com",
				"valuedopinions.co.uk",
				"vantage-media.net",
				"vbanalytics.com",
				"vdna-assets.com",
				"vdoing.com",
				"veduy.com",
				"veinteractive.com",
				"velaro.com",
				"ventivmedia.com",
				"vertical-leap.co.uk",
				"vertical-leap.net",
				"verticalscope.com",
				"verticalsearchworks.com",
				"vertster.com",
				"verypopularwebsite.com",
				"video.oms.eu",
				"videos.oms.eu",
				"videostat.com",
				"vidigital.ru",
				"viewar.org",
				"vihtori-analytics.fi",
				"vinlens.com",
				"vinsight.de",
				"viralninjas.com",
				"vira.ru",
				"virool.com",
				"virtualnet.co.uk",
				"visibility-stats.com",
				"visibli.com",
				"visioncriticalpanels.com",
				"visistat.com",
				"visitlog.net",
				"visitorglobe.com",
				"visitorinspector.com",
				"visitorjs.com",
				"visitorpath.com",
				"visitorprofiler.com",
				"visitor-stats.de",
				"visitor-track.com",
				"visitortracklog.com",
				"visitorville.com",
				"visits.lt",
				"visitstreamer.com",
				"visualdna.com",
				"visualdna-stats.com",
				"visualrevenue.com",
				"visualwebsiteoptimizer.com",
				"vivistats.com",
				"vivocha.com",
				"vizisense.net",
				"vizury.com",
				"vizzit.se",
				"vmmpxl.com",
				"vmm-satellite1.com",
				"vmm-satellite2.com",
				"vmp.boldchat.com",
				"vmss.boldchat.com",
				"vmtrk.com",
				"voicefive.com",
				"volgograd-info.ru",
				"vologda-info.ru",
				"voodooalerts.com",
				"votistics.com",
				"vtracker.net",
				"w3counter.com",
				"w55c.net",
				"waplog.net",
				"warlog.ru",
				"watch.teroti.com",
				"waudit.cz",
				"way2traffic.com",
				"webalytics.pw",
				"webcare.byside.com",
				"webclicktracker.com",
				"webcompteur.com",
				"web-controlling.org",
				"webcounter.co.za",
				"web-counter.net",
				"webcounter.ws",
				"webest.info",
				"webflowmetrics.com",
				"webforensics.co.uk",
				"webglstats.com",
				"webgozar.com",
				"webgozar.ir",
				"webhits.de",
				"webiqonline.com",
				"webkatalog.li",
				"webleads-tracker.com",
				"weblist.de",
				"weblog.com.ua",
				"webmasterplan.com",
				"webmeter.ws",
				"webmobile.ws",
				"webprospector.de",
				"webserviceaward.com",
				"webservis.gen.tr",
				"websiteceo.com",
				"website-hit-counters.com",
				"websiteperform.com",
				"websitesampling.com",
				"websitewelcome.com",
				"webspectator.com",
				"web-stat.com",
				"webstat.com",
				"webstatistika.lt",
				"webstatistika.lv",
				"webstatistik.odav.de",
				"web-stat.net",
				"webstat.net",
				"webstat.no",
				"webstats4u.com",
				"webstats.com",
				"webstat.se",
				"webstats.motigo.com",
				"webtalking.ru",
				"webtrack.biz",
				"webtracker.jp",
				"webtrafficagents.com",
				"webtraffic.se",
				"webtraffiq.com",
				"webtraffstats.net",
				"webtraxs.com",
				"webtrekk.de",
				"webtrekk.net",
				"webtrends.com",
				"webtrendslive.com",
				"webttracking.de",
				"webtuna.com",
				"web-visor.com",
				"webvisor.ru",
				"wecount4u.com",
				"weesh.co.uk",
				"welt-der-links.de",
				"wemfbox.ch",
				"whackedmedia.com",
				"whitepixel.com",
				"whoaremyfriends.com",
				"whoisonline.net",
				"whosclickingwho.com",
				"whoseesyou.com",
				"whoson.com",
				"whoson.creativemark.co.uk",
				"wikia-beacon.com",
				"wikiodeliv.com",
				"wildxtraffic.com",
				"wiredminds.de",
				"woopra.com",
				"woopra-ns.com",
				"worldlogger.com",
				"wos.lv",
				"wowanalytics.co.uk",
				"wpdstat.com",
				"wp-stats.com",
				"wrating.com",
				"wredint.com",
				"wstatslive.com",
				"wt-eu02.net",
				"wtp101.com",
				"wtstats.com",
				"wundercounter.com",
				"wunderloop.net",
				"www.hey.lt",
				"www-path.com",
				"www.rt-ns.ru",
				"wwwstats.info",
				"wysistat.com",
				"wzrk.co",
				"wzrkt.com",
				"xa-counter.com",
				"xclaimwords.net",
				"xclk-integracion.com",
				"xcounter.ch",
				"xg4ken.com",
				"xhit.com",
				"xiti.com",
				"xl-counti.com",
				"xplosion.de",
				"xref.io",
				"x-stat.de",
				"x-traceur.com",
				"xtractor.no",
				"xtremline.com",
				"xxxcounter.com",
				"xyztraffic.com",
				"yamanoha.com",
				"yapi.awe.sm",
				"yaudience.com",
				"ybotvisit.com",
				"ycctrk.co.uk",
				"yellowbrix.com",
				"yieldbot.com",
				"yieldsoftware.com",
				"yjtag.jp",
				"yoochoose.net",
				"youramigo.com",
				"your-counter.be",
				"ytsa.net",
				"zaehler.tv",
				"zdbb.net",
				"zdtag.com",
				"zebestof.com",
				"zenlivestats.com",
				"zero.kz",
				"zesep.com",
				"zipstat.dk",
				"zirve100.com",
				"ziyu.net",
				"zoomflow.com",
				"zoomino.com",
				"zoosnet.net",
				"zowary.com",
				"zqtk.net",
				"zroitracker.com",
				"zt-dst.com",
				};

	for (String sites : blockedSites) {
         for (String site : sites.split(" ")) {
            if (host.toLowerCase().endsWith(site.toLowerCase())) {
            	return true; 
            	}
         }
	}
	return false;
    }



        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view,
                String url) {


            boolean useMostVisited = BrowserSettings.getInstance().useMostVisitedHomepage();
            Uri uri = Uri.parse(url);

            if (useMostVisited && url.startsWith("content://")) {
                if (HomeProvider.AUTHORITY.equals(uri.getAuthority())) {
                    try {
                        InputStream ins = mContext.getApplicationContext().getContentResolver()
                            .openInputStream(Uri.parse(url + "/home"));
                        return new WebResourceResponse("text/html", "utf-8", ins);
                    } catch (java.io.FileNotFoundException e) {
                    }
                }
            }
            if (uri.getScheme().toLowerCase().equals("file")) {
                File file = new File(uri.getPath());
                try {
                    if (file.getCanonicalPath().startsWith(
                            mContext.getApplicationContext().getApplicationInfo().dataDir)) {
                        return new WebResourceResponse("text/html","UTF-8",
                                new ByteArrayInputStream(RESTRICTED.getBytes("UTF-8")));
                    }
                } catch (Exception ex) {
                    Log.e(LOGTAG, "Bad canonical path" + ex.toString());
                    try {
                        return new WebResourceResponse("text/html","UTF-8",
                                new ByteArrayInputStream(RESTRICTED.getBytes("UTF-8")));
                    } catch (java.io.UnsupportedEncodingException e) {
                    }
                }
            }
            
            if (url.equals("browser:incognito")||url.startsWith("about")||(!url.startsWith("http"))){
                // just do nothing
                Log.v(LOGTAG, "Detected incognito or about or data:// app store etc");
                }
                else if (url.startsWith("http")){
                    if (isBlockedSite(url)) {
                    Uri uri2 = Uri.parse(url);
                    return new WebResourceResponse("text/plain", "utf-8", 
                    new ByteArrayInputStream(("[The following URL was blocked " + uri2.getHost() + "]").getBytes()));
                    }
                }


            WebResourceResponse res = HomeProvider.shouldInterceptRequest(
                    mContext, url);
            return res;
        }

// until here
        @Override
        public boolean shouldOverrideKeyEvent(WebView view, KeyEvent event) {
            if (!mInForeground) {
                return false;
            }
            return mWebViewController.shouldOverrideKeyEvent(event);
        }

        @Override
        public void onUnhandledKeyEvent(WebView view, KeyEvent event) {
            if (!mInForeground) {
                return;
            }
            if (!mWebViewController.onUnhandledKeyEvent(event)) {
                super.onUnhandledKeyEvent(view, event);
            }
        }

        @Override
        public void onReceivedLoginRequest(WebView view, String realm,
                String account, String args) {
            new DeviceAccountLogin(mWebViewController.getActivity(), view, Tab.this, mWebViewController)
                    .handleLogin(realm, account, args);
        }

    };

    private void syncCurrentState(WebView view, String url) {
        // Sync state (in case of stop/timeout)
        mCurrentState.mUrl = view.getUrl();
        if (mCurrentState.mUrl == null) {
            mCurrentState.mUrl = "";
        }
        mCurrentState.mOriginalUrl = view.getOriginalUrl();
        mCurrentState.mTitle = view.getTitle();
        mCurrentState.mFavicon = view.getFavicon();
        if (!URLUtil.isHttpsUrl(mCurrentState.mUrl)) {
            // In case we stop when loading an HTTPS page from an HTTP page
            // but before a provisional load occurred
            mCurrentState.mSecurityState = SecurityState.SECURITY_STATE_NOT_SECURE;
            mCurrentState.mSslCertificateError = null;
        }
        mCurrentState.mIncognito = view.isPrivateBrowsingEnabled();
    }

    // Called by DeviceAccountLogin when the Tab needs to have the auto-login UI
    // displayed.
    void setDeviceAccountLogin(DeviceAccountLogin login) {
        mDeviceAccountLogin = login;
    }

    // Returns non-null if the title bar should display the auto-login UI.
    DeviceAccountLogin getDeviceAccountLogin() {
        return mDeviceAccountLogin;
    }

    // -------------------------------------------------------------------------
    // WebChromeClient implementation for the main WebView
    // -------------------------------------------------------------------------

    private final WebChromeClient mWebChromeClient = new WebChromeClient() {
        // Helper method to create a new tab or sub window.
        private void createWindow(final boolean dialog, final Message msg) {
            WebView.WebViewTransport transport =
                    (WebView.WebViewTransport) msg.obj;
            if (dialog) {
                createSubWindow();
                mWebViewController.attachSubWindow(Tab.this);
                transport.setWebView(mSubView);
            } else {
                final Tab newTab = mWebViewController.openTab(null,
                        Tab.this, true, true);
                transport.setWebView(newTab.getWebView());
            }
            msg.sendToTarget();
        }

        @Override
        public boolean onCreateWindow(WebView view, final boolean dialog,
                final boolean userGesture, final Message resultMsg) {
            // only allow new window or sub window for the foreground case
            if (!mInForeground) {
                return false;
            }
            // Short-circuit if we can't create any more tabs or sub windows.
            if (dialog && mSubView != null) {
                new AlertDialog.Builder(mContext)
                        .setTitle(R.string.too_many_subwindows_dialog_title)
                        .setIconAttribute(android.R.attr.alertDialogIcon)
                        .setMessage(R.string.too_many_subwindows_dialog_message)
                        .setPositiveButton(R.string.ok, null)
                        .show();
                return false;
            } else if (!mWebViewController.getTabControl().canCreateNewTab()) {
                new AlertDialog.Builder(mContext)
                        .setTitle(R.string.too_many_windows_dialog_title)
                        .setIconAttribute(android.R.attr.alertDialogIcon)
                        .setMessage(R.string.too_many_windows_dialog_message)
                        .setPositiveButton(R.string.ok, null)
                        .show();
                return false;
            }

            // Short-circuit if this was a user gesture.
            if (userGesture) {
                createWindow(dialog, resultMsg);
                return true;
            }

            // Allow the popup and create the appropriate window.
            final AlertDialog.OnClickListener allowListener =
                    new AlertDialog.OnClickListener() {
                        public void onClick(DialogInterface d,
                                int which) {
                            createWindow(dialog, resultMsg);
                        }
                    };

            // Block the popup by returning a null WebView.
            final AlertDialog.OnClickListener blockListener =
                    new AlertDialog.OnClickListener() {
                        public void onClick(DialogInterface d, int which) {
                            resultMsg.sendToTarget();
                        }
                    };

            // Build a confirmation dialog to display to the user.
            final AlertDialog d =
                    new AlertDialog.Builder(mContext)
                    .setIconAttribute(android.R.attr.alertDialogIcon)
                    .setMessage(R.string.popup_window_attempt)
                    .setPositiveButton(R.string.allow, allowListener)
                    .setNegativeButton(R.string.block, blockListener)
                    .setCancelable(false)
                    .create();

            // Show the confirmation dialog.
            d.show();
            return true;
        }

        @Override
        public void onRequestFocus(WebView view) {
            if (!mInForeground) {
                mWebViewController.switchToTab(Tab.this);
            }
        }

        @Override
        public void onCloseWindow(WebView window) {
            if (mParent != null) {
                // JavaScript can only close popup window.
                if (mInForeground) {
                    mWebViewController.switchToTab(mParent);
                }
                mWebViewController.closeTab(Tab.this);
            }
        }

        @Override
        public boolean onJsAlert(WebView view, String url, String message,
                JsResult result) {
            mWebViewController.getTabControl().setActiveTab(Tab.this);
            return false;
        }

        @Override
        public boolean onJsConfirm(WebView view, String url, String message,
                JsResult result) {
            mWebViewController.getTabControl().setActiveTab(Tab.this);
            return false;
        }

        @Override
        public boolean onJsPrompt(WebView view, String url, String message,
                String defaultValue, JsPromptResult result) {
            mWebViewController.getTabControl().setActiveTab(Tab.this);
            return false;
        }

        @Override
        public void onProgressChanged(WebView view, int newProgress) {
            mPageLoadProgress = newProgress;
            if (newProgress == 100) {
                mInPageLoad = false;
            }
            mWebViewController.onProgressChanged(Tab.this);
            if (mUpdateThumbnail && newProgress == 100) {
                mUpdateThumbnail = false;
            }
        }

        @Override
        public void onReceivedTitle(WebView view, final String title) {
            mCurrentState.mTitle = title;
            mWebViewController.onReceivedTitle(Tab.this, title);
        }

        @Override
        public void onReceivedIcon(WebView view, Bitmap icon) {
            mCurrentState.mFavicon = icon;
            mWebViewController.onFavicon(Tab.this, view, icon);
        }

        @Override
        public void onReceivedTouchIconUrl(WebView view, String url,
                boolean precomposed) {
            final ContentResolver cr = mContext.getContentResolver();
            // Let precomposed icons take precedence over non-composed
            // icons.
            if (precomposed && mTouchIconLoader != null) {
                mTouchIconLoader.cancel(false);
                mTouchIconLoader = null;
            }
            // Have only one async task at a time.
            if (mTouchIconLoader == null) {
                mTouchIconLoader = new DownloadTouchIcon(Tab.this, cr, view);
                mTouchIconLoader.execute(url);
            }
        }

        @Override
        public void onShowCustomView(View view,
                WebChromeClient.CustomViewCallback callback) {
            Activity activity = mWebViewController.getActivity();
            if (activity != null) {
                onShowCustomView(view, activity.getRequestedOrientation(), callback);
            }
        }

        @Override
        public void onShowCustomView(View view, int requestedOrientation,
                WebChromeClient.CustomViewCallback callback) {
            if (mInForeground) mWebViewController.showCustomView(Tab.this, view,
                    requestedOrientation, callback);
        }

        @Override
        public void onHideCustomView() {
            if (mInForeground) mWebViewController.hideCustomView();
        }

        /**
         * The origin has exceeded its database quota.
         * @param url the URL that exceeded the quota
         * @param databaseIdentifier the identifier of the database on which the
         *            transaction that caused the quota overflow was run
         * @param currentQuota the current quota for the origin.
         * @param estimatedSize the estimated size of the database.
         * @param totalUsedQuota is the sum of all origins' quota.
         * @param quotaUpdater The callback to run when a decision to allow or
         *            deny quota has been made. Don't forget to call this!
         */
        @Override
        public void onExceededDatabaseQuota(String url,
            String databaseIdentifier, long currentQuota, long estimatedSize,
            long totalUsedQuota, WebStorage.QuotaUpdater quotaUpdater) {
            mSettings.getWebStorageSizeManager()
                    .onExceededDatabaseQuota(url, databaseIdentifier,
                            currentQuota, estimatedSize, totalUsedQuota,
                            quotaUpdater);
        }

        /**
         * The Application Cache has exceeded its max size.
         * @param spaceNeeded is the amount of disk space that would be needed
         *            in order for the last appcache operation to succeed.
         * @param totalUsedQuota is the sum of all origins' quota.
         * @param quotaUpdater A callback to inform the WebCore thread that a
         *            new app cache size is available. This callback must always
         *            be executed at some point to ensure that the sleeping
         *            WebCore thread is woken up.
         */
        @Override
        public void onReachedMaxAppCacheSize(long spaceNeeded,
                long totalUsedQuota, WebStorage.QuotaUpdater quotaUpdater) {
            mSettings.getWebStorageSizeManager()
                    .onReachedMaxAppCacheSize(spaceNeeded, totalUsedQuota,
                            quotaUpdater);
        }

        /**
         * Instructs the browser to show a prompt to ask the user to set the
         * Geolocation permission state for the specified origin.
         * @param origin The origin for which Geolocation permissions are
         *     requested.
         * @param callback The callback to call once the user has set the
         *     Geolocation permission state.
         */
        @Override
        public void onGeolocationPermissionsShowPrompt(String origin,
                GeolocationPermissions.Callback callback) {
            if (mInForeground) {
                getGeolocationPermissionsPrompt().show(origin, callback);
            }
        }

        /**
         * Instructs the browser to hide the Geolocation permissions prompt.
         */
        @Override
        public void onGeolocationPermissionsHidePrompt() {
            if (mInForeground && mGeolocationPermissionsPrompt != null) {
                mGeolocationPermissionsPrompt.hide();
            }
        }

        @Override
        public void onPermissionRequest(PermissionRequest request) {
            if (!mInForeground) return;
            getPermissionsPrompt().show(request);
        }

        @Override
        public void onPermissionRequestCanceled(PermissionRequest request) {
            if (mInForeground && mPermissionsPrompt != null) {
                mPermissionsPrompt.hide();
            }
        }

        /* Adds a JavaScript error message to the system log and if the JS
         * console is enabled in the about:debug options, to that console
         * also.
         * @param consoleMessage the message object.
         */
        @Override
        public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
            if (mInForeground) {
                // call getErrorConsole(true) so it will create one if needed
                ErrorConsoleView errorConsole = getErrorConsole(true);
                errorConsole.addErrorMessage(consoleMessage);
                if (mWebViewController.shouldShowErrorConsole()
                        && errorConsole.getShowState() !=
                            ErrorConsoleView.SHOW_MAXIMIZED) {
                    errorConsole.showConsole(ErrorConsoleView.SHOW_MINIMIZED);
                }
            }

            // Don't log console messages in private browsing mode
            if (isPrivateBrowsingEnabled()) return true;

            String message = "Console: " + consoleMessage.message() + " "
                    + consoleMessage.sourceId() +  ":"
                    + consoleMessage.lineNumber();

            switch (consoleMessage.messageLevel()) {
                case TIP:
                    Log.v(CONSOLE_LOGTAG, message);
                    break;
                case LOG:
                    Log.i(CONSOLE_LOGTAG, message);
                    break;
                case WARNING:
                    Log.w(CONSOLE_LOGTAG, message);
                    break;
                case ERROR:
                    Log.e(CONSOLE_LOGTAG, message);
                    break;
                case DEBUG:
                    Log.d(CONSOLE_LOGTAG, message);
                    break;
            }

            return true;
        }

        /**
         * Ask the browser for an icon to represent a <video> element.
         * This icon will be used if the Web page did not specify a poster attribute.
         * @return Bitmap The icon or null if no such icon is available.
         */
        @Override
        public Bitmap getDefaultVideoPoster() {
            if (mInForeground) {
                return mWebViewController.getDefaultVideoPoster();
            }
            return null;
        }

        /**
         * Ask the host application for a custom progress view to show while
         * a <video> is loading.
         * @return View The progress view.
         */
        @Override
        public View getVideoLoadingProgressView() {
            if (mInForeground) {
                return mWebViewController.getVideoLoadingProgressView();
            }
            return null;
        }

        @Override
        public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> callback,
            FileChooserParams params) {
            if (mInForeground) {
                mWebViewController.showFileChooser(callback, params);
                return true;
            } else {
                return false;
            }
        }

        /**
         * Deliver a list of already-visited URLs
         */
        @Override
        public void getVisitedHistory(final ValueCallback<String[]> callback) {
            if (isPrivateBrowsingEnabled()) {
                callback.onReceiveValue(new String[0]);
            } else {
                mWebViewController.getVisitedHistory(callback);
            }
        }

    };

    // -------------------------------------------------------------------------
    // WebViewClient implementation for the sub window
    // -------------------------------------------------------------------------

    // Subclass of WebViewClient used in subwindows to notify the main
    // WebViewClient of certain WebView activities.
    private static class SubWindowClient extends WebViewClient {
        // The main WebViewClient.
        private final WebViewClient mClient;
        private final WebViewController mController;

        SubWindowClient(WebViewClient client, WebViewController controller) {
            mClient = client;
            mController = controller;
        }
        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            // Unlike the others, do not call mClient's version, which would
            // change the progress bar.  However, we do want to remove the
            // find or select dialog.
            mController.endActionMode();
        }
        @Override
        public void doUpdateVisitedHistory(WebView view, String url,
                boolean isReload) {
            mClient.doUpdateVisitedHistory(view, url, isReload);
        }
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            return mClient.shouldOverrideUrlLoading(view, url);
        }
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler,
                SslError error) {
            mClient.onReceivedSslError(view, handler, error);
        }
        @Override
        public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
            mClient.onReceivedClientCertRequest(view, request);
        }
        @Override
        public void onReceivedHttpAuthRequest(WebView view,
                HttpAuthHandler handler, String host, String realm) {
            mClient.onReceivedHttpAuthRequest(view, handler, host, realm);
        }
        @Override
        public void onFormResubmission(WebView view, Message dontResend,
                Message resend) {
            mClient.onFormResubmission(view, dontResend, resend);
        }
        @Override
        public void onReceivedError(WebView view, int errorCode,
                String description, String failingUrl) {
            mClient.onReceivedError(view, errorCode, description, failingUrl);
        }
        @Override
        public boolean shouldOverrideKeyEvent(WebView view,
                android.view.KeyEvent event) {
            return mClient.shouldOverrideKeyEvent(view, event);
        }
        @Override
        public void onUnhandledKeyEvent(WebView view,
                android.view.KeyEvent event) {
            mClient.onUnhandledKeyEvent(view, event);
        }
    }

    // -------------------------------------------------------------------------
    // WebChromeClient implementation for the sub window
    // -------------------------------------------------------------------------

    private class SubWindowChromeClient extends WebChromeClient {
        // The main WebChromeClient.
        private final WebChromeClient mClient;

        SubWindowChromeClient(WebChromeClient client) {
            mClient = client;
        }
        @Override
        public void onProgressChanged(WebView view, int newProgress) {
            mClient.onProgressChanged(view, newProgress);
        }
        @Override
        public boolean onCreateWindow(WebView view, boolean dialog,
                boolean userGesture, android.os.Message resultMsg) {
            return mClient.onCreateWindow(view, dialog, userGesture, resultMsg);
        }
        @Override
        public void onCloseWindow(WebView window) {
            if (window != mSubView) {
                Log.e(LOGTAG, "Can't close the window");
            }
            mWebViewController.dismissSubWindow(Tab.this);
        }
    }

    // -------------------------------------------------------------------------

    // Construct a new tab
    Tab(WebViewController wvcontroller, WebView w) {
        this(wvcontroller, w, null);
    }

    Tab(WebViewController wvcontroller, Bundle state) {
        this(wvcontroller, null, state);
    }

    Tab(WebViewController wvcontroller, WebView w, Bundle state) {
        mWebViewController = wvcontroller;
        mContext = mWebViewController.getContext();
        mSettings = BrowserSettings.getInstance();
        mDataController = DataController.getInstance(mContext);
        mCurrentState = new PageState(mContext, w != null
                ? w.isPrivateBrowsingEnabled() : false);
        mInPageLoad = false;
        mInForeground = false;

        mDownloadListener = new BrowserDownloadListener() {
            public void onDownloadStart(String url, String userAgent,
                    String contentDisposition, String mimetype, String referer,
                    long contentLength) {
                mWebViewController.onDownloadStart(Tab.this, url, userAgent, contentDisposition,
                        mimetype, referer, contentLength);
            }
        };
        mWebBackForwardListClient = new WebBackForwardListClient() {
            @Override
            public void onNewHistoryItem(WebHistoryItem item) {
                if (mClearHistoryUrlPattern != null) {
                    boolean match =
                        mClearHistoryUrlPattern.matcher(item.getOriginalUrl()).matches();
                    if (LOGD_ENABLED) {
                        Log.d(LOGTAG, "onNewHistoryItem: match=" + match + "\n\t"
                                + item.getUrl() + "\n\t"
                                + mClearHistoryUrlPattern);
                    }
                    if (match) {
                        if (mMainView != null) {
                            mMainView.clearHistory();
                        }
                    }
                    mClearHistoryUrlPattern = null;
                }
            }
        };

        mCaptureWidth = mContext.getResources().getDimensionPixelSize(
                R.dimen.tab_thumbnail_width);
        mCaptureHeight = mContext.getResources().getDimensionPixelSize(
                R.dimen.tab_thumbnail_height);
        updateShouldCaptureThumbnails();
        restoreState(state);
        if (getId() == -1) {
            mId = TabControl.getNextId();
        }
        setWebView(w);
        mHandler = new Handler() {
            @Override
            public void handleMessage(Message m) {
                switch (m.what) {
                case MSG_CAPTURE:
                    capture();
                    break;
                }
            }
        };
    }

    public boolean shouldUpdateThumbnail() {
        return mUpdateThumbnail;
    }

    /**
     * This is used to get a new ID when the tab has been preloaded, before it is displayed and
     * added to TabControl. Preloaded tabs can be created before restoreInstanceState, leading
     * to overlapping IDs between the preloaded and restored tabs.
     */
    public void refreshIdAfterPreload() {
        mId = TabControl.getNextId();
    }

    public void updateShouldCaptureThumbnails() {
        if (mWebViewController.shouldCaptureThumbnails()) {
            synchronized (Tab.this) {
                if (mCapture == null) {
                    mCapture = Bitmap.createBitmap(mCaptureWidth, mCaptureHeight,
                            Bitmap.Config.RGB_565);
                    mCapture.eraseColor(Color.WHITE);
                    if (mInForeground) {
                        postCapture();
                    }
                }
            }
        } else {
            synchronized (Tab.this) {
                mCapture = null;
                deleteThumbnail();
            }
        }
    }

    public void setController(WebViewController ctl) {
        mWebViewController = ctl;
        updateShouldCaptureThumbnails();
    }

    public long getId() {
        return mId;
    }

    void setWebView(WebView w) {
        setWebView(w, true);
    }

    /**
     * Sets the WebView for this tab, correctly removing the old WebView from
     * the container view.
     */
    void setWebView(WebView w, boolean restore) {
        if (mMainView == w) {
            return;
        }

        // If the WebView is changing, the page will be reloaded, so any ongoing
        // Geolocation permission requests are void.
        if (mGeolocationPermissionsPrompt != null) {
            mGeolocationPermissionsPrompt.hide();
        }

        if (mPermissionsPrompt != null) {
            mPermissionsPrompt.hide();
        }

        mWebViewController.onSetWebView(this, w);

        if (mMainView != null) {
            mMainView.setPictureListener(null);
            if (w != null) {
                syncCurrentState(w, null);
            } else {
                mCurrentState = new PageState(mContext, false);
            }
        }
        // set the new one
        mMainView = w;
        // attach the WebViewClient, WebChromeClient and DownloadListener
        if (mMainView != null) {
            mMainView.setWebViewClient(mWebViewClient);
            mMainView.setWebChromeClient(mWebChromeClient);
            // Attach DownloadManager so that downloads can start in an active
            // or a non-active window. This can happen when going to a site that
            // does a redirect after a period of time. The user could have
            // switched to another tab while waiting for the download to start.
            mMainView.setDownloadListener(mDownloadListener);
            TabControl tc = mWebViewController.getTabControl();
            if (tc != null && tc.getOnThumbnailUpdatedListener() != null) {
                mMainView.setPictureListener(this);
            }
            if (restore && (mSavedState != null)) {
                restoreUserAgent();
                WebBackForwardList restoredState
                        = mMainView.restoreState(mSavedState);
                if (restoredState == null || restoredState.getSize() == 0) {
                    Log.w(LOGTAG, "Failed to restore WebView state!");
                    loadUrl(mCurrentState.mOriginalUrl, null);
                }
                mSavedState = null;
            }
        }
    }

    /**
     * Destroy the tab's main WebView and subWindow if any
     */
    void destroy() {
        if (mMainView != null) {
            dismissSubWindow();
            // save the WebView to call destroy() after detach it from the tab
            WebView webView = mMainView;
            setWebView(null);
            webView.destroy();
        }
    }

    /**
     * Remove the tab from the parent
     */
    void removeFromTree() {
        // detach the children
        if (mChildren != null) {
            for(Tab t : mChildren) {
                t.setParent(null);
            }
        }
        // remove itself from the parent list
        if (mParent != null) {
            mParent.mChildren.remove(this);
        }
        deleteThumbnail();
    }

    /**
     * Create a new subwindow unless a subwindow already exists.
     * @return True if a new subwindow was created. False if one already exists.
     */
    boolean createSubWindow() {
        if (mSubView == null) {
            mWebViewController.createSubWindow(this);
            mSubView.setWebViewClient(new SubWindowClient(mWebViewClient,
                    mWebViewController));
            mSubView.setWebChromeClient(new SubWindowChromeClient(
                    mWebChromeClient));
            // Set a different DownloadListener for the mSubView, since it will
            // just need to dismiss the mSubView, rather than close the Tab
            mSubView.setDownloadListener(new BrowserDownloadListener() {
                public void onDownloadStart(String url, String userAgent,
                        String contentDisposition, String mimetype, String referer,
                        long contentLength) {
                    mWebViewController.onDownloadStart(Tab.this, url, userAgent,
                            contentDisposition, mimetype, referer, contentLength);
                    if (mSubView.copyBackForwardList().getSize() == 0) {
                        // This subwindow was opened for the sole purpose of
                        // downloading a file. Remove it.
                        mWebViewController.dismissSubWindow(Tab.this);
                    }
                }
            });
            mSubView.setOnCreateContextMenuListener(mWebViewController.getActivity());
            return true;
        }
        return false;
    }

    /**
     * Dismiss the subWindow for the tab.
     */
    void dismissSubWindow() {
        if (mSubView != null) {
            mWebViewController.endActionMode();
            mSubView.destroy();
            mSubView = null;
            mSubViewContainer = null;
        }
    }


    /**
     * Set the parent tab of this tab.
     */
    void setParent(Tab parent) {
        if (parent == this) {
            throw new IllegalStateException("Cannot set parent to self!");
        }
        mParent = parent;
        // This tab may have been freed due to low memory. If that is the case,
        // the parent tab id is already saved. If we are changing that id
        // (most likely due to removing the parent tab) we must update the
        // parent tab id in the saved Bundle.
        if (mSavedState != null) {
            if (parent == null) {
                mSavedState.remove(PARENTTAB);
            } else {
                mSavedState.putLong(PARENTTAB, parent.getId());
            }
        }

        // Sync the WebView useragent with the parent
        if (parent != null && mSettings.hasDesktopUseragent(parent.getWebView())
                != mSettings.hasDesktopUseragent(getWebView())) {
            mSettings.toggleDesktopUseragent(getWebView());
        }

        if (parent != null && parent.getId() == getId()) {
            throw new IllegalStateException("Parent has same ID as child!");
        }
    }

    /**
     * If this Tab was created through another Tab, then this method returns
     * that Tab.
     * @return the Tab parent or null
     */
    public Tab getParent() {
        return mParent;
    }

    /**
     * When a Tab is created through the content of another Tab, then we
     * associate the Tabs.
     * @param child the Tab that was created from this Tab
     */
    void addChildTab(Tab child) {
        if (mChildren == null) {
            mChildren = new Vector<Tab>();
        }
        mChildren.add(child);
        child.setParent(this);
    }

    Vector<Tab> getChildren() {
        return mChildren;
    }

    void resume() {
        if (mMainView != null) {
            setupHwAcceleration(mMainView);
            mMainView.onResume();
            if (mSubView != null) {
                mSubView.onResume();
            }
        }
    }

    private void setupHwAcceleration(View web) {
        if (web == null) return;
        BrowserSettings settings = BrowserSettings.getInstance();
        if (settings.isHardwareAccelerated()) {
            web.setLayerType(View.LAYER_TYPE_NONE, null);
        } else {
            web.setLayerType(View.LAYER_TYPE_SOFTWARE, null);
        }
    }

    void pause() {
        if (mMainView != null) {
            mMainView.onPause();
            if (mSubView != null) {
                mSubView.onPause();
            }
        }
    }

    void putInForeground() {
        if (mInForeground) {
            return;
        }
        mInForeground = true;
        resume();
        Activity activity = mWebViewController.getActivity();
        mMainView.setOnCreateContextMenuListener(activity);
        if (mSubView != null) {
            mSubView.setOnCreateContextMenuListener(activity);
        }
        // Show the pending error dialog if the queue is not empty
        if (mQueuedErrors != null && mQueuedErrors.size() >  0) {
            showError(mQueuedErrors.getFirst());
        }
        mWebViewController.bookmarkedStatusHasChanged(this);
    }

    void putInBackground() {
        if (!mInForeground) {
            return;
        }
        capture();
        mInForeground = false;
        pause();
        mMainView.setOnCreateContextMenuListener(null);
        if (mSubView != null) {
            mSubView.setOnCreateContextMenuListener(null);
        }
    }

    boolean inForeground() {
        return mInForeground;
    }

    /**
     * Return the top window of this tab; either the subwindow if it is not
     * null or the main window.
     * @return The top window of this tab.
     */
    WebView getTopWindow() {
        if (mSubView != null) {
            return mSubView;
        }
        return mMainView;
    }

    /**
     * Return the main window of this tab. Note: if a tab is freed in the
     * background, this can return null. It is only guaranteed to be
     * non-null for the current tab.
     * @return The main WebView of this tab.
     */
    WebView getWebView() {
        /* Ensure the root webview object is in sync with our internal incognito status */
        if (mMainView instanceof BrowserWebView) {
            if (isPrivateBrowsingEnabled() && !mMainView.isPrivateBrowsingEnabled()) {
                ((BrowserWebView)mMainView).setPrivateBrowsing(isPrivateBrowsingEnabled());
            }
        }
        return mMainView;
    }

    void setViewContainer(View container) {
        mContainer = container;
    }

    View getViewContainer() {
        return mContainer;
    }

    /**
     * Return whether private browsing is enabled for the main window of
     * this tab.
     * @return True if private browsing is enabled.
     */
    boolean isPrivateBrowsingEnabled() {
        return mCurrentState.mIncognito;
    }

    /**
     * Return the subwindow of this tab or null if there is no subwindow.
     * @return The subwindow of this tab or null.
     */
    WebView getSubWebView() {
        return mSubView;
    }

    void setSubWebView(WebView subView) {
        mSubView = subView;
    }

    View getSubViewContainer() {
        return mSubViewContainer;
    }

    void setSubViewContainer(View subViewContainer) {
        mSubViewContainer = subViewContainer;
    }

    /**
     * @return The geolocation permissions prompt for this tab.
     */
    GeolocationPermissionsPrompt getGeolocationPermissionsPrompt() {
        if (mGeolocationPermissionsPrompt == null) {
            ViewStub stub = (ViewStub) mContainer
                    .findViewById(R.id.geolocation_permissions_prompt);
            mGeolocationPermissionsPrompt = (GeolocationPermissionsPrompt) stub
                    .inflate();
        }
        return mGeolocationPermissionsPrompt;
    }

    /**
     * @return The permissions prompt for this tab.
     */
    PermissionsPrompt getPermissionsPrompt() {
        if (mPermissionsPrompt == null) {
            ViewStub stub = (ViewStub) mContainer
                    .findViewById(R.id.permissions_prompt);
            mPermissionsPrompt = (PermissionsPrompt) stub.inflate();
        }
        return mPermissionsPrompt;
    }

    /**
     * @return The application id string
     */
    String getAppId() {
        return mAppId;
    }

    /**
     * Set the application id string
     * @param id
     */
    void setAppId(String id) {
        mAppId = id;
    }

    boolean closeOnBack() {
        return mCloseOnBack;
    }

    void setCloseOnBack(boolean close) {
        mCloseOnBack = close;
    }

    String getUrl() {
        return UrlUtils.filteredUrl(mCurrentState.mUrl);
    }

    String getOriginalUrl() {
        if (mCurrentState.mOriginalUrl == null) {
            return getUrl();
        }
        return UrlUtils.filteredUrl(mCurrentState.mOriginalUrl);
    }

    /**
     * Get the title of this tab.
     */
    String getTitle() {
        if (mCurrentState.mTitle == null && mInPageLoad) {
            return mContext.getString(R.string.title_bar_loading);
        }
        return mCurrentState.mTitle;
    }

    /**
     * Get the favicon of this tab.
     */
    Bitmap getFavicon() {
        if (mCurrentState.mFavicon != null) {
            return mCurrentState.mFavicon;
        }
        return getDefaultFavicon(mContext);
    }

    public boolean isBookmarkedSite() {
        return mCurrentState.mIsBookmarkedSite;
    }

    /**
     * Return the tab's error console. Creates the console if createIfNEcessary
     * is true and we haven't already created the console.
     * @param createIfNecessary Flag to indicate if the console should be
     *            created if it has not been already.
     * @return The tab's error console, or null if one has not been created and
     *         createIfNecessary is false.
     */
    ErrorConsoleView getErrorConsole(boolean createIfNecessary) {
        if (createIfNecessary && mErrorConsole == null) {
            mErrorConsole = new ErrorConsoleView(mContext);
            mErrorConsole.setWebView(mMainView);
        }
        return mErrorConsole;
    }

    /**
     * Sets the security state, clears the SSL certificate error and informs
     * the controller.
     */
    private void setSecurityState(SecurityState securityState) {
        mCurrentState.mSecurityState = securityState;
        mCurrentState.mSslCertificateError = null;
        mWebViewController.onUpdatedSecurityState(this);
    }

    /**
     * @return The tab's security state.
     */
    SecurityState getSecurityState() {
        return mCurrentState.mSecurityState;
    }

    /**
     * Gets the SSL certificate error, if any, for the page's main resource.
     * This is only non-null when the security state is
     * SECURITY_STATE_BAD_CERTIFICATE.
     */
    SslError getSslCertificateError() {
        return mCurrentState.mSslCertificateError;
    }

    int getLoadProgress() {
        if (mInPageLoad) {
            return mPageLoadProgress;
        }
        return 100;
    }

    /**
     * @return TRUE if onPageStarted is called while onPageFinished is not
     *         called yet.
     */
    boolean inPageLoad() {
        return mInPageLoad;
    }

    /**
     * @return The Bundle with the tab's state if it can be saved, otherwise null
     */
    public Bundle saveState() {
        // If the WebView is null it means we ran low on memory and we already
        // stored the saved state in mSavedState.
        if (mMainView == null) {
            return mSavedState;
        }

        if (TextUtils.isEmpty(mCurrentState.mUrl)) {
            return null;
        }

        mSavedState = new Bundle();
        WebBackForwardList savedList = mMainView.saveState(mSavedState);
        if (savedList == null || savedList.getSize() == 0) {
            Log.w(LOGTAG, "Failed to save back/forward list for "
                    + mCurrentState.mUrl);
        }

        mSavedState.putLong(ID, mId);
        mSavedState.putString(CURRURL, mCurrentState.mUrl);
        mSavedState.putString(CURRTITLE, mCurrentState.mTitle);
        mSavedState.putBoolean(INCOGNITO, mMainView.isPrivateBrowsingEnabled());
        if (mAppId != null) {
            mSavedState.putString(APPID, mAppId);
        }
        mSavedState.putBoolean(CLOSEFLAG, mCloseOnBack);
        // Remember the parent tab so the relationship can be restored.
        if (mParent != null) {
            mSavedState.putLong(PARENTTAB, mParent.mId);
        }
        mSavedState.putBoolean(USERAGENT,
                mSettings.hasDesktopUseragent(getWebView()));
        return mSavedState;
    }

    /*
     * Restore the state of the tab.
     */
    private void restoreState(Bundle b) {
        mSavedState = b;
        if (mSavedState == null) {
            return;
        }
        // Restore the internal state even if the WebView fails to restore.
        // This will maintain the app id, original url and close-on-exit values.
        mId = b.getLong(ID);
        mAppId = b.getString(APPID);
        mCloseOnBack = b.getBoolean(CLOSEFLAG);
        restoreUserAgent();
        String url = b.getString(CURRURL);
        String title = b.getString(CURRTITLE);
        boolean incognito = b.getBoolean(INCOGNITO);
        mCurrentState = new PageState(mContext, incognito, url, null);
        mCurrentState.mTitle = title;
        synchronized (Tab.this) {
            if (mCapture != null) {
                DataController.getInstance(mContext).loadThumbnail(this);
            }
        }
    }

    private void restoreUserAgent() {
        if (mMainView == null || mSavedState == null) {
            return;
        }
        if (mSavedState.getBoolean(USERAGENT)
                != mSettings.hasDesktopUseragent(mMainView)) {
            mSettings.toggleDesktopUseragent(mMainView);
        }
    }

    public void updateBookmarkedStatus() {
        mDataController.queryBookmarkStatus(getUrl(), mIsBookmarkCallback);
    }

    private DataController.OnQueryUrlIsBookmark mIsBookmarkCallback
            = new DataController.OnQueryUrlIsBookmark() {
        @Override
        public void onQueryUrlIsBookmark(String url, boolean isBookmark) {
            if (mCurrentState.mUrl.equals(url)) {
                mCurrentState.mIsBookmarkedSite = isBookmark;
                mWebViewController.bookmarkedStatusHasChanged(Tab.this);
            }
        }
    };

    public Bitmap getScreenshot() {
        synchronized (Tab.this) {
            return mCapture;
        }
    }

    public boolean isSnapshot() {
        return false;
    }

    private static class SaveCallback implements ValueCallback<Boolean> {
        boolean mResult;

        @Override
        public void onReceiveValue(Boolean value) {
            mResult = value;
            synchronized (this) {
                notifyAll();
            }
        }

    }

    /**
     * Must be called on the UI thread
     */
    public ContentValues createSnapshotValues() {
        return null;
    }

    /**
     * Probably want to call this on a background thread
     */
    public boolean saveViewState(ContentValues values) {
        return false;
    }

    public byte[] compressBitmap(Bitmap bitmap) {
        if (bitmap == null) {
            return null;
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        bitmap.compress(CompressFormat.PNG, 100, stream);
        return stream.toByteArray();
    }

    public void loadUrl(String url, Map<String, String> headers) {
        if (mMainView != null) {
            mPageLoadProgress = INITIAL_PROGRESS;
            mInPageLoad = true;
            mCurrentState = new PageState(mContext, false, url, null);
            mWebViewController.onPageStarted(this, mMainView, null);
            WebResourceResponse res = HomeProvider.shouldInterceptRequest(mContext, url);
            if (res != null) {
                try {
                    String data = readWebResource(res).toString();
                    mInMostVisitedPage = true;
                    mMainView.loadDataWithBaseURL(url, data, res.getMimeType(), res.getEncoding(),
                            HomeProvider.MOST_VISITED_URL);
                } catch (IOException io) {
                    // Fallback to default load handling
                    mMainView.loadUrl(url, headers);
                }
            } else {
                mMainView.loadUrl(url, headers);
            }
        }
    }

    public void disableUrlOverridingForLoad() {
        mDisableOverrideUrlLoading = true;
    }

    protected void capture() {
        if (mMainView == null || mCapture == null) return;
        if (mMainView.getContentWidth() <= 0 || mMainView.getContentHeight() <= 0) {
            return;
        }
        Canvas c = new Canvas(mCapture);
        final int left = mMainView.getScrollX();
        final int top = mMainView.getScrollY() + mMainView.getVisibleTitleHeight();
        int state = c.save();
        c.translate(-left, -top);
        float scale = mCaptureWidth / (float) mMainView.getWidth();
        c.scale(scale, scale, left, top);
        if (mMainView instanceof BrowserWebView) {
            ((BrowserWebView)mMainView).drawContent(c);
        } else {
            mMainView.draw(c);
        }
        c.restoreToCount(state);
        // manually anti-alias the edges for the tilt
        c.drawRect(0, 0, 1, mCapture.getHeight(), sAlphaPaint);
        c.drawRect(mCapture.getWidth() - 1, 0, mCapture.getWidth(),
                mCapture.getHeight(), sAlphaPaint);
        c.drawRect(0, 0, mCapture.getWidth(), 1, sAlphaPaint);
        c.drawRect(0, mCapture.getHeight() - 1, mCapture.getWidth(),
                mCapture.getHeight(), sAlphaPaint);
        c.setBitmap(null);
        mHandler.removeMessages(MSG_CAPTURE);
        persistThumbnail();
        TabControl tc = mWebViewController.getTabControl();
        if (tc != null) {
            OnThumbnailUpdatedListener updateListener
                    = tc.getOnThumbnailUpdatedListener();
            if (updateListener != null) {
                updateListener.onThumbnailUpdated(this);
            }
        }
    }

    @Override
    public void onNewPicture(WebView view, Picture picture) {
        postCapture();
    }

    private void postCapture() {
        if (!mHandler.hasMessages(MSG_CAPTURE)) {
            mHandler.sendEmptyMessageDelayed(MSG_CAPTURE, CAPTURE_DELAY);
        }
    }

    public boolean canGoBack() {
        return mMainView != null ? mMainView.canGoBack() : false;
    }

    public boolean canGoForward() {
        return mMainView != null ? mMainView.canGoForward() : false;
    }

    public void goBack() {
        if (mMainView != null) {
            mMainView.goBack();
        }
    }

    public void goForward() {
        if (mMainView != null) {
            mMainView.goForward();
        }
    }

    /**
     * Causes the tab back/forward stack to be cleared once, if the given URL is the next URL
     * to be added to the stack.
     *
     * This is used to ensure that preloaded URLs that are not subsequently seen by the user do
     * not appear in the back stack.
     */
    public void clearBackStackWhenItemAdded(Pattern urlPattern) {
        mClearHistoryUrlPattern = urlPattern;
    }

    protected void persistThumbnail() {
        DataController.getInstance(mContext).saveThumbnail(this);
    }

    protected void deleteThumbnail() {
        DataController.getInstance(mContext).deleteThumbnail(this);
    }

    void updateCaptureFromBlob(byte[] blob) {
        synchronized (Tab.this) {
            if (mCapture == null) {
                return;
            }
            ByteBuffer buffer = ByteBuffer.wrap(blob);
            try {
                mCapture.copyPixelsFromBuffer(buffer);
            } catch (RuntimeException rex) {
                Log.e(LOGTAG, "Load capture has mismatched sizes; buffer: "
                        + buffer.capacity() + " blob: " + blob.length
                        + "capture: " + mCapture.getByteCount());
                throw rex;
            }
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(100);
        builder.append(mId);
        builder.append(") has parent: ");
        if (getParent() != null) {
            builder.append("true[");
            builder.append(getParent().getId());
            builder.append("]");
        } else {
            builder.append("false");
        }
        builder.append(", incog: ");
        builder.append(isPrivateBrowsingEnabled());
        if (!isPrivateBrowsingEnabled()) {
            builder.append(", title: ");
            builder.append(getTitle());
            builder.append(", url: ");
            builder.append(getUrl());
        }
        return builder.toString();
    }

    private void handleProceededAfterSslError(SslError error) {
        if (error.getUrl().equals(mCurrentState.mUrl)) {
            // The security state should currently be SECURITY_STATE_SECURE.
            setSecurityState(SecurityState.SECURITY_STATE_BAD_CERTIFICATE);
            mCurrentState.mSslCertificateError = error;
        } else if (getSecurityState() == SecurityState.SECURITY_STATE_SECURE) {
            // The page's main resource is secure and this error is for a
            // sub-resource.
            setSecurityState(SecurityState.SECURITY_STATE_MIXED);
        }
    }

    public void setAcceptThirdPartyCookies(boolean accept) {
        CookieManager cookieManager = CookieManager.getInstance();
        if (mMainView != null)
            cookieManager.setAcceptThirdPartyCookies(mMainView, accept);
        if (mSubView != null)
            cookieManager.setAcceptThirdPartyCookies(mSubView, accept);
    }

    private StringBuilder readWebResource(WebResourceResponse response) throws IOException {
        StringBuilder sb = new StringBuilder();
        InputStream is = response.getData();
        try {
            byte[] data = new byte[512];
            int read = 0;
            while ((read = is.read(data, 0, 512)) != -1) {
                sb.append(new String(data, 0, read));
            }
        } finally {
            is.close();
        }
        return sb;
    }
}
