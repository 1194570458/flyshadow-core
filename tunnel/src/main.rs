use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;

use tokio::spawn;
use tokio::time::sleep;

use tunnel::context::context::TunnelContext;
use tunnel::proxy::proxy::Proxy;

#[tokio::main]
async fn main() {


    let tunnel_context = Arc::new(TunnelContext::new());

    tunnel_context.set_domain_rule(r#"
    [
        {
            "domain": "openai.com",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "bingapis.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "safebrowsing.urlsec.qq.com",
            "matching": 0,
            "proxyType": 0
        },
        {
            "domain": "safebrowsing.googleapis.com",
            "matching": 0,
            "proxyType": 0
        },
        {
            "domain": "developer.apple.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "digicert.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ocsp.apple.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "ocsp.comodoca.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "ocsp.usertrust.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "ocsp.sectigo.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "ocsp.verisign.net",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "apple-dns.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "testflight.apple.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "sandbox.itunes.apple.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "itunes.apple.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "apps.apple.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blobstore.apple.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cvws.icloud-content.com",
            "matching": 0,
            "proxyType": 2
        },
        {
            "domain": "mzstatic.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "itunes.apple.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "icloud.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "icloud-content.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "me.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "aaplimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cdn20.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cdn-apple.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "akadns.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "akamaiedge.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "edgekey.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "mwcloudcdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "mwcname.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "apple.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "apple-cloudkit.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "apple-mapkit.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cn",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "-cn",
            "matching": 2,
            "proxyType": 0
        },
        {
            "domain": "126.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "126.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "127.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "163.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "360buyimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "36kr.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "acfun.tv",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "air-matters.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "aixifan.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "alicdn",
            "matching": 2,
            "proxyType": 0
        },
        {
            "domain": "alipay",
            "matching": 2,
            "proxyType": 0
        },
        {
            "domain": "taobao",
            "matching": 2,
            "proxyType": 0
        },
        {
            "domain": "amap.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "autonavi.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "baidu",
            "matching": 2,
            "proxyType": 0
        },
        {
            "domain": "bdimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "bdstatic.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "bilibili.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "bilivideo.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "caiyunapp.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "clouddn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cnbeta.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cnbetacdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cootekservice.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "csdn.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ctrip.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "dgtle.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "dianping.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "douban.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "doubanio.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "duokan.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "easou.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ele.me",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "feng.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "fir.im",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "frdic.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "g-cores.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "godic.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "gtimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "cdn.hockeyapp.net",
            "matching": 0,
            "proxyType": 0
        },
        {
            "domain": "hongxiu.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "hxcdn.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "iciba.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ifeng.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ifengimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ipip.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "iqiyi.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "jd.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "jianshu.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "knewone.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "le.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "lecloud.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "lemicp.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "licdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "linkedin.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "luoo.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "meituan.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "meituan.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "mi.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "miaopai.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "microsoft.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "microsoftonline.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "miui.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "miwifi.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "mob.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "netease.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "office.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "office365.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "officecdn",
            "matching": 2,
            "proxyType": 0
        },
        {
            "domain": "oschina.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ppsimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "pstatp.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qcloud.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qdaily.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qdmm.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qhimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qhres.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qidian.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qihucdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qiniu.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qiniucdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qiyipic.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qq.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "qqurl.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "rarbg.to",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ruguoapp.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "segmentfault.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "sinaapp.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "smzdm.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "snapdrop.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "sogou.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "sogoucdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "sohu.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "soku.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "speedtest.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "sspai.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "suning.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "taobao.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "tencent.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "tenpay.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "tianyancha.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "tmall.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "tudou.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "umetrip.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "upaiyun.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "upyun.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "veryzhun.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "weather.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "weibo.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "xiami.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "xiami.net",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "xiaomicp.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ximalaya.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "xmcdn.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "xunlei.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "yhd.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "yihaodianimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "yinxiang.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "ykimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "youdao.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "youku.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "zealer.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "zhihu.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "zhimg.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "zimuzu.tv",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "zoho.com",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "amazon",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "google",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "gmail",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "youtube",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "facebook",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "fb.me",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "fbcdn.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "twitter",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "instagram",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "dropbox",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "twimg.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blogspot",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "youtu.be",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "whatsapp",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "admarvel",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "admaster",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "adsage",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "adsmogo",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "adsrvmedia",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "adwords",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "adservice",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "appsflyer.com",
            "matching": 1,
            "proxyType": 1
        },
        {
            "domain": "domob",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "doubleclick.net",
            "matching": 1,
            "proxyType": 1
        },
        {
            "domain": "duomeng",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "dwtrack",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "guanggao",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "lianmeng",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "mmstat.com",
            "matching": 1,
            "proxyType": 1
        },
        {
            "domain": "mopub",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "omgmta",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "openx",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "partnerad",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "pingfore",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "supersonicads",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "uedas",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "umeng",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "usage",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "vungle.com",
            "matching": 1,
            "proxyType": 1
        },
        {
            "domain": "wlmonitor",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "zjtoolbar",
            "matching": 2,
            "proxyType": 1
        },
        {
            "domain": "t.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "9to5mac.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "abpchina.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "adblockplus.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "adobe.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "akamaized.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "alfredapp.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "amplitude.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ampproject.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "android.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "angularjs.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "aolcdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "apkpure.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "appledaily.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "appshopper.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "appspot.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "arcgis.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "archive.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "armorgames.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "aspnetcdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "att.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "awsstatic.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "azureedge.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "azurewebsites.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bing.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bintray.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bit.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bit.ly",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bitbucket.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bjango.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bkrtx.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blog.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blogcdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blogger.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blogsmithmedia.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blogspot.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "blogspot.hk",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "bloomberg.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "box.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "box.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cachefly.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "chromium.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cl.ly",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cloudflare.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cloudfront.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cloudmagic.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cmail19.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cnet.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "cocoapods.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "comodoca.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "crashlytics.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "culturedcode.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "d.pr",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "danilo.to",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "dayone.me",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "db.tt",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "deskconnect.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "disq.us",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "disqus.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "disquscdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "dnsimple.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "docker.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "dribbble.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "droplr.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "duckduckgo.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "dueapp.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "dytt8.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "edgecastcdn.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "edgekey.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "edgesuite.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "engadget.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "entrust.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "eurekavpt.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "evernote.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "fabric.io",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "fast.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "fastly.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "fc2.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "feedburner.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "feedly.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "feedsportal.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "fiftythree.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "firebaseio.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "flexibits.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "flickr.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "flipboard.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "g.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gabia.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "geni.us",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gfx.ms",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ggpht.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ghostnoteapp.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "git.io",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "github",
            "matching": 2,
            "proxyType": 2
        },
        {
            "domain": "globalsign.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gmodules.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "godaddy.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "golang.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gongm.in",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "goo.gl",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "goodreaders.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "goodreads.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gravatar.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gstatic.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "gvt0.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "hockeyapp.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "hotmail.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "icons8.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ifixit.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ift.tt",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ifttt.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "iherb.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "imageshack.us",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "img.ly",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "imgur.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "imore.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "instapaper.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ipn.li",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "is.gd",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "issuu.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "itgonglun.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "itun.es",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ixquick.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "j.mp",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "js.revsci.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "jshint.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "jtvnw.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "justgetflux.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "kat.cr",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "klip.me",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "libsyn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "linode.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "lithium.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "littlehj.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "live.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "live.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "livefilestore.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "llnwd.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "macid.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "macromedia.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "macrumors.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "mashable.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "mathjax.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "medium.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "mega.co.nz",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "mega.nz",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "megaupload.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "microsofttranslator.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "mindnode.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "mobile01.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "modmyi.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "msedge.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "myfontastic.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "name.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "nextmedia.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "nsstatic.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "nssurge.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "nyt.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "nytimes.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "omnigroup.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "onedrive.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "onenote.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ooyala.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "openvpn.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "openwrt.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "orkut.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "osxdaily.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "outlook.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ow.ly",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "paddleapi.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "parallels.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "parse.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "pdfexpert.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "periscope.tv",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "pinboard.in",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "pinterest.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "pixelmator.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "pixiv.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "playpcesor.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "playstation.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "playstation.com.hk",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "playstation.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "playstationnetwork.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "pushwoosh.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "rime.im",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "servebom.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "sfx.ms",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "shadowsocks.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "sharethis.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "shazam.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "skype.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "smartdns$app_name.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "smartmailcloud.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "sndcdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "sony.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "soundcloud.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "sourceforge.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "spotify.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "squarespace.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "sstatic.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "st.luluku.pw",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "stackoverflow.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "startpage.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "staticflickr.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "steamcommunity.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "symauth.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "symcb.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "symcd.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tapbots.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tapbots.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tdesktop.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "techcrunch.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "techsmith.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "thepiratebay.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "theverge.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "time.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "timeinc.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tiny.cc",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tinypic.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tmblr.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "todoist.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "trello.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "trustasiassl.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tumblr.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tumblr.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tweetdeck.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "tweetmarker.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "twitch.tv",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "txmblr.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "typekit.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ubertags.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ublock.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ubnt.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ulyssesapp.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "urchin.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "usertrust.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "v.gd",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "v2ex.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vimeo.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vimeocdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vine.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vivaldi.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vox-cdn.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vsco.co",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "vultr.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "w.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "w3schools.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "webtype.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wikiwand.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wikileaks.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wikimedia.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wikipedia.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wikipedia.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "windows.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "windows.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wire.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wordpress.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "workflowy.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wp.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wsj.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "wsj.net",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "xda-developers.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "xeeno.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "xiti.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "yahoo.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "yimg.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ying.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "yoyo.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "ytimg.com",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "telegra.ph",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "telegram.org",
            "matching": 1,
            "proxyType": 2
        },
        {
            "domain": "91.108.4.0/22",
            "matching": 3,
            "proxyType": 2
        },
        {
            "domain": "91.108.8.0/21",
            "matching": 3,
            "proxyType": 2
        },
        {
            "domain": "91.108.16.0/22",
            "matching": 3,
            "proxyType": 2
        },
        {
            "domain": "91.108.56.0/22",
            "matching": 3,
            "proxyType": 2
        },
        {
            "domain": "149.154.160.0/20",
            "matching": 3,
            "proxyType": 2
        },
        {
            "domain": "2001:67c:4e8::/48",
            "matching": 4,
            "proxyType": 2
        },
        {
            "domain": "2001:b28:f23d::/48",
            "matching": 4,
            "proxyType": 2
        },
        {
            "domain": "2001:b28:f23f::/48",
            "matching": 4,
            "proxyType": 2
        },
        {
            "domain": "injections.adguard.org",
            "matching": 0,
            "proxyType": 0
        },
        {
            "domain": "local.adguard.org",
            "matching": 0,
            "proxyType": 0
        },
        {
            "domain": "local",
            "matching": 1,
            "proxyType": 0
        },
        {
            "domain": "127.0.0.0/8",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "172.16.0.0/12",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "192.168.0.0/16",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "10.0.0.0/8",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "17.0.0.0/8",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "100.64.0.0/10",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "224.0.0.0/4",
            "matching": 3,
            "proxyType": 0
        },
        {
            "domain": "fe80::/10",
            "matching": 4,
            "proxyType": 0
        },
        {
            "domain": "CN",
            "matching": 6,
            "proxyType": 0
        },
        {
            "domain": "",
            "matching": 10,
            "proxyType": 2
        }
    ]
    "#.to_string()).await;

    let mut proxy = Proxy::new(tunnel_context.clone(), 6555);
    match proxy.start().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    };

    match tunnel_context.connect_tunnel("47.242.6.116".to_string(), 6001, "855ddy1sg2nczhxh4vgl".to_string()).await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    };

    let tunnel_context1 = tunnel_context.clone();
    spawn(async move{
        loop {
            sleep(Duration::from_secs(1)).await;
            println!("upload: {}", tunnel_context1.get_tunnel_upload().await);
            println!("download: {}", tunnel_context1.get_tunnel_download().await);
        }
    });

    loop {
        sleep(Duration::from_secs(20000)).await;
    }
}
