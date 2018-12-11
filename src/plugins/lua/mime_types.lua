--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

if confighelp then
  return
end

-- This plugin implements mime types checks for mail messages
local logger = require "rspamd_logger"
local lua_util = require "lua_util"
local N = "mime_types"
local settings = {
  file = '',
  symbol_unknown = 'MIME_UNKNOWN',
  symbol_bad = 'MIME_BAD',
  symbol_good = 'MIME_GOOD',
  symbol_attachment = 'MIME_BAD_ATTACHMENT',
  symbol_encrypted_archive = 'MIME_ENCRYPTED_ARCHIVE',
  symbol_archive_in_archive = 'MIME_ARCHIVE_IN_ARCHIVE',
  symbol_double_extension = 'MIME_DOUBLE_BAD_EXTENSION',
  symbol_bad_extension = 'MIME_BAD_EXTENSION',
  regexp = false,
  extension_map = { -- extension -> mime_type
    html = 'text/html',
    htm = 'text/html',
    txt = 'text/plain',
    pdf = 'application/pdf'
  },

  bad_extensions = {
    scr = 4,
    lnk = 4,
    exe = 1,
    jar = 2,
    com = 2,
    bat = 2,
    -- Have you ever seen that in legit email?
    ace = 4,
    arj = 2,
    cab = 3,
    -- Additional bad extensions from Gmail
    ade = 2,
    adp = 2,
    chm = 2,
    cmd = 2,
    cpl = 2,
    ins = 2,
    isp = 2,
    js = 2,
    jse = 2,
    lib = 2,
    mde = 2,
    msc = 2,
    msi = 2,
    msp = 2,
    mst = 2,
    nsh = 2,
    pif = 2,
    sct = 2,
    shb = 2,
    sys = 2,
    vb = 2,
    vbe = 2,
    vbs = 2,
    vxd = 2,
    wsc = 2,
    wsh = 2,
    -- Additional bad extensions from Outlook
    app = 2,
    asp = 2,
    bas = 2,
    cnt = 2,
    csh = 2,
    diagcab = 2,
    fxp = 2,
    gadget = 2,
    grp = 2,
    hlp = 2,
    hpj = 2,
    inf = 2,
    its = 2,
    jnlp = 2,
    ksh = 2,
    mad = 2,
    maf = 2,
    mag = 2,
    mam = 2,
    maq = 2,
    mar = 2,
    mas = 2,
    mat = 2,
    mau = 2,
    mav = 2,
    maw = 2,
    mcf = 2,
    mda = 2,
    mdb = 2,
    mdt = 2,
    mdw = 2,
    mdz = 2,
    msh = 2,
    msh1 = 2,
    msh2 = 2,
    mshxml = 2,
    msh1xml = 2,
    msh2xml = 2,
    msu = 2,
    ops = 2,
    osd = 2,
    pcd = 2,
    pl = 2,
    plg = 2,
    prf = 2,
    prg = 2,
    printerexport = 2,
    ps1 = 2,
    ps1xml = 2,
    ps2 = 2,
    ps2xml = 2,
    psc1 = 2,
    psc2 = 2,
    psd1 = 2,
    psdm1 = 2,
    pst = 2,
    reg = 2,
    scf = 2,
    shs = 2,
    theme = 2,
    tmp = 2,
    url = 2,
    vbp = 2,
    vsmacros = 2,
    vsw = 2,
    webpnp = 2,
    website = 2,
    ws = 2,
    xbap = 2,
    xll = 2,
    xnk = 2,
  },

  -- Something that should not be in archive
  bad_archive_extensions = {
    pptx = 0.1,
    docx = 0.1,
    xlsx = 0.1,
    pdf = 0.1,
    jar = 3,
    js = 0.5,
    vbs = 4,
    wsf = 4,
    hta = 4,
  },

  archive_extensions = {
    zip = 1,
    arj = 1,
    rar = 1,
    ace = 1,
    ['7z'] = 1,
    cab = 1,
  },

  -- Not really archives
  archive_exceptions = {
    odt = true,
    ods = true,
    odp = true,
    docx = true,
    xlsx = true,
    pptx = true,
    vsdx = true,
    -- jar = true,
  },

  -- Multiplier for full extension_map mismatch
  other_extensions_mult = 0.4,
}

local map = nil

local full_extensions_map = {
  {"323", "text/h323"},
  {"3g2", "video/3gpp2"},
  {"3gp", "video/3gpp"},
  {"3gp2", "video/3gpp2"},
  {"3gpp", "video/3gpp"},
  {"7z", "application/x-7z-compressed"},
  {"aa", "audio/audible"},
  {"AAC", "audio/aac"},
  {"aaf", "application/octet-stream"},
  {"aax", "audio/vnd.audible.aax"},
  {"ac3", "audio/ac3"},
  {"aca", "application/octet-stream"},
  {"accda", "application/msaccess.addin"},
  {"accdb", "application/msaccess"},
  {"accdc", "application/msaccess.cab"},
  {"accde", "application/msaccess"},
  {"accdr", "application/msaccess.runtime"},
  {"accdt", "application/msaccess"},
  {"accdw", "application/msaccess.webapplication"},
  {"accft", "application/msaccess.ftemplate"},
  {"acx", "application/internet-property-stream"},
  {"AddIn", "text/xml"},
  {"ade", "application/msaccess"},
  {"adobebridge", "application/x-bridge-url"},
  {"adp", "application/msaccess"},
  {"ADT", "audio/vnd.dlna.adts"},
  {"ADTS", "audio/aac"},
  {"afm", "application/octet-stream"},
  {"ai", "application/postscript"},
  {"aif", "audio/aiff"},
  {"aifc", "audio/aiff"},
  {"aiff", "audio/aiff"},
  {"air", "application/vnd.adobe.air-application-installer-package+zip"},
  {"amc", "application/mpeg"},
  {"anx", "application/annodex"},
  {"apk", "application/vnd.android.package-archive" },
  {"application", "application/x-ms-application"},
  {"art", "image/x-jg"},
  {"asa", "application/xml"},
  {"asax", "application/xml"},
  {"ascx", "application/xml"},
  {"asd", "application/octet-stream"},
  {"asf", "video/x-ms-asf"},
  {"ashx", "application/xml"},
  {"asi", "application/octet-stream"},
  {"asm", "text/plain"},
  {"asmx", "application/xml"},
  {"aspx", "application/xml"},
  {"asr", "video/x-ms-asf"},
  {"asx", "video/x-ms-asf"},
  {"atom", "application/atom+xml"},
  {"au", "audio/basic"},
  {"avi", "video/x-msvideo"},
  {"axa", "audio/annodex"},
  {"axs", "application/olescript"},
  {"axv", "video/annodex"},
  {"bas", "text/plain"},
  {"bcpio", "application/x-bcpio"},
  {"bin", "application/octet-stream"},
  {"bmp", "image/bmp"},
  {"c", "text/plain"},
  {"cab", "application/octet-stream"},
  {"caf", "audio/x-caf"},
  {"calx", "application/vnd.ms-office.calx"},
  {"cat", "application/vnd.ms-pki.seccat"},
  {"cc", "text/plain"},
  {"cd", "text/plain"},
  {"cdda", "audio/aiff"},
  {"cdf", "application/x-cdf"},
  {"cer", "application/x-x509-ca-cert"},
  {"cfg", "text/plain"},
  {"chm", "application/octet-stream"},
  {"class", "application/x-java-applet"},
  {"clp", "application/x-msclip"},
  {"cmd", "text/plain"},
  {"cmx", "image/x-cmx"},
  {"cnf", "text/plain"},
  {"cod", "image/cis-cod"},
  {"config", "application/xml"},
  {"contact", "text/x-ms-contact"},
  {"coverage", "application/xml"},
  {"cpio", "application/x-cpio"},
  {"cpp", "text/plain"},
  {"crd", "application/x-mscardfile"},
  {"crl", "application/pkix-crl"},
  {"crt", "application/x-x509-ca-cert"},
  {"cs", "text/plain"},
  {"csdproj", "text/plain"},
  {"csh", "application/x-csh"},
  {"csproj", "text/plain"},
  {"css", "text/css"},
  {"csv", "text/csv"},
  {"cur", "application/octet-stream"},
  {"cxx", "text/plain"},
  {"dat", {"application/octet-stream", "application/ms-tnef"}},
  {"datasource", "application/xml"},
  {"dbproj", "text/plain"},
  {"dcr", "application/x-director"},
  {"def", "text/plain"},
  {"deploy", "application/octet-stream"},
  {"der", "application/x-x509-ca-cert"},
  {"dgml", "application/xml"},
  {"dib", "image/bmp"},
  {"dif", "video/x-dv"},
  {"dir", "application/x-director"},
  {"disco", "text/xml"},
  {"divx", "video/divx"},
  {"dll", "application/x-msdownload"},
  {"dll.config", "text/xml"},
  {"dlm", "text/dlm"},
  {"doc", "application/msword"},
  {"docm", "application/vnd.ms-word.document.macroEnabled.12"},
  {"docx", {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword", "application/vnd.ms-word.document.12", "application/octet-stream"}},
  {"dot", "application/msword"},
  {"dotm", "application/vnd.ms-word.template.macroEnabled.12"},
  {"dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
  {"dsp", "application/octet-stream"},
  {"dsw", "text/plain"},
  {"dtd", "text/xml"},
  {"dtsConfig", "text/xml"},
  {"dv", "video/x-dv"},
  {"dvi", "application/x-dvi"},
  {"dwf", "drawing/x-dwf"},
  {"dwg", {"application/acad", "image/vnd.dwg"}},
  {"dwp", "application/octet-stream"},
  {"dxf", "application/x-dxf" },
  {"dxr", "application/x-director"},
  {"eml", "message/rfc822"},
  {"emz", "application/octet-stream"},
  {"eot", "application/vnd.ms-fontobject"},
  {"eps", "application/postscript"},
  {"etl", "application/etl"},
  {"etx", "text/x-setext"},
  {"evy", "application/envoy"},
  {"exe", "application/x-dosexec"},
  {"exe.config", "text/xml"},
  {"fdf", "application/vnd.fdf"},
  {"fif", "application/fractals"},
  {"filters", "application/xml"},
  {"fla", "application/octet-stream"},
  {"flac", "audio/flac"},
  {"flr", "x-world/x-vrml"},
  {"flv", "video/x-flv"},
  {"fsscript", "application/fsharp-script"},
  {"fsx", "application/fsharp-script"},
  {"generictest", "application/xml"},
  {"gif", "image/gif"},
  {"gpx", "application/gpx+xml"},
  {"group", "text/x-ms-group"},
  {"gsm", "audio/x-gsm"},
  {"gtar", "application/x-gtar"},
  {"gz", {"application/gzip", "application/x-gzip"}},
  {"h", "text/plain"},
  {"hdf", "application/x-hdf"},
  {"hdml", "text/x-hdml"},
  {"hhc", "application/x-oleobject"},
  {"hhk", "application/octet-stream"},
  {"hhp", "application/octet-stream"},
  {"hlp", "application/winhlp"},
  {"hpp", "text/plain"},
  {"hqx", "application/mac-binhex40"},
  {"hta", "application/hta"},
  {"htc", "text/x-component"},
  {"htm", "text/html"},
  {"html", "text/html"},
  {"htt", "text/webviewhtml"},
  {"hxa", "application/xml"},
  {"hxc", "application/xml"},
  {"hxd", "application/octet-stream"},
  {"hxe", "application/xml"},
  {"hxf", "application/xml"},
  {"hxh", "application/octet-stream"},
  {"hxi", "application/octet-stream"},
  {"hxk", "application/xml"},
  {"hxq", "application/octet-stream"},
  {"hxr", "application/octet-stream"},
  {"hxs", "application/octet-stream"},
  {"hxt", "text/html"},
  {"hxv", "application/xml"},
  {"hxw", "application/octet-stream"},
  {"hxx", "text/plain"},
  {"i", "text/plain"},
  {"ico", "image/x-icon"},
  {"ics", {"text/calendar", "application/octet-stream"}},
  {"idl", "text/plain"},
  {"ief", "image/ief"},
  {"iii", "application/x-iphone"},
  {"inc", "text/plain"},
  {"inf", "application/octet-stream"},
  {"ini", "text/plain"},
  {"inl", "text/plain"},
  {"ins", "application/x-internet-signup"},
  {"ipa", "application/x-itunes-ipa"},
  {"ipg", "application/x-itunes-ipg"},
  {"ipproj", "text/plain"},
  {"ipsw", "application/x-itunes-ipsw"},
  {"iqy", "text/x-ms-iqy"},
  {"isp", "application/x-internet-signup"},
  {"ite", "application/x-itunes-ite"},
  {"itlp", "application/x-itunes-itlp"},
  {"itms", "application/x-itunes-itms"},
  {"itpc", "application/x-itunes-itpc"},
  {"IVF", "video/x-ivf"},
  {"jar", "application/java-archive"},
  {"java", "application/octet-stream"},
  {"jck", "application/liquidmotion"},
  {"jcz", "application/liquidmotion"},
  {"jfif", "image/pjpeg"},
  {"jnlp", "application/x-java-jnlp-file"},
  {"jpb", "application/octet-stream"},
  {"jpe", {"image/jpeg", "image/pjpeg"}},
  {"jpeg", {"image/jpeg", "image/pjpeg"}},
  {"jpg", {"image/jpeg", "image/pjpeg"}},
  {"js", "application/javascript"},
  {"json", "application/json"},
  {"jsx", "text/jscript"},
  {"jsxbin", "text/plain"},
  {"latex", "application/x-latex"},
  {"library-ms", "application/windows-library+xml"},
  {"lit", "application/x-ms-reader"},
  {"loadtest", "application/xml"},
  {"lpk", "application/octet-stream"},
  {"lsf", "video/x-la-asf"},
  {"lst", "text/plain"},
  {"lsx", "video/x-la-asf"},
  {"lzh", "application/octet-stream"},
  {"m13", "application/x-msmediaview"},
  {"m14", "application/x-msmediaview"},
  {"m1v", "video/mpeg"},
  {"m2t", "video/vnd.dlna.mpeg-tts"},
  {"m2ts", "video/vnd.dlna.mpeg-tts"},
  {"m2v", "video/mpeg"},
  {"m3u", "audio/x-mpegurl"},
  {"m3u8", "audio/x-mpegurl"},
  {"m4a", {"audio/m4a", "audio/x-m4a"}},
  {"m4b", "audio/m4b"},
  {"m4p", "audio/m4p"},
  {"m4r", "audio/x-m4r"},
  {"m4v", "video/x-m4v"},
  {"mac", "image/x-macpaint"},
  {"mak", "text/plain"},
  {"man", "application/x-troff-man"},
  {"manifest", "application/x-ms-manifest"},
  {"map", "text/plain"},
  {"master", "application/xml"},
  {"mbox", "application/mbox"},
  {"mda", "application/msaccess"},
  {"mdb", "application/x-msaccess"},
  {"mde", "application/msaccess"},
  {"mdp", "application/octet-stream"},
  {"me", "application/x-troff-me"},
  {"mfp", "application/x-shockwave-flash"},
  {"mht", "message/rfc822"},
  {"mhtml", "message/rfc822"},
  {"mid", "audio/mid"},
  {"midi", "audio/mid"},
  {"mix", "application/octet-stream"},
  {"mk", "text/plain"},
  {"mmf", "application/x-smaf"},
  {"mno", "text/xml"},
  {"mny", "application/x-msmoney"},
  {"mod", "video/mpeg"},
  {"mov", "video/quicktime"},
  {"movie", "video/x-sgi-movie"},
  {"mp2", "video/mpeg"},
  {"mp2v", "video/mpeg"},
  {"mp3", "audio/mpeg"},
  {"mp4", "video/mp4"},
  {"mp4v", "video/mp4"},
  {"mpa", "video/mpeg"},
  {"mpe", "video/mpeg"},
  {"mpeg", "video/mpeg"},
  {"mpf", "application/vnd.ms-mediapackage"},
  {"mpg", "video/mpeg"},
  {"mpp", "application/vnd.ms-project"},
  {"mpv2", "video/mpeg"},
  {"mqv", "video/quicktime"},
  {"ms", "application/x-troff-ms"},
  {"msg", "application/vnd.ms-outlook"},
  {"msi", "application/octet-stream"},
  {"mso", "application/octet-stream"},
  {"mts", "video/vnd.dlna.mpeg-tts"},
  {"mtx", "application/xml"},
  {"mvb", "application/x-msmediaview"},
  {"mvc", "application/x-miva-compiled"},
  {"mxp", "application/x-mmxp"},
  {"nc", "application/x-netcdf"},
  {"nsc", "video/x-ms-asf"},
  {"nws", "message/rfc822"},
  {"ocx", "application/octet-stream"},
  {"oda", "application/oda"},
  {"odb", "application/vnd.oasis.opendocument.database"},
  {"odc", "application/vnd.oasis.opendocument.chart"},
  {"odf", "application/vnd.oasis.opendocument.formula"},
  {"odg", "application/vnd.oasis.opendocument.graphics"},
  {"odh", "text/plain"},
  {"odi", "application/vnd.oasis.opendocument.image"},
  {"odl", "text/plain"},
  {"odm", "application/vnd.oasis.opendocument.text-master"},
  {"odp", "application/vnd.oasis.opendocument.presentation"},
  {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
  {"odt", "application/vnd.oasis.opendocument.text"},
  {"oga", "audio/ogg"},
  {"ogg", "audio/ogg"},
  {"ogv", "video/ogg"},
  {"ogx", "application/ogg"},
  {"one", "application/onenote"},
  {"onea", "application/onenote"},
  {"onepkg", "application/onenote"},
  {"onetmp", "application/onenote"},
  {"onetoc", "application/onenote"},
  {"onetoc2", "application/onenote"},
  {"opus", "audio/ogg"},
  {"orderedtest", "application/xml"},
  {"osdx", "application/opensearchdescription+xml"},
  {"otf", "application/font-sfnt"},
  {"otg", "application/vnd.oasis.opendocument.graphics-template"},
  {"oth", "application/vnd.oasis.opendocument.text-web"},
  {"otp", "application/vnd.oasis.opendocument.presentation-template"},
  {"ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
  {"ott", "application/vnd.oasis.opendocument.text-template"},
  {"oxt", "application/vnd.openofficeorg.extension"},
  {"p10", "application/pkcs10"},
  {"p12", "application/x-pkcs12"},
  {"p7b", "application/x-pkcs7-certificates"},
  {"p7c", "application/pkcs7-mime"},
  {"p7m", "application/pkcs7-mime"},
  {"p7r", "application/x-pkcs7-certreqresp"},
  {"p7s", "application/pkcs7-signature"},
  {"pbm", "image/x-portable-bitmap"},
  {"pcast", "application/x-podcast"},
  {"pct", "image/pict"},
  {"pcx", "application/octet-stream"},
  {"pcz", "application/octet-stream"},
  {"pdf", "application/pdf"},
  {"pfb", "application/octet-stream"},
  {"pfm", "application/octet-stream"},
  {"pfx", "application/x-pkcs12"},
  {"pgm", "image/x-portable-graymap"},
  {"pic", "image/pict"},
  {"pict", "image/pict"},
  {"pkgdef", "text/plain"},
  {"pkgundef", "text/plain"},
  {"pko", "application/vnd.ms-pki.pko"},
  {"pls", "audio/scpls"},
  {"pma", "application/x-perfmon"},
  {"pmc", "application/x-perfmon"},
  {"pml", "application/x-perfmon"},
  {"pmr", "application/x-perfmon"},
  {"pmw", "application/x-perfmon"},
  {"png", "image/png"},
  {"pnm", "image/x-portable-anymap"},
  {"pnt", "image/x-macpaint"},
  {"pntg", "image/x-macpaint"},
  {"pnz", "image/png"},
  {"pot", "application/vnd.ms-powerpoint"},
  {"potm", "application/vnd.ms-powerpoint.template.macroEnabled.12"},
  {"potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
  {"ppa", "application/vnd.ms-powerpoint"},
  {"ppam", "application/vnd.ms-powerpoint.addin.macroEnabled.12"},
  {"ppm", "image/x-portable-pixmap"},
  {"pps", "application/vnd.ms-powerpoint"},
  {"ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
  {"ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
  {"ppt", "application/vnd.ms-powerpoint"},
  {"pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
  {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
  {"prf", "application/pics-rules"},
  {"prm", "application/octet-stream"},
  {"prx", "application/octet-stream"},
  {"ps", "application/postscript"},
  {"psc1", "application/PowerShell"},
  {"psd", "application/octet-stream"},
  {"psess", "application/xml"},
  {"psm", "application/octet-stream"},
  {"psp", "application/octet-stream"},
  {"pst", "application/vnd.ms-outlook"},
  {"pub", "application/x-mspublisher"},
  {"pwz", "application/vnd.ms-powerpoint"},
  {"qht", "text/x-html-insertion"},
  {"qhtm", "text/x-html-insertion"},
  {"qt", "video/quicktime"},
  {"qti", "image/x-quicktime"},
  {"qtif", "image/x-quicktime"},
  {"qtl", "application/x-quicktimeplayer"},
  {"qxd", "application/octet-stream"},
  {"ra", "audio/x-pn-realaudio"},
  {"ram", "audio/x-pn-realaudio"},
  {"rar", {"application/x-rar-compressed", "application/x-rar", "application/octet-stream"}},
  {"ras", "image/x-cmu-raster"},
  {"rat", "application/rat-file"},
  {"rc", "text/plain"},
  {"rc2", "text/plain"},
  {"rct", "text/plain"},
  {"rdlc", "application/xml"},
  {"reg", "text/plain"},
  {"resx", "application/xml"},
  {"rf", "image/vnd.rn-realflash"},
  {"rgb", "image/x-rgb"},
  {"rgs", "text/plain"},
  {"rm", "application/vnd.rn-realmedia"},
  {"rmi", "audio/mid"},
  {"rmp", "application/vnd.rn-rn_music_package"},
  {"roff", "application/x-troff"},
  {"rpm", "audio/x-pn-realaudio-plugin"},
  {"rqy", "text/x-ms-rqy"},
  {"rtf", {"application/rtf","application/msword", "text/richtext"}},
  {"rtx", "text/richtext"},
  {"rvt", "application/octet-stream" },
  {"ruleset", "application/xml"},
  {"s", "text/plain"},
  {"safariextz", "application/x-safari-safariextz"},
  {"scd", "application/x-msschedule"},
  {"scr", "text/plain"},
  {"sct", "text/scriptlet"},
  {"sd2", "audio/x-sd2"},
  {"sdp", "application/sdp"},
  {"sea", "application/octet-stream"},
  {"searchConnector-ms", "application/windows-search-connector+xml"},
  {"setpay", "application/set-payment-initiation"},
  {"setreg", "application/set-registration-initiation"},
  {"settings", "application/xml"},
  {"sgimb", "application/x-sgimb"},
  {"sgml", "text/sgml"},
  {"sh", "application/x-sh"},
  {"shar", "application/x-shar"},
  {"shtml", "text/html"},
  {"sit", "application/x-stuffit"},
  {"sitemap", "application/xml"},
  {"skin", "application/xml"},
  {"skp", "application/x-koan" },
  {"sldm", "application/vnd.ms-powerpoint.slide.macroEnabled.12"},
  {"sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"},
  {"slk", "application/vnd.ms-excel"},
  {"sln", "text/plain"},
  {"slupkg-ms", "application/x-ms-license"},
  {"smd", "audio/x-smd"},
  {"smi", "application/octet-stream"},
  {"smx", "audio/x-smd"},
  {"smz", "audio/x-smd"},
  {"snd", "audio/basic"},
  {"snippet", "application/xml"},
  {"snp", "application/octet-stream"},
  {"sol", "text/plain"},
  {"sor", "text/plain"},
  {"spc", "application/x-pkcs7-certificates"},
  {"spl", "application/futuresplash"},
  {"spx", "audio/ogg"},
  {"src", "application/x-wais-source"},
  {"srf", "text/plain"},
  {"SSISDeploymentManifest", "text/xml"},
  {"ssm", "application/streamingmedia"},
  {"sst", "application/vnd.ms-pki.certstore"},
  {"stl", "application/vnd.ms-pki.stl"},
  {"sv4cpio", "application/x-sv4cpio"},
  {"sv4crc", "application/x-sv4crc"},
  {"svc", "application/xml"},
  {"svg", "image/svg+xml"},
  {"swf", "application/x-shockwave-flash"},
  {"step", "application/step"},
  {"stp", "application/step"},
  {"t", "application/x-troff"},
  {"tar", "application/x-tar"},
  {"tcl", "application/x-tcl"},
  {"testrunconfig", "application/xml"},
  {"testsettings", "application/xml"},
  {"tex", "application/x-tex"},
  {"texi", "application/x-texinfo"},
  {"texinfo", "application/x-texinfo"},
  {"tgz", "application/x-compressed"},
  {"thmx", "application/vnd.ms-officetheme"},
  {"thn", "application/octet-stream"},
  {"tif", {"image/tiff", "application/octet-stream"}},
  {"tiff", "image/tiff"},
  {"tlh", "text/plain"},
  {"tli", "text/plain"},
  {"toc", "application/octet-stream"},
  {"tr", "application/x-troff"},
  {"trm", "application/x-msterminal"},
  {"trx", "application/xml"},
  {"ts", "video/vnd.dlna.mpeg-tts"},
  {"tsv", "text/tab-separated-values"},
  {"ttf", "application/font-sfnt"},
  {"tts", "video/vnd.dlna.mpeg-tts"},
  {"txt", "text/plain"},
  {"u32", "application/octet-stream"},
  {"uls", "text/iuls"},
  {"user", "text/plain"},
  {"ustar", "application/x-ustar"},
  {"vb", "text/plain"},
  {"vbdproj", "text/plain"},
  {"vbk", "video/mpeg"},
  {"vbproj", "text/plain"},
  {"vbs", "text/vbscript"},
  {"vcf", {"text/x-vcard", "text/vcard"}},
  {"vcproj", "application/xml"},
  {"vcs", "text/plain"},
  {"vcxproj", "application/xml"},
  {"vddproj", "text/plain"},
  {"vdp", "text/plain"},
  {"vdproj", "text/plain"},
  {"vdx", "application/vnd.ms-visio.viewer"},
  {"vml", "text/xml"},
  {"vscontent", "application/xml"},
  {"vsct", "text/xml"},
  {"vsd", "application/vnd.visio"},
  {"vsi", "application/ms-vsi"},
  {"vsix", "application/vsix"},
  {"vsixlangpack", "text/xml"},
  {"vsixmanifest", "text/xml"},
  {"vsmdi", "application/xml"},
  {"vspscc", "text/plain"},
  {"vss", "application/vnd.visio"},
  {"vsscc", "text/plain"},
  {"vssettings", "text/xml"},
  {"vssscc", "text/plain"},
  {"vst", "application/vnd.visio"},
  {"vstemplate", "text/xml"},
  {"vsto", "application/x-ms-vsto"},
  {"vsw", "application/vnd.visio"},
  {"vsx", "application/vnd.visio"},
  {"vtx", "application/vnd.visio"},
  {"wav", "audio/wav"},
  {"wave", "audio/wav"},
  {"wax", "audio/x-ms-wax"},
  {"wbk", "application/msword"},
  {"wbmp", "image/vnd.wap.wbmp"},
  {"wcm", "application/vnd.ms-works"},
  {"wdb", "application/vnd.ms-works"},
  {"wdp", "image/vnd.ms-photo"},
  {"webarchive", "application/x-safari-webarchive"},
  {"webm", "video/webm"},
  {"webp", "image/webp"},
  {"webtest", "application/xml"},
  {"wiq", "application/xml"},
  {"wiz", "application/msword"},
  {"wks", "application/vnd.ms-works"},
  {"WLMP", "application/wlmoviemaker"},
  {"wlpginstall", "application/x-wlpg-detect"},
  {"wlpginstall3", "application/x-wlpg3-detect"},
  {"wm", "video/x-ms-wm"},
  {"wma", "audio/x-ms-wma"},
  {"wmd", "application/x-ms-wmd"},
  {"wmf", "application/x-msmetafile"},
  {"wml", "text/vnd.wap.wml"},
  {"wmlc", "application/vnd.wap.wmlc"},
  {"wmls", "text/vnd.wap.wmlscript"},
  {"wmlsc", "application/vnd.wap.wmlscriptc"},
  {"wmp", "video/x-ms-wmp"},
  {"wmv", "video/x-ms-wmv"},
  {"wmx", "video/x-ms-wmx"},
  {"wmz", "application/x-ms-wmz"},
  {"woff", "application/font-woff"},
  {"wpl", "application/vnd.ms-wpl"},
  {"wps", "application/vnd.ms-works"},
  {"wri", "application/x-mswrite"},
  {"wrl", "x-world/x-vrml"},
  {"wrz", "x-world/x-vrml"},
  {"wsc", "text/scriptlet"},
  {"wsdl", "text/xml"},
  {"wvx", "video/x-ms-wvx"},
  {"x", "application/directx"},
  {"xaf", "x-world/x-vrml"},
  {"xaml", "application/xaml+xml"},
  {"xap", "application/x-silverlight-app"},
  {"xbap", "application/x-ms-xbap"},
  {"xbm", "image/x-xbitmap"},
  {"xdr", "text/plain"},
  {"xht", "application/xhtml+xml"},
  {"xhtml", "application/xhtml+xml"},
  {"xla", "application/vnd.ms-excel"},
  {"xlam", "application/vnd.ms-excel.addin.macroEnabled.12"},
  {"xlc", "application/vnd.ms-excel"},
  {"xld", "application/vnd.ms-excel"},
  {"xlk", "application/vnd.ms-excel"},
  {"xll", "application/vnd.ms-excel"},
  {"xlm", "application/vnd.ms-excel"},
  {"xls", {"application/vnd.ms-excel", "application/vnd.ms-office", "application/x-excel", "application/octet-stream"}},
  {"xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
  {"xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"},
  {"xlsx", {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel.12", "application/octet-stream"}},
  {"xlt", "application/vnd.ms-excel"},
  {"xltm", "application/vnd.ms-excel.template.macroEnabled.12"},
  {"xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
  {"xlw", "application/vnd.ms-excel"},
  {"xml", {"application/xml", "text/xml", "application/octet-stream"}},
  {"xmp", "application/octet-stream" },
  {"xmta", "application/xml"},
  {"xof", "x-world/x-vrml"},
  {"XOML", "text/plain"},
  {"xpm", "image/x-xpixmap"},
  {"xps", "application/vnd.ms-xpsdocument"},
  {"xrm-ms", "text/xml"},
  {"xsc", "application/xml"},
  {"xsd", "text/xml"},
  {"xsf", "text/xml"},
  {"xsl", "text/xml"},
  {"xslt", "text/xml"},
  {"xsn", "application/octet-stream"},
  {"xss", "application/xml"},
  {"xspf", "application/xspf+xml"},
  {"xtp", "application/octet-stream"},
  {"xwd", "image/x-xwindowdump"},
  {"z", "application/x-compress"},
  {"zip", {"application/zip", "application/x-zip-compressed", "application/octet-stream"}},
  {"zlib", "application/zlib"},
}

local function check_mime_type(task)
  local function gen_extension(fname)
    local parts = rspamd_str_split(fname, '.')

    local ext = {}
    for n = 1, 2 do
        ext[n] = #parts > n and string.lower(parts[#parts + 1 - n]) or nil
    end

    return ext[1],ext[2],parts
  end

  local function check_filename(fname, ct, is_archive, part)
    local ext,ext2,parts = gen_extension(fname)
    -- ext is the last extension, LOWERCASED
    -- ext2 is the one before last extension LOWERCASED

    local function check_extension(badness_mult, badness_mult2)
      if not badness_mult and not badness_mult2 then return end
      if #parts > 2 then
        -- We need to ensure that next-to-last extension is an extension,
        -- so we check for its length and if it is not a number or date
        if #ext2 <= 4 and not string.match(ext2, '^%d+$') then

          -- Use the greatest badness multiplier
          if not badness_mult or
              (badness_mult2 and badness_mult < badness_mult2) then
            badness_mult = badness_mult2
          end

          -- Double extension + bad extension == VERY bad
          task:insert_result(settings['symbol_double_extension'], badness_mult,
            string.format(".%s.%s", ext2, ext))
          task:insert_result('MIME_TRACE', 0.0,
              string.format("%s:%s", part:get_id(), '-'))
          return
        end
      end
      if badness_mult then
        -- Just bad extension
        task:insert_result(settings['symbol_bad_extension'], badness_mult, ext)
        task:insert_result('MIME_TRACE', 0.0,
            string.format("%s:%s", part:get_id(), '-'))
      end
    end

    if ext then
      -- Also check for archive bad extension
      if is_archive then
        if ext2 then
          local score1 = settings['bad_archive_extensions'][ext] or
              settings['bad_extensions'][ext]
          local score2 = settings['bad_archive_extensions'][ext2] or
              settings['bad_extensions'][ext2]
          check_extension(score1, score2)
        else
          local score1 = settings['bad_archive_extensions'][ext] or
              settings['bad_extensions'][ext]
          check_extension(score1, nil)
        end

        if settings['archive_extensions'][ext] then
          -- Archive in archive
          task:insert_result(settings['symbol_archive_in_archive'], 1.0, ext)
          task:insert_result('MIME_TRACE', 0.0,
              string.format("%s:%s", part:get_id(), '-'))
        end
      else
        if ext2 then
          check_extension(settings['bad_extensions'][ext],
            settings['bad_extensions'][ext2])
          -- Check for archive cloaking like .zip.gz
          if settings['archive_extensions'][ext2]
            -- Exclude multipart archive extensions, e.g. .zip.001
            and not string.match(ext, '^%d+$')
          then
            task:insert_result(settings['symbol_archive_in_archive'],
                1.0, string.format(".%s.%s", ext2, ext))
            task:insert_result('MIME_TRACE', 0.0,
                string.format("%s:%s", part:get_id(), '-'))
          end
        else
          check_extension(settings['bad_extensions'][ext], nil)
        end
      end

      local mt = settings['extension_map'][ext]
      if mt and ct then
        local found
        local mult
        for _,v in ipairs(mt) do
          mult = v.mult
          if ct == v.ct then
            found = true
            break
          end
        end

        if not found  then
          task:insert_result(settings['symbol_attachment'], mult, ext)
        end
      end
    end
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      local mtype,subtype = p:get_type()
      local dtype,dsubtype = p:get_detected_type()

      if not mtype then
        task:insert_result(settings['symbol_unknown'], 1.0, 'missing content type')
        task:insert_result('MIME_TRACE', 0.0,
            string.format("%s:%s", p:get_id(), '~'))
      else
        -- Check for attachment
        local filename = p:get_filename()
        local ct = string.format('%s/%s', mtype, subtype):lower()
        local detected_ct
        if dtype and dsubtype then
          detected_ct = string.format('%s/%s', dtype, dsubtype)
        end

        if filename then
          filename = filename:gsub('[^%s%g]', '?')
          check_filename(filename, ct, false, p)
        end

        if p:is_archive() then

          local check = true

          if filename then
            local ext = gen_extension(filename)

            if ext and settings.archive_exceptions[ext] then
              check = false
              logger.debugm("mime_types", task, "skip checking of %s as archive, %s is whitelisted",
                filename, ext)
            end
          end
          local arch = p:get_archive()

          if arch:is_encrypted() then
            task:insert_result(settings['symbol_encrypted_archive'], 1.0, filename)
            task:insert_result('MIME_TRACE', 0.0,
                string.format("%s:%s", p:get_id(), '-'))
          end

          if check then
            local fl = arch:get_files_full()

            for _,f in ipairs(fl) do
              -- Strip bad characters
              if f['name'] then
                f['name'] = f['name']:gsub('[\128-\255%s%G]', '?')
              end

              if f['encrypted'] then
                task:insert_result(settings['symbol_encrypted_archive'],
                    1.0, f['name'])
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '-'))
              end

              if f['name'] then
                check_filename(f['name'], nil, true, p)
              end
            end
          end
        end

        if map then
          local v
          local detected_different = false
          if detected_ct and detected_ct ~= ct then
            v = map:get_key(detected_ct)
            detected_different = true
          else
            v = map:get_key(ct)
          end
          if v then
            local n = tonumber(v)

            if n then
              if n > 0 then
                if detected_different then
                  -- Penalize case
                  n = n * 1.5
                  task:insert_result(settings['symbol_bad'], n,
                      string.format('%s:%s', ct, detected_ct))
                else
                  task:insert_result(settings['symbol_bad'], n, ct)
                end
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '-'))
              elseif n < 0 then
                task:insert_result(settings['symbol_good'], -n, ct)
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '+'))
              end
            else
              logger.warnx(task, 'unknown value: "%s" for content type %s in the map',
                  v, ct)
            end
          else
            task:insert_result(settings['symbol_unknown'], 1.0, ct)
            task:insert_result('MIME_TRACE', 0.0,
                string.format("%s:%s", p:get_id(), '~'))
          end
        end
      end
    end
  end
end

local opts =  rspamd_config:get_all_opt('mime_types')
if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end

  local function change_extension_map_entry(ext, ct, mult)
    if type(ct) == 'table' then
      local tbl = {}
      for _,elt in ipairs(ct) do
        table.insert(tbl, {
          ct = elt,
          mult = mult,
        })
      end
      settings.extension_map[ext] = tbl
    else
      settings.extension_map[ext] = { [1] = {
        ct = ct,
        mult = mult
      } }
    end
  end

  -- Transform extension_map
  for ext,ct in pairs(settings.extension_map) do
    change_extension_map_entry(ext, ct, 1.0)
  end

  -- Add all extensions
  for _,pair in ipairs(full_extensions_map) do
    local ext, ct = pair[1], pair[2]
    if not settings.extension_map[ext] then
        change_extension_map_entry(ext, ct, settings.other_extensions_mult)
    end
  end

  local type = 'map'
  if settings['regexp'] then type = 'regexp' end
  map = rspamd_map_add('mime_types', 'file', type,
    'mime types map')
  if map then
    local id = rspamd_config:register_symbol({
      name = 'MIME_TYPES_CALLBACK',
      callback = check_mime_type,
      type = 'callback,nostat',
      group = 'mime_types',
    })

    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_unknown'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_good'],
      flags = 'nice',
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_attachment'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_encrypted_archive'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_archive_in_archive'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_double_extension'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad_extension'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual,nostat',
      name = 'MIME_TRACE',
      parent = id,
      group = 'mime_types',
      score = 0,
    })
  else
    lua_util.disable_module(N, "config")
  end
end
