package azkaban.webapp.servlet;

import azkaban.ServiceProvider;
import azkaban.scheduler.ScheduleManagerException;
import azkaban.server.AzkabanServer;
import azkaban.server.session.Session;
import azkaban.server.session.SessionCache;
import azkaban.trigger.TriggerManagerException;
import azkaban.user.User;
import azkaban.user.UserManager;
import azkaban.user.UserManagerException;
import azkaban.utils.EncryptUtil;
import azkaban.utils.Props;
import azkaban.utils.StringUtils;
import azkaban.utils.WebUtils;
import azkaban.webapp.AzkabanWebServer;
import azkaban.webapp.WebMetrics;
import com.webank.wedatasphere.schedulis.common.i18nutils.LoadJsonUtils;
import com.webank.wedatasphere.schedulis.common.system.JdbcSystemUserImpl;
import com.webank.wedatasphere.schedulis.common.system.SystemUserLoader;
import com.webank.wedatasphere.schedulis.common.system.SystemUserManagerException;
import com.webank.wedatasphere.schedulis.common.system.entity.WtssUser;
import com.webank.wedatasphere.schedulis.common.user.SystemUserManager;
import com.webank.wedatasphere.schedulis.common.utils.RSAUtils;
import com.webank.wedatasphere.schedulis.common.utils.XSSFilterUtils;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static azkaban.Constants.WTSS_PUBLIC_KEY;
import static azkaban.ServiceProvider.SERVICE_PROVIDER;
import static azkaban.webapp.servlet.LoginAbstractAzkabanServlet.SESSION_ID_NAME;

public abstract class AbstractLoginAzkabanServlet extends AbstractAzkabanServlet {

    private static final Logger logger = LoggerFactory.getLogger(AbstractLoginAzkabanServlet.class);

    private static final int DEFAULT_UPLOAD_DISK_SPOOL_SIZE = 20 * 1024 * 1024;

    private AzkabanServer application;
    private final WebMetrics webMetrics = SERVICE_PROVIDER.getInstance(WebMetrics.class);
    private boolean shouldLogRawUserAgent = false;
    private File webResourceDirectory = null;
    private static final HashMap<String, String> CONTEXT_TYPE = new HashMap<>();
    private MultipartParser multipartParser;

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        this.multipartParser = new MultipartParser(DEFAULT_UPLOAD_DISK_SPOOL_SIZE);

        this.shouldLogRawUserAgent = getApplication().getServerProps().getBoolean("accesslog.raw.useragent",false);
        //获取Web Server实体对象
        this.application = SERVICE_PROVIDER.getInstance(AzkabanWebServer.class);
    }

    private Session getSessionFromRequest(final HttpServletRequest req)
            throws ServletException {
        final Cookie cookie = getCookieByName(req, SESSION_ID_NAME);
        String sessionId = null;
        String referer = req.getHeader("Referer");

        final Props props = this.application.getServerProps();
        String refererUrl = props.getString("azkaban.header.referer.url", "");

        if (cookie != null) {
            sessionId = cookie.getValue();
        }

        if (sessionId == null && hasParam(req, "session.id")) {
            sessionId = getParam(req, "session.id");
        }

        return getSessionFromSessionId(sessionId);
    }

    private Session getSessionFromSessionId(final String sessionId) {
        if (sessionId == null) {
            return null;
        }

        return getApplication().getSessionCache().getSession(sessionId);
    }

    private String getRealClientIpAddr(final HttpServletRequest req) {

        // If some upstream device added an X-Forwarded-For header
        // use it for the client ip
        // This will support scenarios where load balancers or gateways
        // front the Azkaban web server and a changing Ip address invalidates
        // the session
        final HashMap<String, String> headers = new HashMap<>();
        headers.put(WebUtils.X_FORWARDED_FOR_HEADER, req.getHeader(WebUtils.X_FORWARDED_FOR_HEADER.toLowerCase()));

        final WebUtils utils = new WebUtils();

        return utils.getRealClientIpAddr(headers, req.getRemoteAddr());
    }

    private boolean isIllegalPostRequest(final HttpServletRequest req) {
        return (req.getQueryString() != null && req.getQueryString().contains("password="));
    }

    private void logRequest(final HttpServletRequest req, final Session session) {
        final StringBuilder buf = new StringBuilder();
        buf.append(getRealClientIpAddr(req)).append(" ");
        if (session != null && session.getUser() != null) {
            buf.append(session.getUser().getUserId()).append(" ");
        } else {
            buf.append(" - ").append(" ");
        }

        buf.append("\"");
        buf.append(req.getMethod()).append(" ");
        buf.append(req.getRequestURI()).append(" ");
        if (req.getQueryString() != null && !isIllegalPostRequest(req)) {
            buf.append(req.getQueryString()).append(" ");
        } else {
            buf.append("-").append(" ");
        }
        buf.append(req.getProtocol()).append("\" ");

        final String userAgent = req.getHeader("User-Agent");
        if (this.shouldLogRawUserAgent) {
            buf.append(userAgent);
        } else {
            // simply log a short string to indicate browser or not
            if (StringUtils.isFromBrowser(userAgent)) {
                buf.append("browser");
            } else {
                buf.append("not-browser");
            }
        }

        logger.info(buf.toString());
    }

    private boolean isRequestWithoutSession(HttpServletRequest req) {
        String ajaxName = getParam(req, "ajax", "");
        return "executeFlowCycleFromExecutor".equals(ajaxName) || "reloadWebData".equals(ajaxName);
    }

    private boolean handleFileGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws IOException {
        if (this.webResourceDirectory == null) {
            return false;
        }

        // Check if it's a resource
        final String prefix = req.getContextPath() + req.getServletPath();
        String path = req.getRequestURI().substring(prefix.length());

        // 路径操作漏洞,将非法请求路径中的目录转换为不可到达
        path = path.replace("../", "");

        final int index = path.lastIndexOf('.');
        if (index == -1) {
            return false;
        }

        final String extension = path.substring(index);
        if (CONTEXT_TYPE.containsKey(extension)) {
            final File file = new File(this.webResourceDirectory, path);
            if (!file.exists() || !file.isFile()) {
                return false;
            }

            resp.setContentType(CONTEXT_TYPE.get(extension));

            final OutputStream output = resp.getOutputStream();
            BufferedInputStream input = null;
            try {
                input = new BufferedInputStream(new FileInputStream(file));
                IOUtils.copy(input, output);
            } finally {
                if (input != null) {
                    input.close();
                }
            }
            output.flush();
            return true;
        }

        return false;
    }

    private void handleErrorRequest(final HttpServletRequest req, final HttpServletResponse resp,
                                    final String errorMsg) throws ServletException, IOException {
        final Page page = newPage(req, resp, "azkaban/webapp/servlet/velocity/single-error-page.vm");
        page.add("errorMsg", errorMsg);
        String languageType = LoadJsonUtils.getLanguageType();
        page.add("currentlangType", languageType);
        page.render();
        resp.sendError(230);
    }

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        final Props props = this.application.getServerProps();
        String nginxSSL = props.getString("nginx.ssl.module", "");
        if("open".equals(nginxSSL)) {
            String referer = req.getHeader("Referer");
            String refererUrl = props.getString("azkaban.header.referer.url", "");
            // 判断 Referer 是否以 bank.example 开头
            if ((null != referer) && !(referer.trim().startsWith(refererUrl))) {
                resp.sendRedirect("/error");
            }
        }
        this.webMetrics.markWebGetCall();
        // Set session id
        final Session session = getSessionFromRequest(req);
        logRequest(req, session);
        if (this.validCsrf(req, resp, session, true, null)) {
            resp.sendRedirect("/error");
            return;
        }
        if (hasParam(req, "logout")) {
            resp.sendRedirect(req.getContextPath());
            if (session != null) {
                getApplication().getSessionCache().removeSession(session.getSessionId());
            }
            return;
        }

        //session不为空，或者请求不需要检查session
        if (session != null || isRequestWithoutSession(req)) {
            if("open".equals(nginxSSL)) {
                //XSS参数过滤
                String reqString = req.getQueryString();
                if (XSSFilterUtils.invalidStringFilter(reqString)) {
                    resp.sendRedirect("/error");
                    return;
                }
                if (XSSFilterUtils.invalidCookieFilter(req)) {
                    resp.sendRedirect("/error");
                    return;
                }
            }
            if (session != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Found session {}", session.getUser());
                }
                Object csrfToken = session.getSessionData("csrfToken");
                if (csrfToken != null) {
                    resp.setHeader("csrfToken", csrfToken.toString());
                }
            }
            if (handleFileGet(req, resp)) {
                return;
            }
            if ("/error".equals(req.getRequestURI())) {
                handleErrorRequest(req, resp, "Illegal Request.");
                return;
            }
            handleGet(req, resp, session);
        } else {
            if (hasParam(req, "ajax")) {
                final HashMap<String, String> retVal = new HashMap<>();
                retVal.put("error", "session");
                //处理ajax请求， session超时
                resp.setHeader("session-status", "timeout");
                this.writeJSON(resp, retVal);
            } else if ("/toL".equals(req.getRequestURI())){
                handleLogin(req, resp);
            } else if ("/error".equals(req.getRequestURI())) {
                handleErrorRequest(req, resp, "Illegal Request.");
            } else {
                handleLogin(req, resp);
            }
        }
    }

    private void handleLogin(final HttpServletRequest req, final HttpServletResponse resp,
                             final String errorMsg) throws ServletException, IOException {
        String setCookie = resp.getHeader("Set-Cookie");
        if(null != setCookie){
            resp.setHeader("Set-Cookie", setCookie + ";Secure");
            resp.setHeader("Set-Cookie", setCookie + ";HttpOnly");
        }
        final Page page = newPage(req, resp, "azkaban/webapp/servlet/velocity/login.vm");

        String languageType = LoadJsonUtils.getLanguageType();
        Map<String, String> loginMap;
        Map<String, String> subPageMap1;
        if ("zh_CN".equalsIgnoreCase(languageType)) {
            // 添加国际化标签
            loginMap = LoadJsonUtils.transJson("/conf/azkaban-web-server-zh_CN.json",
                    "azkaban.webapp.servlet.velocity.login.vm");
            subPageMap1 = LoadJsonUtils.transJson("/conf/azkaban-web-server-zh_CN.json",
                    "azkaban.webapp.servlet.velocity.nav.vm");
            this.passwordPlaceholder = "密码";
        }else {
            loginMap = LoadJsonUtils.transJson("/conf/azkaban-web-server-en_US.json",
                    "azkaban.webapp.servlet.velocity.login.vm");
            subPageMap1 = LoadJsonUtils.transJson("/conf/azkaban-web-server-en_US.json",
                    "azkaban.webapp.servlet.velocity.nav.vm");
            this.passwordPlaceholder = "Password";
        }
        loginMap.forEach(page::add);
        subPageMap1.forEach(page::add);

        page.add("passwordPlaceholder", this.passwordPlaceholder);
        page.add("publicKey", getApplication().getServerProps().get(WTSS_PUBLIC_KEY));
        page.add("opsLoginCheck", getApplication().getServerProps().getBoolean("wtss.opsuser.login.switch", false));
        if (errorMsg != null) {
            page.add("errorMsg", errorMsg);
        }
        page.add("currentlangType", languageType);
        page.render();
    }

    private void handleLogin(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        handleLogin(req, resp, null);
    }

    protected abstract void handleGet(HttpServletRequest req, HttpServletResponse resp, Session session) throws ServletException, IOException;

    private boolean validCsrf(HttpServletRequest req, HttpServletResponse resp, Session session,
                              boolean isGet, Map<String, Object> params)
            throws IOException, ServletException {
        if (!getApplication().getServerProps().getBoolean("azkaban.csrf.check", true) || session == null
                || "/error".equals(req.getRequestURI()) || !StringUtils
                .isFromBrowser(req.getHeader("User-Agent"))) {
            return false;
        }
        if (isGet) {
            if (!hasParam(req, "ajax") && !hasParam(req, "action") && !hasParam(req, "delete")
                    && !hasParam(req, "purge") && !hasParam(req, "download") && !hasParam(req, "logout")) {
                return false;
            }
            String referer = req.getHeader("Referer");
            if (referer == null || !referer.contains(req.getServerName())) {
                handleLogin(req, resp);
                return true;
            }
        } else {
            Object csrfToken = session.getSessionData("csrfToken");
            if (csrfToken != null && !csrfToken.equals(req.getHeader("csrfToken")) && (params == null
                    ? true : !csrfToken.equals(params.get("csrfToken") + ""))) {
                resp.sendRedirect("/error");
                return true;
            }
        }
        return false;
    }

    protected void writeResponse(final HttpServletResponse resp, final String response) throws IOException {
        final Writer writer = resp.getWriter();
        writer.append(response);
        writer.flush();
    }

    protected void handleMultiformPost(final HttpServletRequest req,
                                       final HttpServletResponse resp, final Map<String, Object> multipart, final Session session)
            throws ServletException, IOException {
    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        Session session = getSessionFromRequest(req);
        this.webMetrics.markWebPostCall();
        logRequest(req, session);
        Map<String, Object> params = null;
        if (ServletFileUpload.isMultipartContent(req)) {
            params = this.multipartParser.parseMultipart(req);
        }
        if (this.validCsrf(req, resp, session, false, params)) {
            return;
        }
        if (session != null) {
            resp.setHeader("csrfToken", session.getSessionData("csrfToken") + "");
        }
        if (isIllegalPostRequest(req)) {
            writeResponse(resp, "Login error. Must pass username and password in request body");
            return;
        }
        final Props props = this.application.getServerProps();
        String nginxSSL = props.getString("nginx.ssl.module", "");
        if("open".equals(nginxSSL)) {
            String referer = req.getHeader("Referer");
            String refererUrl = props.getString("azkaban.header.referer.url", "");
            // 判断 Referer 是否以 bank.example 开头
            if ((referer != null) && !(referer.trim().startsWith(refererUrl))) {
                resp.sendRedirect("/error");
            }

            Map<String, String[]> param = req.getParameterMap();
            for(Map.Entry<String, String[]> entry : param.entrySet()){
                //XSS参数过滤
                String reqString = ObjectUtils.toString(entry.getValue()[0]);
                if(XSSFilterUtils.invalidStringFilter(reqString)){
                    //handleErrorRequest(req, resp, "请不要输入非法字符串！");
                    resp.sendRedirect("/error");
                    return;
                }
            }
            if(XSSFilterUtils.invalidCookieFilter(req)){
                resp.sendRedirect("/error");
                return;
            }
        }
        // Handle Multipart differently from other post messages
        if (ServletFileUpload.isMultipartContent(req)) {
            if (session == null) {
                // See if the session id is properly set.
                if (params.containsKey("session.id")) {
                    final String sessionId = (String) params.get("session.id");

                    session = getSessionFromSessionId(sessionId);
                    if (session != null) {
                        handleMultiformPost(req, resp, params, session);
                        return;
                    }
                }

                // if there's no valid session, see if it's a one time session.
                if (!params.containsKey("username") || !params.containsKey("userpwd")) {
                    writeResponse(resp, "Login error. Need username and password");
                    return;
                }

                final String username = (String) params.get("username");
                final String password  = (String) params.get("userpwd");
                final String ip = getRealClientIpAddr(req);

                String wtss_secret_de = props.getString("dss.secret", "");
                String wtss_private_key = props.getString("wtss.private.key", "");
                String from_dss_secret_de = "";
                if(params.containsKey("dss_secret")){
                    String from_dss_secret_en = (String)params.get("dss_secret");
                    logger.info("handle dss login , secret > {}" , from_dss_secret_en);
                    try {
                        if(from_dss_secret_en!=null){
                            from_dss_secret_en = from_dss_secret_en.replaceAll(" ","+");
                        }
                        from_dss_secret_de = RSAUtils.decrypt(from_dss_secret_en,wtss_private_key);
                    } catch (Exception e) {
                        logger.error("parse dss.secret failed , caused by {} " , e);
                    }
                }
                if(wtss_secret_de.equals(from_dss_secret_de)){
                    logger.info("handle dss login , dss_secret pass check" );
                    try{
                        session = createSession(username, password, ip, wtss_secret_de);
                        resp.setHeader("csrfToken", session.getSessionData("csrfToken") + "");
                    } catch(final Exception e){
                        writeResponse(resp, "Login error: " + e.getMessage());
                        return;
                    }
                }else{
                    try {
                        session = createSession(username, password, ip);
                        resp.setHeader("csrfToken", session.getSessionData("csrfToken") + "");
                    } catch (final UserManagerException e) {
                        writeResponse(resp, "Login error: " + e.getMessage());
                        return;
                    }
                }
            }
            handleMultiformPost(req, resp, params, session);
        } else if ("/checkin".equals(req.getRequestURI()) && hasParam(req, "action")
                && "login".equals(getParam(req, "action"))) {
            final HashMap<String, Object> obj = new HashMap<>();
            handleAjaxLoginAction(req, resp, obj);
            this.writeJSON(resp, obj);
        } else if (session == null) {
            if (hasParam(req, "username") && hasParam(req, "userpwd")) {
                // If it's a post command with curl, we create a temporary session
                try {
                    session = createSession(req);
                    resp.setHeader("csrfToken", session.getSessionData("csrfToken") + "");
                } catch (final UserManagerException e) {
                    writeResponse(resp, "Login error: " + e.getMessage());
                }
                try {
                    handlePost(req, resp, session);
                } catch (TriggerManagerException e) {
                    e.printStackTrace();
                } catch (ScheduleManagerException e) {
                    e.printStackTrace();
                }
            } else {
                // There are no valid sessions and temporary logins, no we either pass
                // back a message or redirect.
                if (isAjaxCall(req)) {
                    final String response =
                            createJsonResponse("error", "Invalid Session. Please login in again.",
                                    "login", null);
                    resp.setCharacterEncoding("utf-8");
                    //处理ajax请求， session超时
                    resp.setHeader("session-status", "timeout");
                    writeResponse(resp, response);
                } else {
                    handleLogin(req, resp, "Enter username and password");
                }
            }
        } else {
            try {
                handlePost(req, resp, session);
            } catch (TriggerManagerException e) {
                e.printStackTrace();
            } catch (ScheduleManagerException e) {
                e.printStackTrace();
            }
        }
    }

    private Session createSession(final String username, final String password, final String ip,
                                  final String superUser) throws UserManagerException{

        UserManager manager = getApplication().getTransitionService().getUserManager();
        if (manager instanceof SystemUserManager){
            //不改接口，直接改SystemUserManager，这样做到少侵入
            SystemUserManager userManager = (SystemUserManager)manager;
            final User user = userManager.getUser(username, password, superUser);
            logger.info("User is {}", user.toString());
            final String uuid = UUID.randomUUID().toString();
            return new Session(uuid, user, ip);
        }else{
            logger.warn("user manager 不是 WebankXmlUserManager 实例，不能进行创建session");
            return null;
        }
    }

    private Session createSession(final String username, final String password, final String ip)
            throws UserManagerException, ServletException {
        final UserManager manager = getApplication().getTransitionService().getUserManager();
        final User user = manager.getUser(username, password);

        final String randomUID = UUID.randomUUID().toString();
        final Session session = new Session(randomUID, user, ip);

        return session;
    }

    private Session createSession(final HttpServletRequest req)
            throws UserManagerException, ServletException, IOException {
        final String username = getParam(req, "username");
        String password = getParam(req, "userpwd");
        String frompage = "";
        if(hasParam(req, "frompage")){
            frompage = getParam(req, "frompage");
        }

        final Props props = this.application.getServerProps();

        if (hasParam(req, "encryption") && "true".equals(getParam(req, "encryption"))){
            String wtss_private_key = props.getString("wtss.private.key", "");
            logger.debug("encryption is enable , decode password {}" , password);
            try {
                if(password!=null){
                    password = password.replaceAll(" ","+");
                }
                password = RSAUtils.decrypt(password,wtss_private_key);
            } catch (Exception e) {
                throw new RuntimeException("parse encryption secret info failed , caused by {} " + e.getMessage());
            }
        }

        final String ip = getRealClientIpAddr(req);

        try{
            String wtss_secret_de = props.getString("dss.secret", "");
            String wtss_private_key = props.getString("wtss.private.key", "");
            String from_dss_secret_de = "";
            if(hasParam(req, "dss_secret")){
                String from_dss_secret_en = (String)getParam(req, "dss_secret");
                logger.debug("handle dss login , secret > {}" , from_dss_secret_en);
                try {
                    if(from_dss_secret_en!=null){
                        from_dss_secret_en = from_dss_secret_en.replaceAll(" ","+");
                    }
                    from_dss_secret_de = RSAUtils.decrypt(from_dss_secret_en,wtss_private_key);
                } catch (Exception e) {
                    throw new RuntimeException("parse dss.secret failed , caused by " , e);
                }
            }

            if(wtss_secret_de.equals(from_dss_secret_de)){
                logger.debug("handle dss login , dss_secret pass check" );
                //如果超级用户用户名和密码都是对的，那么我们直接放行
                if(!StringUtils.isFromBrowser(req.getHeader("User-Agent"))){
                    logger.info("not browser.");
                    Session cacheSession = null;
                    try {
                        cacheSession = this.application.getSessionCache().getSessionByUsername(username);
                    } catch (Exception e) {
                        logger.info("get session by username error, caused by: " + e);
                    }
                    if(cacheSession != null){
                        logger.info("session not found.");
                        return cacheSession;
                    }
                }

                SessionCache sessionCache = getApplication().getSessionCache();
                Session sessionByUsername = sessionCache.getSessionByUsername(username);
                if (sessionByUsername == null) {
                    Session newSession = createSession(username, password, ip, wtss_secret_de);
                    sessionCache.addSession(newSession);
                    return newSession;
                } else {
                    return sessionByUsername;
                }
            }
        }catch(final Exception e){
            logger.error("no super user", e);
            //没有超级用户，直接ignore
        }
        if("true".equals(frompage)){
            try {
                String passwordPrivateKey = props.getString("password.private.key");
                password = EncryptUtil.decrypt(passwordPrivateKey, password);
            } catch (Exception e){
                logger.error("decrypt password failed.", e);
                throw new UserManagerException("decrypt password failed.");
            }
            checkUserCategory(req, username);
        }
        return createSession(username, password, ip, req);
    }

    private void checkUserCategory(HttpServletRequest req, String username) throws ServletException, UserManagerException {
        //开关打开才校验用户类型
        if (!getApplication().getServerProps().getBoolean("wtss.opsuser.login.switch", false)) {
            return;
        }

        if (username == null || username.trim().isEmpty()) {
            return;
        }

        String userCategory = getUserCategory(username);
        if (hasParam(req, "isOps") && "true".equals(getParam(req, "isOps")) && !"".equals(userCategory)) {
            //ops-运维用户
            if (!"ops".equals(userCategory)) {
                throw new UserManagerException("not ops user.");
            }
            //校验实名用户
            String normalUser = getParam(req, "normalUserName");
            if (normalUser == null || normalUser.trim().isEmpty()) {
                return;
            }
            if (!"personal".equals(getUserCategory(normalUser))) {
                throw new UserManagerException("the normal user is not real-name user.");
            }
        } else {
            //普通用户登录
            if ("ops".equals(userCategory)) {
                throw new UserManagerException("the username is ops user.");
            }
        }
    }

    private String getUserCategory(String username) {
        SystemUserLoader systemUserLoader = ServiceProvider.SERVICE_PROVIDER.getInstance(JdbcSystemUserImpl.class);
        try {
            WtssUser wtssUser = systemUserLoader.getWtssUserByUsername(username);
            if (wtssUser != null) {
                return wtssUser.getUserCategory() == null ? "" : wtssUser.getUserCategory().trim();
            }
        } catch (SystemUserManagerException e) {
            logger.error("query user by name exception", e);
        }
        return "";
    }

    private Session createSession(final String username, final String password, final String ip, HttpServletRequest request)
            throws UserManagerException, ServletException {
        final UserManager manager = getApplication().getTransitionService().getUserManager();
        User user = null;
        if ("dssToken".equals(password)) {
            user = new User(username);
        } else {
            if (hasParam(request, "isOps") && "true".equals(getParam(request, "isOps"))) {
                String normalUserName = getParam(request, "normalUserName");
                String normalPassword = getParam(request, "normalPassword");
                user = manager.validateOpsUser(username, password, normalUserName, normalPassword);
            } else {
                user = manager.getUser(username, password);
            }
        }
        if(!StringUtils.isFromBrowser(request.getHeader("User-Agent"))){
            logger.info("not browser.");
            Session cacheSession = this.application.getSessionCache().getSessionByUsername(username);
            if(cacheSession != null){
                logger.info("session not found.");
                return cacheSession;
            }
        }

        SessionCache sessionCache = getApplication().getSessionCache();
        Session sessionByUsername = sessionCache.getSessionByUsername(username);
        if (sessionByUsername == null) {
            final String randomUID = UUID.randomUUID().toString();
            final Session session = new Session(randomUID, user, ip);
            sessionCache.addSession(session);
            return session;
        } else {
            return sessionByUsername;
        }
    }

    protected abstract void handlePost(HttpServletRequest req, HttpServletResponse resp, Session session) throws ServletException, IOException, TriggerManagerException, ScheduleManagerException;

    protected boolean isAjaxCall(final HttpServletRequest req) throws ServletException {
        final String value = req.getHeader("X-Requested-With");
        if (value != null) {
            logger.info("has X-Requested-With {}", value);
            return "XMLHttpRequest".equals(value);
        }
        final String ajaxString = req.getParameter("ajax");
        if(null != ajaxString && ajaxString.contains("ext")){
            return true;
        }

        return false;
    }

    protected void handleAjaxLoginAction(final HttpServletRequest req,
                                         final HttpServletResponse resp, final Map<String, Object> ret)
            throws ServletException {

        final Props props = this.application.getServerProps();
        String nginxSSL = props.getString("nginx.ssl.module", "");
        if("open".equals(nginxSSL)){
            //SSL模式下 cookie安全 为了通过 appscan 测试
//      List<String> cookieList = (ArrayList<String>) resp.getHeaders("Set-Cookie");
//      for(String setC : cookieList){
//        //setC = resp.getHeader("Set-Cookie");
//        resp.setHeader("Set-Cookie", setC + ";Secure");
//      }
            String setCookie = resp.getHeader("Set-Cookie");
            resp.setHeader("Set-Cookie", setCookie + ";Secure");
            resp.setHeader("Set-Cookie", setCookie + ";HttpOnly");
        }

        if (hasParam(req, "username") && hasParam(req, "userpwd")) {
            Session session = null;
            try {
                session = createSession(req);
                resp.setHeader("csrfToken", session.getSessionData("csrfToken") + "");
            } catch (final UserManagerException | IOException e) {
                ret.put("error", "Login in error. " + e.getMessage());
                return;
            }
            if (null == session){
                logger.error("session is null");
                ret.put("error","Login in error, session is null.");
                return;
            }
            final Cookie cookie = new Cookie(SESSION_ID_NAME, session.getSessionId());
            cookie.setPath("/");
            if("open".equals(nginxSSL)) {
                cookie.setSecure(true);
                //限制web页面程序的browser端script程序读取cookie 开启可能会影响测试工具工作
                cookie.setHttpOnly(true);
            }
            cookie.setHttpOnly(true);
            resp.addCookie(cookie);

            ret.put("status", "success");
            ret.put("session.id", session.getSessionId());

        } else {
            ret.put("error", "Login in error.");
        }
    }

}
