package com.corp.vul;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.ProgressListener;
import org.apache.log4j.Logger;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.coverity.security.Escape;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static java.util.Arrays.asList;

/**
 * Created by 0c0c0f on 2015/12/8.
 */

public class SecurityUtil {
    //防范xss漏洞,重载方法，大多数是直接输出到html标签内
    public static String SecurityXssScript(String content) {
        return Escape.html(content);
    }

    public static String SecurityXssScript(String content, String type) {
        if (type.equals("h")) {
            return Escape.html(content);
        } else if (type.equals("u")) {
            return Escape.uri(content);
        } else if (type.equals("uh")) {
            return Escape.html(Escape.uri(content));
        } else if (type.equals("jh")) {
            return Escape.html(Escape.jsString(content));
        } else if (type.equals("j")) {
            return Escape.jsString(content);
        } else if (type.equals("hj")) {
            return Escape.jsString(Escape.html(content));
        } else if (type.equals("c")) {
            return Escape.cssString(content);
        } else if (type.equals("ch")) {
            return Escape.html(Escape.cssString(content));
        }
        return Escape.html(content);
    }

    //防范SQL注入漏洞
    public static String SecuritySQLI(String content) {
        //根据关键字过滤
        return content.replaceAll("(?i)select", "&#115;elect").replaceAll("(?i)insert", "&#105;nsert").replaceAll("(?i)update", "&#117;pdate").
                replaceAll("(?i)delete", "&#100;elete").replaceAll("(?i)drop", "&#100;rop").replaceAll("(?i)create", "&#99;reate").replaceAll("(?i)union", "&#117;nion").
                replaceAll("(?i)benchmark", "&#98;enchmark").replaceAll("(?i)sleep", "&#98;leep").
                replaceAll("(?i)substring", "&#115;ubstring").replaceAll("(?i)and", "&#97;nd").replaceAll("(?)or", "&#111;r");
    }

    //防范任意文件读取漏洞
    public static boolean SecurityLFI(Path dir, Path file) throws Exception {
        try {
            if (!Files.exists(file.toAbsolutePath().normalize()) || Files.isHidden(file) || !file.toAbsolutePath().normalize().startsWith(dir.toAbsolutePath())) {
                return false;
            } else {
                return true;
            }
        } catch (Exception e) {
            throw new Exception("Down failure Problem during down files:" + e.getMessage());
        }
    }

    //文件后缀检测函数
    public static boolean isValidFileName(String fileName) {
        String extsStr = "txt|doc|docx|pdf|xls|xlsx|jpg|png|cvs|ppt|pptx";
        String filesStr = "\0|00|%00|;|.asp|.jsp|.aspx|.php|.asa|.cer";
        List<String> extList = asList(extsStr.split("\\|"));
        List<String> fileList = asList(filesStr.split("\\|"));
        String preName = fileName.substring(0, fileName.lastIndexOf("."));
        String extName = fileName.substring(fileName.lastIndexOf(".") + 1, fileName.length());
        //检测异常文件名
        String evilname = null;
        for (int i = 0; i < fileList.size(); i++) {
            evilname = fileList.get(i);
            if (preName.contains(evilname)) {
                return false;
            }
        }
        //检查后缀是否合法
        if (!extList.contains(extName.toString())) {
            return false;
        }
        return true;
    }

    public static boolean isValidFileName(String fileName, String extsStr) {
        String filesStr = "\0|00|%00|;|.asp|.jsp|.aspx|.php|.asa|.cer";
        List<String> extList = asList(extsStr.split("\\|"));
        List<String> fileList = asList(filesStr.split("\\|"));
        String preName = fileName.substring(0, fileName.lastIndexOf("."));
        String extName = fileName.substring(fileName.lastIndexOf(".") + 1, fileName.length());
        //检测异常文件名
        String filename = null;
        for (int i = 0; i < fileList.size(); i++) {
            filename = fileList.get(i);
            if (preName.contains(filename)) {
                return false;
            }
        }
        //检查后缀是否合法
        if (!extList.contains(extName.toString())) {
            return false;
        }
        return true;
    }

    //防范文件上传漏洞
    public static List<File> SecurityFileUploads(HttpServletRequest request, int maxBytes, File tempDir, File finalDir, String exts, boolean reNameIsTrue) throws Exception {
        if (!tempDir.exists()) {
            tempDir.mkdirs();
        }
        List<File> newFiles = new ArrayList<File>();
        try {
            final HttpSession session = request.getSession(false);
            if (!ServletFileUpload.isMultipartContent(request)) {
                throw new Exception("Upload failed Not a multipart request");
            }

            // this factory will store ALL files in the temp directory,
            // regardless of size
            DiskFileItemFactory factory = new DiskFileItemFactory(0, tempDir);
            ServletFileUpload upload = new ServletFileUpload(factory);
            upload.setSizeMax(maxBytes);

            // Create a progress listener
            ProgressListener progressListener = new ProgressListener() {
                private long megaBytes = -1;
                private long progress = 0;

                public void update(long pBytesRead, long pContentLength, int pItems) {
                    if (pItems == 0)
                        return;
                    long mBytes = pBytesRead / 1000000;
                    if (megaBytes == mBytes)
                        return;
                    megaBytes = mBytes;
                    progress = (long) (((double) pBytesRead / (double) pContentLength) * 100);
                    if (session != null) {
                        session.setAttribute("progress", Long.toString(progress));
                    }
                    // logger.logSuccess(Logger.SECURITY, "   Item " + pItems + " (" + progress + "% of " + pContentLength + " bytes]");
                }
            };
            upload.setProgressListener(progressListener);

            List<FileItem> items = upload.parseRequest(request);
            for (FileItem item : items) {
                if (!item.isFormField() && item.getName() != null && !(item.getName().equals(""))) {
                    String[] fparts = item.getName().split("[\\/\\\\]");
                    String filename = fparts[fparts.length - 1];

                    if (!isValidFileName(filename) && !isValidFileName(filename, exts)) {
                        item.delete();
                        throw new Exception("Upload only simple filenames with the following extensions Upload failed isValidFileName check");
                    }
                    if (reNameIsTrue == true) {
                        String extName = filename.substring(filename.lastIndexOf(".") + 1, filename.length());
                        Long time = System.currentTimeMillis();
                        Date date = new Date(time);
                        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
                        filename = sdf.format(date) + "." + extName;
                    }
                    File f = new File(finalDir, filename);
                    if (f.exists()) {
                        String[] parts = filename.split("\\/.");
                        String extension = "";
                        if (parts.length > 1) {
                            extension = parts[parts.length - 1];
                        }
                        String filenm = filename.substring(0, filename.length() - extension.length());
                        f = File.createTempFile(filenm, "." + extension, finalDir);
                    }
                    item.write(f);
                    newFiles.add(f);
                    // delete temporary file
                    item.delete();
                    //logger.fatal(Logger.SECURITY_SUCCESS, "File successfully uploaded: " + f);
                    if (session != null) {
                        session.setAttribute("progress", Long.toString(0));
                    }
                }
            }
        } catch (Exception e) {
            throw new Exception("Upload failure Problem during upload:" + e.getMessage());
        }
        return Collections.synchronizedList(newFiles);
    }

    public static boolean SecurityUrlRedirect(String url, String whiteUrl) {
        url = getHost(url);
        if (!whiteUrl.startsWith("*")) {
            if (!url.equals(whiteUrl)) {
                return false;
            }
        } else {
            if (!url.endsWith(whiteUrl.substring(1, whiteUrl.length()))) {
                return false;
            }
        }
        return true;
    }

    //白名单方式,支持*.360.net|www.360.net两种格式。
    public static boolean SecuritySSRF(String url, String whiteUrl) {
        url = getHost(url);
        if (!whiteUrl.startsWith("*")) {
            if (!url.equals(whiteUrl)) {
                return false;
            }
        } else {
            if (!url.endsWith(whiteUrl.substring(1, whiteUrl.length()))) {
                return false;
            }
        }
        return true;
    }

    public static String getHost(String url) {
        //先判断字符串是否为空
        if (url == null || url.trim().equals("")) {
            return "";
        }
        //在判断url里面是否有特殊字符
        String evilStrs = "%0d|@|%40|%2e|%252e|%23|%00|\0";
        List<String> evilList = asList(evilStrs.toLowerCase().split("\\|"));
        for (String str : evilList) {
            if (url.contains(str)) {
                return "";
            }
        }
        String host = "";
        Pattern p = Pattern.compile("(?<=//|)((\\w)+\\.)+\\w+");
        Matcher matcher = p.matcher(url);
        if (matcher.find()) {
            host = matcher.group();
        }
        return host;
    }

    public static boolean SecurityXXE(String content) {
        String evilStrs = "SYSTEM|<!ENTITY|file:";
        List<String> evilList = asList(evilStrs.toLowerCase().split("\\|"));
        for (String str : evilList) {
            if (content.contains(str)) {
                return false;
            }
        }
        return true;
    }

    public static boolean hostHeaderInj(String host) {
        String whiteList = "b.360.cn|www.360.net";
        List<String> evilList = asList(whiteList.toLowerCase().split("\\|"));
        for (String str : evilList) {
            if (host.equals(str)) {
                return true;
            }
        }
        return false;
    }

    public static String SecurityRSHeaderInjection(String rsHeaderStr) {
        //在设置HTTP响应头的代码中，过滤回车换行（%0d%0a、%0D%0A)字符
        return rsHeaderStr.replaceAll("(?i)%0d|%0a", "").replaceAll("(?i)\\r|\\n", "");
    }

    public static void main(String[] args) throws Exception {
        String rs = SecurityUtil.SecurityXssScript("<scritp>alert(1)</script>","h");
        System.out.println(rs);
    }
}
