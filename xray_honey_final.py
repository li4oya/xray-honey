from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import re
import hashlib
import urllib.parse
import base64
import os
import datetime

f = open('level2_12.10_2.log', 'a+')
server_address = ("0.0.0.0", 9999)
dict_num = {}
dict_filename = {}

# noinspection PyUnreachableCode
class MyServer(BaseHTTPRequestHandler):
    def send_error(self, code: int, message: str  = ..., explain: str  = ...):
        now_time = datetime.datetime.now()
        if 'md5' in message:
            send = calc_md5(message.encode('utf8'))
            self.error_message_format = send
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))
            self.wfile.write(bytes(str(now_time), 'utf8'))

    def do_DELETE(self):
        f.write('\r\nDELETE ' + self.path + ' HTTP/1.1\r\n') # test_writelog
        f.write(str(self.headers)+'\r\n') # test_writelog
        if '/nacos/v1/auth/users?username=' in self.path:
            f.write('\r\nDELETE ' + self.path + ' HTTP/1.1\r\n')  # test_writelog
            f.write(str(self.headers) + '\r\n')  # test_writelog
            send = 'true'

    def do_PUT(self):
        f.write('\r\nPUT ' + self.path + ' HTTP/1.1\r\n') # test_writelog
        f.write(str(self.headers)+'\r\n') # test_writelog
        if '.jsp' in self.path:
            self.send_response(201)
            self.send_header("Content-type", "application/json")
            self.end_headers()
        elif '/fileserver/' in self.path:
            self.send_response(204)
            self.send_header("Content-type", "application/json")
            self.end_headers()
        elif '/SDK/webLanguage' in self.path:
            send = '<requestURL>/SDK/webLanguage</requestURL>'
            self.send_response(500)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

    # noinspection PyUnreachableCode
    def do_GET(self):
        now_time = datetime.datetime.now()
        code = 1
        send = '' # test_writelog
        f.write('\r\nGET ' + self.path + ' HTTP/1.1\r\n') # test_writelog
        f.write(str(self.headers)+'\r\n') # test_writelog
        # try:
        #     if re.match(r'/(\d+)\.php', self.path):
        #         try:
        #             num = re.match(r'/(\d+)\.php', self.path)
        #             a_fetch_1 = open('a_fetch', 'r')
        #             content = a_fetch_1.read()
        #             if num in content and '/index.php?a=fetch&content=' in content:
        #
        #         except:
        #             pass
        # except:
        #     pass
        try:
            num = re.findall(r'/(\d+)\.php', self.path)
            send = ''
            if num[0] in os.listdir('./'):
                md5 = hashlib.md5()
                md5.update(num[0].encode())
                md5_data = md5.hexdigest()
                send += md5_data
                try:
                    f_fetch_content_1 = open(str(num[0]), 'r')
                    send += f_fetch_content_1.read()
                    f_fetch_content_1.close()
                except:
                    pass
                try:
                    result = ''
                    result = dict_num[str(num[0])]
                    send += str(result)
                except:
                    pass
                self.send_response(200)
                code = 200
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                pass
        except:
            pass

        try:
            filename = re.findall(r'/(\w+)\.php', self.path)
            send = ''
            if filename[0] in os.listdir('./') or dict_filename[filename[0]] == '1':
                try:
                    result = ''
                    result = filename[0]
                    md5 = hashlib.md5()
                    md5.update(result.encode())
                    md5_data = md5.hexdigest()
                    send += md5_data
                    self.send_response(200)
                    code = 200
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(bytes(send, 'utf8'))
                except:
                    pass
        except:
            pass


        try:
            num = re.findall(r'/(\d+)\.jsp', self.path)
            send = 'verifyStr\r\ncommentStr'
            try:
                result = ''
                result = dict_num[str(num[0])]
                send = str(result)
                self.send_response(200)
                code = 200
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            except:
                pass
        except:
            pass


        try:
            if '/include/' in self.path and 'exportUser.php' not in self.path and 'makecvs.php' not in self.path:
                f_exportUser_1 = open('exportUser', 'r')
                send = f_exportUser_1.read()
                f_exportUser_1.close()
                self.send_response(200)
                code = 200
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
        except:
            pass

        if 'md5' in self.path and 'faq.php' not in self.path and '/tool/log/c.php' not in self.path and '/index.php?s=api/goods_detail&goods_id=1' not in self.path and '/manager/radius/server_ping.php' not in self.path and '/data/mysqli_error_trace.php' not in self.path and '/get_luser_by_sshport.php' not in self.path and '/include/makecvs.php' not in self.path:
            if 'md5%28' in self.path:
                path = urllib.parse.unquote(self.path)
                send = calc_md5(path.encode("utf8"))
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                data = self.path
                send = calc_md5(data.encode("utf8"))
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif 'md5' in str(self.headers) and '/user.php?act=collection_list' not in self.path:
            headers = str(self.headers)
            send = calc_md5(headers.encode('utf8'))
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/canal/config/1/1' in self.path:
            send = 'ncanal.aliyun.accessKey\r\nncanal.aliyun.secretKey'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        # elif '/api/v1/users/admin?fields=*,privileges/PrivilegeInfo/cluster_name,privileges/PrivilegeInfo/permission_name' in self.path and 'Basic YWRtaW46YWRtaW4=' in str(self.headers):
        elif '/api/v1/users/admin?fields=*,privileges/PrivilegeInfo/cluster_name,privileges/PrivilegeInfo/permission_name' in self.path:
            send = 'PrivilegeInfo\r\nAMBARI.ADMINISTRATOR'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/?unix:AAAAAAAAAA' in self.path:
            send = ''
            self.send_response(302)
            self.send_header("Content-type", "text/html")
            self.send_header("localtion", "http://www.baidu.com/search/error.html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/kylin/api/admin/config' in self.path:
            send = 'config\r\nkylin.metadata.url'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/nifi-api/flow/current-user' in self.path:
            send = '\"identity\":\"anonymous\",\"anonymous\":true'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/cluster/summary' in self.path:
            send = '{\"totalMem\":\r\n\"stormVersion\":'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/pma/' in self.path:
            send = 'information_schema\r\nphpMyAdmin\r\nserver_sql.php'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua' in self.path:
            send = 'INTERNAL_PASSWORD_ENABLED'
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/vpn/../vpns/cfg/smb.conf' in self.path:
            send = 'encrypt passwords\r\nname resolve order'
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/jsp/help-sb-download.jsp?sbFileName=' in self.path:
            send = etc_passwd()
            self.send_response(200)
            self.send_header("Content-type", "octet-stream")
            self.end_headers()
            self.wfile.write(bytes(send))

        elif '/CFIDE/administrator/enter.cfm?locale=' in self.path:
            send = 'rdspassword=\r\nencrypted='
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/spaces/viewdefaultdecorator.action?decoratorName' in self.path:
            send = 'confluence-init.properties\r\nView Default Decorator'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/s/afplsj/_/;/WEB-INF/web.xml' in self.path:
            send = '<display-name>Confluence</display-name>\r\ncom.atlassian.confluence.setup.ConfluenceAppConfig'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/v1/agent/self' in self.path:
            send = '\"DisableRemoteExec\": false\r\n\"EnableScriptChecks\": true'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/mailsms/s?func=ADMIN:appState&dumpConfig=/' in self.path:
            send = '<object name=\"cm_md_db\">'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/_config' in self.path:
            send = 'httpd_design_handlers\r\nexternal_manager\r\nreplicator_manager'
            self.send_response(401)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/include/downmix.inc.php' in self.path:
            send = 'Fatal error\r\ndownmix.inc.php\r\nCall to undefined function helper()'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/plus/download.php?open=1&link=' in self.path:
            send = ''
            location = ''
            try:
                result = re.findall(r'link=(\w+)', self.path)
                result = base64.b64decode(result[0] + '==')
                location = result.decode()
            except:
                pass
            self.send_response(302)
            self.send_header("location", location)
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/faq.php' in self.path:
            send = ''
            result = calc_md5(self.path.encode('utf8'))
            send = result
            send += '\r\nDiscuz! info</b>: MySQL Query Error'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/plugin.php?id=wechat:wechat&ac=wxregister' in self.path:
            send = ''
            self.send_response(302)
            self.send_header("set-cookie", "auth=")
            self.send_header("location", "wsq.discuz.com")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/config/getuser?index=0' in self.path:
            send = 'name=admin\r\npass='
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/info' == self.path:
            send = 'KernelVersion\r\nRegistryConfig\r\nDockerRootDir'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/druid/index.html' in self.path:
            send = 'Druid Stat Index\r\nDruidVersion\r\nDruidDrivers'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif 'Basic cm9vdDpyb290' in str(self.headers):
            send = '<title>Dubbo Admin</title>\r\n: root'', ''/logout''\r\n/sysinfo/versions'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/device.rsp?opt=user&cmd=list' in self.path:
            send = '\"uid\":\r\nplayback'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/iclock/ccccc/windows/win.ini' in self.path:
            send = 'for 16-bit app support'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml' in self.path:
            send = '<url-pattern>/weaver/'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/web.xml' in self.path:
            send = '<url-pattern>/weaver/'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/user.php?act=collection_list' in self.path:
            send = calc_md5(str(self.headers).encode('utf8'))[1:32]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/authenticationserverservlet' in self.path:
            send = '<username>admin</username>\r\n<password>admin</password>'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/owa/auth/x.js' in self.path:
            send = ''
            self.send_response(200)
            self.send_header("X-CalculatedBETarget", "localhost")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php?s=Admin-Data-down&id=' in self.path:
            send = '<?php\r\ndb_name\r\ndb_pwd\r\ndb_host'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        # elif '/index.php?s=Admin-Data-down&id=../../Conf/config.php' in self.path:
        #     send = '<?php\r\ndb_name\r\ndb_pwd\r\ndb_host'
        #     self.send_response(200)
        #     self.send_header("Content-type", "text/html")
        #     self.end_headers()
        #     self.wfile.write(bytes(send, 'utf8'))

        elif '/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml' in self.path:
            send = '<rootManagerName>\r\n<rootManagerPassword>'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/remote/fgt_lang?lang=' in self.path:
            send = 'fgt_lang\r\nForticlient'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/theme/META-INF/%c0%ae%c0%ae/META-INF/MANIFEST.MF' in self.path:
            send = 'Ant-Version:\r\nManifest-Version:'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/go/add-on/business-continuity/api/plugin?folderName=&pluginName=' in self.path:
            if '/etc/passwd' in self.path:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send))
            else:
                send = 'for 16-bit app support\r\n[extensions]'
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin' in self.path:
            send = '错误的id\r\n审计管理员\r\nadmin'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/GetSrc' in self.path:
            send = 'H5_AUTO\r\nstrUser\r\nstrPasswd'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/ws/v1/cluster/info' in self.path:
            send = 'resourceManagerVersionBuiltOn\r\nhadoopVersion'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/register/toDownload.do?fileName=' in self.path:
            if '/etc/passwd' in self.path:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send))
            elif '/windows/win.ini' in self.path:
                send = "for 16-bit app support\r\n[extensions]"
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/system/deviceInfo?auth=YWRtaW46MTEK' in self.path:
            send = '<firmwareVersion>'
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/him/api/rest/V1.0/system/log/list?filePath=../' in self.path:
            send = '\"absolutePath\":\"/var/logs/'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/admin-console/index.seam' in self.path:
            send = ''
            result = ''
            try:
                result = re.findall(r'fpwned%3d%23%7b(\d+\*\d+)%7d', self.path)
                result = eval(result[0])
                send = result(str(result))
            except:
                pass

            self.send_response(302)
            self.send_header("location", result)
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/jmx-console/' in self.path:
            send = 'jboss.management.local\r\njboss.web'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/Images/Remote?imageUrl=' in self.path:
            send = 'This domain is for use in illustrative examples in documents. You may use this domain in literature without prior coordination or asking for permission.'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/Audio/1/hls/' in self.path:
            send = 'for 16-bit app support'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile' in self.path:
            send = ''
            try:
                result = re.findall(r'module=%27(\w+)%27', self.path)
                send = 'package#' + result[0]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/%2e/WEB-INF/web.xml' in self.path:
            send = '</web-app>'
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/s/anything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml' in self.path:
            send = '<groupId>com.atlassian.jira</groupId>'
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/rest/api/latest/groupuserpicker?query=' in self.path:
            send = 'total\r\ngroups\r\nheader\r\nusers'
            self.send_response(200)
            self.send_header("X-AREQUESTID", "Asria")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/secure/ViewUserHover.jspa?username=' in self.path:
            send = ''
            try:
                result = re.findall(r'username=(\w+)', self.path)
                send = '/secure/ViewProfile.jspa?name=' + result[0] + '\r\ncom.atlassian.jira'
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/terminals/3' in self.path:
            send = 'terminals/websocket\r\nPassword:'
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=' in self.path:
            send = '\"statusCode\":500\r\n\"message\":\"An internal server error occurred\"'
            self.send_response(200)
            self.send_header("kbn-name", "kibana")
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/app/kibana' in self.path:
            send = '.kibanaWelcomeView'
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/appmonitor/protected/selector/server_file/files?' in self.path:
            if 'folder=C://&suffix=' in self.path:
                send = '{\"name\":\"Windows\",\"path\":\"C:\\\\Windows\",\"folder\":true}'
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'folder=/&suffix=' in self.path:
                send = '{\"name\":\"root\",\"path\":\"/root\",\"folder\":true}'
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/htmltopdf/downfile.php?filename=/Windows/win.ini' in self.path:
            send = 'for 16-bit app support'
            self.send_response(200)
            self.send_header("Content-type", "application/zip")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/nodes' in self.path:
            send = '\"kubeletVersion\": \"v\r\n\"containerRuntimeVersion\"'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/conf/config.properties' in self.path:
            send = 'config.admin.username\r\nconfig.admin.password'
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/storage/logs/laravel.log' in self.path:
            send = 'vendor\\laravel\\framework\r\nstacktrace'
            self.send_response(200)
            self.send_header("Content-type", "application/plain")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/admin/?n=product&c=product_admin&a=dopara&app_type=shop' in self.path:
            send = ''
            try:
                result = re.findall(r"(\d+\*\d+)", self.path)
                send = str(eval(result[0]))
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/admin/?n=language&c=language_general&a=doSearchParameter&editor=cn&word=search' in self.path:
            send = ''
            try:
                result = re.findall(r"(\d+\*\d+)", self.path)
                send = str(eval(result[0]))
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/include/thumb.php?dir=http/.....///.....///config/config_db.php' in self.path:
            send = 'con_db_pass\r\ncon_db_host\r\ncon_db_name'
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/service/local/authentication/login' in self.path:
            send = 'loggedIn'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/../../windows/win.ini' in self.path:
            send = '[extensions]'
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/ui_base/js/..%2f..%2f..%2f..%2fsettings.js' in self.path:
            send = 'Node-RED web server is listening\r\nusername\r\npassword'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/admin/cert_download.php?file=pqpqpqpq.txt&certfile=cert_download.php' in self.path:
            send = '$certfile\r\napplication/pdf'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif 'webapi/v1/system/accountmanage/account' in self.path:
            send = 'account\r\npassword'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/css_parser.php?css=css_parser.php' in self.path:
            send = "$_GET['css']"
            self.send_response(200)
            self.send_header("Content-type", "text/css")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/base_import/static/c:/windows/win.ini' in self.path:
            send = 'for 16-bit app support'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/getFavicon?host=' in self.path:
            send = 'image/x-icon\r\n'
            try:
                result = re.findall(r'host=(.*)/', self.path)
                send += result[0]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/data/pbootcms.db' in self.path:
            send = 'PbootCMS'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/pentaho/api/userrolelist/systemRoles?require-cfg.js' in self.path:
            send = '<roles>Anonymous</roles></roleList>'
            self.send_response(200)
            self.send_header("Set-Cookie", "JSESSIONID=")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/new/new' in self.path:
            send = ''
            self.send_response(302)
            self.send_header("location", "https:/baidu.com?")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm' in self.path:
            send = '错误的id\r\n审计管理员\r\n事件审计'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/tests/generate.php' in self.path:
            send = "Fatal error: Class ''PHPUnit_Framework_TestCase'' not found in \r\n/application/third_party/CIUnit/libraries/CIUnitTestCase.php on line"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/%20../web-inf/' in self.path:
            send = "/ ../web-inf/\r\nDirectory of /"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=../../../../../index.jsp' in self.path:
            send = "<%@ page session=\"false\" import=\"com.caucho.vfs.*, com.caucho.server.webapp.*\" %>"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/resin-doc/viewfile/?file=index.jsp' in self.path:
            send = "%@ page session=\"false\" import=\"com.caucho.vfs.*, com.caucho.server.webapp.*\" %"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/login.php' == self.path:
            send = "<title>RG-UAC登录页面</title>\r\n\"password\":\"e10adc3949ba59abbe56e057f20f883e\""
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/tool/log/c.php?strip_slashes=md5&host=' in self.path:
            send = ''
            try:
                result = re.findall(r"strip_slashes=md5&host=(\w+)", self.path)
                md5 = hashlib.md5()
                md5.update(result[0].encode())
                md5_data = md5.hexdigest()
                send = md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/ui/login.php?user=admin' in self.path:
            send = "/download/edr_installer_\r\n"
            self.send_response(302)
            self.send_header("Set-Cookie", "admin=admin")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/tool/log/c.php?strip_slashes=printf&host=' in self.path:
            send = ''
            try:
                result = re.findall(r"host=(\w+)%25%25(\w+)", self.path)
                send = result[0][0] + "%" + result[0][1]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0' in self.path:
            send = "[Content_Types].xml\r\nExcel.Sheet"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/seeyon/webmail.do?method=doDownloadAtt&filename=index.jsp&filePath=../conf/datasourceCtp.properties' in self.path:
            send = "application/x-msdownload\r\nctpDataSource.password"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/yyoa/ext/https/getSessionList.jsp?cmd=getAll' in self.path:
            send = "<SessionList>\r\n<Session>\r\n<usrID>"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml' in self.path:
            send = "<servlet-name>NCInvokerServlet</servlet-name>"
            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php?s=api/goods_detail&goods_id=1' in self.path:
            send = calc_md5(self.path.encode('utf8'))
            self.send_response(404)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/public/index.php?s=/index/qrcode/download/url/' in self.path:
            if 'L1dpbmRvd3Mvd2luLmluaQ=' in self.path:
                send = 'extensions\r\nfor 16-bit app support'
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'L2V0Yy9wYXNzd2Q=' in self.path:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send))

        elif '/web.config.i18n.ashx?l=en-US&v=' in self.path:
            send = 'SolarWinds.Orion.Core.Common\r\n/Orion/NetPerfMon/TemplateSiblingIconUrl'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/settings/values' in self.path:
            send = 'sonaranalyzer-cs.nuget.packageVersion\r\nsonar.core.id'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/v1/submissions' in self.path:
            send = 'Missing an action\r\nserverSparkVersion'
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/a/b/' in self.path and 'etc/resolv.conf' in self.path:
            send = "This file is managed by man:systemd-resolved(8). Do not edit."
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/env' == self.path or '/actuator/env' == self.path:
            send = "java.version\r\nos.arch"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b2x322s2t3c1a342w34' in self.path:
            send = "PD9waH\r\nVGhpbmtBZG1pbg"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/?a=display&templateFile=README.md' in self.path:
            send = "ThinkCMF\r\n## README"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=' in self.path:
            send = ""
            try:
                result = re.findall(r'vars\[1]\[]=(\w+)', self.path)
                send += result[0]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/dbstat/gettablessize' in self.path:
            send = "schema_name\r\ntable_name"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/general/calendar/arrange/get_cal_list.php?starttime=1548058874&endtime=33165447106&view=agendaDay' in self.path:
            send = "creator\r\noriginalTitle"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php/Home/uploadify/fileList?type=.+&path=../' in self.path:
            send = "\"state\":\"SUCCESS\"\r\ntotal"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/ueditor/net/controller.ashx?action=catchimage&encode=utf-8' in self.path:
            send = "没有指定抓取源"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/eam/vib?id=C:\ProgramData\VMware\\vCenterServer\cfg\\vmware-vpx\\vcdb.properties' in self.path:
            send = "org.postgresql.Driver"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/console/images/%252E./console.portal' in self.path:
            send = "/console/console.portal"
            self.send_response(302)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/uddiexplorer/SearchPublicRegistries.jsp' in self.path:
            send = "&#39;127.1.1.1&#39;, port: &#39;700&#39;\r\nSocket Closed"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/wp-admin/admin.php?page=download_report&report=users&status=all' in self.path:
            send = "Name,Email,Status,Created"
            self.send_response(200)
            self.send_header("Content-Disposition", "filename=abcd.csv")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/wp-content/plugins/adaptive-images/adaptive-images-script.php?adaptive-images-settings[source_file]=../../../wp-config.php' in self.path:
            send = "DB_NAME\r\nDB_USER\r\nDB_PASSWORD\r\nDB_HOST"
            self.send_response(200)
            self.send_header("Content-Disposition", "filename=abcd.csv")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif 'MD5' in self.path:
            send = 'sql_error:MySQL Query Error\r\n'
            if '/user/City_ajax.aspx' in self.path:
                try:
                    result = re.findall(r"'MD5','(\d+)'", self.path)
                    md5 = hashlib.md5()
                    md5.update(result[0].encode())
                    md5_data = md5.hexdigest()
                    send += md5_data
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                try:
                    result = re.findall(r'MD5\((\d+)\)', self.path)
                    md5 = hashlib.md5()
                    md5.update(result[0].encode())
                    md5_data = md5.hexdigest()
                    send += md5_data
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/install/' == self.path:
            send = "/view/js/xiuno.js\r\nChoose Language (选择语言)"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/backup/auto.php?password=' in self.path:
            send = ''
            try:
                result = re.findall(r'password=(\w+)', self.path)
                send += result[0] + "\r\ndisplay_errors"
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/zabbix.php?action=dashboard.view&dashboardid=1' in self.path:
            send = "<a class=\"top-nav-zbbshare\" target=\"_blank\" title=\"Zabbix Share\" href=\"https://share.zabbix.com/\">Share</a>\r\n<title>Dashboard</title>"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/_next/static/../server/pages-manifest.json' in self.path:
            send = "/_app\": \"abcd_app\\.js"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/webapi/v1/system/accountmanage/account' in self.path:
            send = "account\r\npassword"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/manager/radius/server_ping.php' in self.path:
            send = 'parent.doTestResult\r\n'
            try:
                result = re.findall(r'md5\((\w+)\)', self.path)
                md5 = hashlib.md5()
                md5.update(result[0].encode())
                md5_data = md5.hexdigest()
                send += md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/GetDevice' in self.path:
            send = 'H5_DEV\r\nstrUser\r\nstrPasswd'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/data/cache_template/rss.tpl.php?' in self.path:
            send = ''
            try:
                result = re.findall(r'rss\.tpl\.php\?(\d+)=(\d+)', self.path)
                md5 = hashlib.md5()
                md5.update(result[0][1].encode())
                md5_data = md5.hexdigest()
                send += md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/comment/api/index.php?gid=1&page=2&rlist[]=*hex/@eval' in self.path:
            send = ''
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/data/mysqli_error_trace.php' in self.path:
            send = ''
            try:
                result = re.findall(r'md5\("(\w+)"\)', self.path)
                md5 = hashlib.md5()
                md5.update(result[0].encode())
                md5_data = md5.hexdigest()
                send += md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/whoami' in self.path:
            if 'Basic Z3Vlc3Q6Z3Vlc3Q=' in str(self.headers):
                send = '\"name\":\"guest\"'
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                send = ''
                self.send_response(401)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/Pages/login.htm' in self.path:
            send = '<title>NVMS-1000</title>'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/s/opentsdb_header.jpg' in self.path:
            send = '\xff\xd8\xff\xe1'
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/ping' == self.path:
            send = ''
            self.send_response(204)
            self.send_header("Content-type", "text/plain")
            self.send_header("x-influxdb-version", "1.02")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/plugins/weathermap/' in self.path:
            if 'editor.php?' in self.path:
                send = ''
                try:
                    result = re.findall(r"map_title=(\w+)&", self.path)
                    f1 = open('test', 'w')
                    f1.write(result[0])
                    f1.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            if 'configs/' in self.path:
                send = ''
                try:
                    f2 = open('test', 'r')
                    send = f2.read()
                    f2.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/run' == self.path:
            send = 'wheel_async\r\nrunner_async'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/v2/' == self.path:
            send = ''
            self.send_response(200)
            self.send_header("docker-distribution-api-version", "registry/2.0")
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/php/' in self.path:
            if '/php/setup.php?step=' in self.path:
                send = ''
                try:
                    f_setup = open('setup', 'w')
                    result = re.findall(r'PDF2SWF_PATH=printf%20(\w+)%25%25(\w+)', self.path)
                    f_setup.write(result[0][0] + '%' + result[0][1])
                    f_setup.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'pdf2swf' in self.path:
                send = ''
                try:
                    f_setup_1 = open('setup', 'r')
                    send = f_setup_1.read()
                    f_setup_1.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/jkstatus;' in self.path:
            if 'cmd=dump' in self.path:
                send = 'ServerRoot='
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                send = 'JK Status Manager\r\nListing Load Balancing Worker'
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/objects/xvlb.txt' == self.path:
            send = ''
            try:
                f_getImage_1 = open('getImage', 'r')
                content = f_getImage_1.read()
                send += content
                f_getImage_1.close()
            except:
                pass

            try:
                f_getSpiritsFromVideo_1 = open('getSpiritsFromVideo', 'r')
                content = f_getSpiritsFromVideo_1.read()
                send += content
                f_getSpiritsFromVideo_1.close()
            except:
                pass

            try:
                f_getImageMP4_1 = open('getImageMP4', 'r')
                content = f_getImageMP4_1.read()
                send += content
                f_getImageMP4_1.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/objects/' in self.path:
            if 'getImage.php' in self.path:
                send = ''
                try:
                    path = urllib.parse.unquote(self.path)
                    result = re.findall(r'base64Url=(\w+)', path)
                    result = base64.b64decode(result[0] + '=')
                    content = re.findall(r'echo (\w+)', result.decode('utf8'))
                    f_getImage = open('getImage', 'w')
                    f_getImage.write(content[0])
                    f_getImage.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'getSpiritsFromVideo.php' in self.path:
                send = ''
                try:
                    path = urllib.parse.unquote(self.path)
                    result = re.findall(r'base64Url=(\w+)', path)
                    result = base64.b64decode(result[0] + '=')
                    content = re.findall(r'echo (\w+)', result.decode('utf8'))
                    f_getSpiritsFromVideo = open('getSpiritsFromVideo', 'w')
                    f_getSpiritsFromVideo.write(content[0])
                    f_getSpiritsFromVideo.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'getImageMP4.php' in self.path:
                send = ''
                try:
                    path = urllib.parse.unquote(self.path)
                    result = re.findall(r'base64Url=(\w+)', path)
                    result = base64.b64decode(result[0] + '=')
                    content = re.findall(r'echo (\w+)', result.decode('utf8'))
                    f_getImageMP4 = open('getImageMP4', 'w')
                    f_getImageMP4.write(content[0])
                    f_getImageMP4.close()
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/page/exportImport/fileTransfer/' in self.path:
            send = ''
            try:
                f_page_exportImport_1 = open('page_exportImport', 'r')
                send += f_page_exportImport_1.read()
                f_page_exportImport_1.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/debug/pprof/' == self.path:
            send = 'Types of profiles available\r\nProfile Descriptions'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php?a=fetch&content=' in self.path:
            send = 'true'
            try:
                result_file = re.findall(r'file_put_contents\(%22(\d+)', self.path)
                result = re.findall(r'echo\+(\d+)%3B%22', self.path)
                dict_num[str(result_file[0])] = str(result[0])
                f_fetch_conent = open(result_file[0], 'w')
                f_fetch_conent.write(str(result[0]))
                f_fetch_conent.close()
                # a_fetch = open('a_fetch', 'w')
                # a_fetch.writelines(str(result_file[0]))
                # a_fetch.writelines(str(result[0]))
                # a_fetch.writelines('/index.php?a=fetch&content=')
                # a_fetch.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/_/;/WEB-INF/web.xml' in self.path:
            send = '<display-name>Confluence</display-name>\r\ncom.atlassian.confluence.setup.ConfluenceAppConfig'
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/include/thumb.php?dir=http\..\\admin\login\login_check.php' in self.path:
            send = '<?php\r\nlogin_met_cookie($metinfo_admin_name);'
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/users/connection-token/' in self.path:
            send = 'not_authenticated'
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/manager/index.php' == self.path:
            send = ""
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/eam/vib?id=C:\ProgramData\VMware\\vCenterServer\cfg\\vmware-vpx\\vcdb.properties' in self.path:
            send = "org.postgresql.Driver"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/includes/mysql2i/mysql2i.func.php' in self.path:
            send = "mysql2i.func.php on line 10\r\nFatal error: Cannot redeclare mysql_affected_rows() in"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/systemController/showOrDownByurl.do?down=&dbPath=' in self.path:
            if '/etc/passwd' in self.path:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send))
            elif '/Windows/win.ini' in self.path:
                send = "for 16-bit app support"
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/guest_auth/' in self.path:
            send = ''
            try:
                f_guestIsUp_1 = open('guestIsUp', 'r')
                send += f_guestIsUp_1.read()
                f_guestIsUp_1.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/common/download/resource?resource=' in self.path:
            if '/etc/passwd' in self.path:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send))
            elif '/Windows/win.ini' in self.path:
                send = "for 16-bit app support"
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/seeyon/thirdpartyController.do.css/..;/ajax.do' in self.path:
            send = "java.lang.NullPointerException:null"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/ui/vropspluginui/rest/services/' in self.path:
            if 'uploadova' in self.path:
                send = "Method Not Allowed"
                self.send_response(405)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'getstatus' in self.path:
                send = "States\r\nInstall Progress"
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/index.htm?PAGE=web' in self.path:
            send = "www.ifw8.cn"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/admin/' == self.path:
            if 'Basic YWRtaW46YWRtaW4=' in str(self.headers):
                send = "Welcome to the Apache ActiveMQ Console of\r\n<h2>Broker</h2>"
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                send = "<title>Airflow - DAGs</title>\r\n<h2>DAGs</h2>"
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
                # send = ""
                # self.send_response(401)
                # self.send_header("Content-type", "text/xml")
                # self.end_headers()
                # self.wfile.write(bytes(send, 'utf8'))

        elif '/include/makecvs.php' in self.path:
            send = "Service,DateTime"
            try:
                r1 = re.findall(r'md5\((\w+)\)', self.path)
                md5 = hashlib.md5()
                md5.update(r1[0].encode())
                md5_data = md5.hexdigest()
                f_makecvs = open(r1[0], 'w')
                f_makecvs.write(md5_data)
                f_makecvs.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/csv")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/login.html' == self.path:
            send = "<title>安网科技-智能路由系统</title>"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/include/exportUser.php' in self.path:
            send = ''
            try:
                path = urllib.parse.unquote(self.path)
                result = re.findall(r'opt=\(expr (\d+ \+  \d+)\)', path)
                result = eval(result[0])
                f_exportUser = open('exportUser', 'w')
                f_exportUser.write(str(result))
                f_exportUser.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/page/login/login.html' == self.path:
            send = "var ModelName=\"DSL-2888A\";"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/get_luser_by_sshport.php' in self.path:
            send = ''
            try:
                result = re.findall(r'md5\((\w+)\)', self.path)
                dict_filename[result[0]] = '1'
                f_sshport = open(result[0], 'w')
                f_sshport.write('1')
                f_sshport.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/secure/QueryComponent!Default.jspa' in self.path:
            send = "com.atlassian.jira"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/plus/carbuyaction.php?dopost=return&code=../../' in self.path:
            if 'cod' in str(self.headers):
                send = "Cod::respond()"
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'alipay' in str(self.headers):
                send = ""
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))


        elif '/action/usermanager.htm' in self.path:
            send = '\"pwd\":\"e10adc3949ba59abbe56e057f20f883e\"'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/debug/pprof/goroutine?debug=1' in self.path:
            send = "goroutine profile: total"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/cgi-bin/execute_cmd.cgi?timestamp=' in self.path:
            send = "uid=0(admin) gid=0(admin)"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/addons/phpmailer/phpmailer.php' in self.path:
            send = "phpmailer.php on line 10\r\nFatal error: Call to a menber function add_event_listener() on a non-object in"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/v2/_catalog' in self.path:
            send = "repositories"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/nacos/v1/auth/users?pageNo=1&pageSize=' in self.path:
            send = ""
            try:
                f_nacos_1 = open('nacos', 'r')
                send += f_nacos_1.read()
                f_nacos_1.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/query?q=show%20users' in self.path:
            send = "columns\r\nuser"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/seeyon/personalBind.do.jpg/..;/ajax.do?method=ajaxAction&managerName=mMOneProfileManager&managerMethod=getOAProfile' in self.path:
            send = "MMOneProfile\r\nproductTags\r\nserverIdentifier\r\n"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/data/plugins_listing' in self.path:
            send = "profile\r\ndistributions"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/config/user.xml' in self.path:
            send = "<user name=\"\r\n password=\""
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/user/zs' in self.path:
            send = ''
            try:
                f_zs_1 = open('zs_num', 'r')
                send += f_zs_1.read()
                f_zs_1.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/_cat' == self.path:
            send = "/_cat/master"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/_async/favicon.ico' in self.path:
            send = "Vulnerable"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/status' == self.path:
            send = "kong_db_cache_miss"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))













        elif '/../../../../../../../../../../Windows/win.ini' in self.path:
            send = "for 16-bit app support"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php' == self.path:
            send = ''
            try:
                result = re.findall(r'Accept-Charset: (\w+)', str(self.headers))
                result = base64.b64decode(result[0] + '==')
                result = re.findall(r"md5\('(\w+)'\)", result.decode('utf8'))
                md5 = hashlib.md5()
                md5.update(result[0].encode())
                md5_data = md5.hexdigest()
                send += md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/admin/' in self.path:
            if 'a=Factory()' in self.path:
                send = ''
                try:
                    result = re.findall(r'print\((\d+)%2b(\d+)\);', self.path)
                    result = int(result[0][0]) + int(result[0][1])
                    send = str(result)
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))
            else:
                send = 'Unauthorized\r\n<title>Airflow - DAGs</title>\r\n<h2>DAGs</h2>'
                self.send_response(401)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif 'passwd' in self.path:
            if '/webui/?g=sys_dia_data_down&file_name=' in self.path:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("set-cookie", "USGSESSID=")
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(send))
            else:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send))

        elif '*' in self.path or '%2b' in self.path or '+' in self.path or '-' in self.path or '*' in str(
                self.headers) or '%2b' in str(self.headers) or '+' in str(self.headers) or '-' in str(self.headers):
            if code == 200:
                pass
            else:
                path = urllib.parse.unquote(self.path)
                headers = str(self.headers)
                data = path + headers
                send = ''
                try:
                    result = re.findall(r"(\d+ ?([+,-]|\*) ?\d+)", data)
                    if result != []:
                        send = eval(result[0][0])
                    try:
                        headers_result = re.findall(r"(\d+\*'\d+')", data)
                        send = eval(headers_result[0])
                    except:
                        pass
                except:
                    pass
                # try:
                #     path_result_1 = re.findall(r"(\d+\*\d+)", path)
                #     if path_result_1 != []:
                #         send = eval(path_result_1[0])
                # except:
                #     pass
                # try:
                #     headers_result = re.findall(r"(\d+ ([+,-]|\*|) \d+)", headers)
                #     if headers_result != []:
                #         send = eval(headers_result[0][0])
                # except:
                #     pass
                # try:
                #     headers_result_1 = re.findall(r"(\d+\*'\d+)", headers)
                #     if headers_result_1 != []:
                #         send = eval(headers_result_1[0][0])
                # except:
                #     pass

                if '/' == self.path:
                    if 'Basic Z3Vlc3Q6Z3Vlc3Q=' in str(self.headers):
                        send = '<title>Dubbo Admin</title>\r\n: guest'', ''/logout''\r\n/sysinfo/versions'
                        self.send_response(200)
                        self.send_header("Content-type", "text/plain")
                        self.end_headers()
                        self.wfile.write(bytes(send, 'utf8'))
                    elif 'Basic cm9vdDpyb290' in str(self.headers):
                        send = '<title>Dubbo Admin</title>\r\n: root'', ''/logout''\r\n/sysinfo/versions'
                        self.send_response(200)
                        self.send_header("Content-type", "text/plain")
                        self.end_headers()
                        self.wfile.write(bytes(send, 'utf8'))
                    elif 'PHPSESSID=' in str(self.headers):
                        send = ''
                        self.send_response(200)
                        self.send_header("Content-type", "text/plain")
                        try:
                            result = re.findall(r'public/(\w+)\.php', str(self.headers))
                            set_cookie = result[0]
                            self.send_header("set-cookie", set_cookie)
                        except:
                            pass
                        self.end_headers()
                        self.wfile.write(bytes(send, 'utf8'))
                    else:
                        send = 'Kafka Manager</a>\r\n<title>Kafka Manager</title>\r\nAdd Cluster'
                        send += '\r\n<title>Spark\r\n<strong>URL:</strong> spark:'
                        send += '\r\nYou Know, for Search'
                        send += '\r\nGateOne.init\r\nhref=\"/static/gateone.css\"'
                        send += '\r\ngitlist'
                        send += '\r\nHarbor'
                        send += '\r\n<TITLE>流媒体管理服务器</TITLE>\r\n海康威视'
                        send += '\r\ndocument.title = LOGIN_BTN_LOGIN'
                        send += '\r\n<input\\stype=\"hidden\"\\sname=\"(<token>)\"'
                        send += '\r\nkong_env'
                        send += '\r\nThe TensorFlow Authors. All Rights Reserved.'
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.send_header("token", "880fed4ca2aabd20ae9a5dd774711de2")
                        self.end_headers()
                        self.wfile.write(bytes(send, 'utf8'))
                else:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(bytes(str(send), 'utf8'))  # 计算出负数直接转byte报错，要转成字符串，然后utf8
            # if 'print' in self.path and 'md5' not in self.path:
            #
            #     send = print_req(self.path)

        else:
            if code == 200:
                pass
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("yes", "utf-8"))
            f.write("\r\nresponse:yes") # test_writelog
        self.wfile.write(bytes(str(now_time), 'utf8'))
        f.write("\r\nresponse:"+str(send)) # test_writelog

    def do_POST(self):
        now_time = datetime.datetime.now()
        send = '' # test_writelog
        f.write('\r\nPOST ' + self.path + ' HTTP/1.1\r\n') # test_writelog
        f.write(str(self.headers)) # test_writelog
        req_datas = self.rfile.read(int(self.headers['content-length']))  # 括号里面的内容是读多少，否则在读的时候不会停
        f.write(req_datas.decode('utf8')+'\r\n') # test_writelog
        if 'md5'.encode('utf8') in req_datas:
            if '/?q=node&destination=node' in self.path:
                send = calc_md5(req_datas)
                self.send_response(500)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif '/index.php?option=com_zhbaidumap&no_html=1&format=raw&task=getPlacemarkDetails' in self.path:
                send = calc_md5(req_datas)
                send += 'dataexists'
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif '/ajax/render/widget_tabbedcontainer_tab_panel' in self.path:
                send = calc_md5(req_datas)
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif '/' == self.path:
                send = calc_md5(req_datas)
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                send = calc_md5(req_datas)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/webtools/control/xmlrpc' in self.path:
            if '/etc/passwd'.encode('utf8') in req_datas:
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send))
            else:
                send = 'methodResponse\r\nNo such service ['
                try:
                    result = re.findall(r'<methodName>(\d+)</methodName>', req_datas.decode())
                    send += result[0]
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/cu.html' in self.path:
            send = 'yes'
            self.send_response(302)
            self.send_header("location", "/menu.gch")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/menu/stapp' in self.path:
            r1 = ''
            try:
                result = re.findall(r'alert\(%7B%7B(\w+)%7D%7D\)', req_datas.decode('utf8'))
                r1 = result[0]
            except:
                pass
            send = '<script>alert('+r1+');</script>\r\ncitrix'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1' in self.path:
            send = 'login'
            self.send_response(406)
            self.send_header("Set-Cookie", "SESSID=AIKkIsjHDxLvmsAFNXAYqNsNILfzlxbs")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/rest/tinymce/1/macro/preview' in self.path:
            send = '<param-name>contextConfigLocation</param-name>'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/pages/createpage-entervariables.action?SpaceKey=x' in self.path:
            send = ''
            try:
                result = re.findall(r'%2b%7b(\d+)%2B(\d+)%7d%2b', req_datas.decode())
                send = int(result[0][0]) + int(result[0][1])
            except:
                pass

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/RPC2_Login' in self.path:
            send = '{\"id\":1,\"params\":{\"keepAliveInterval\":60},\"result\":true,\"session\":\"'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/login.cgi' in self.path:
            send = 'window.open(\'index.htm?_'
            self.send_response(200)
            self.send_header("set-cookie", "ac_userid=admin,ac_passwd=")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/hedwig.cgi' in self.path:
            send = '</usrid>\r\n</password>\r\n<result>OK</result>'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/apply_sec.cgi' in self.path:
            send = '</usrid>\r\n</password>\r\n<result>OK</result>'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/getcfg.php' in self.path:
            if 'SERVICES=DEVICE.ACCOUNT%0aAUTHORIZED_GROUP=1'.encode('utf8') in req_datas:
                send = '<name>Admin</name>\r\n</usrid>\r\n</password>'
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))
            elif 'SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a'.encode('utf8') in req_datas:
                send = '<name>\r\n<password>'
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))

        elif '/cgi-bin/mainfunction.cgi' in self.path:
            send = 'uid\r\ngid'.encode('utf8')
            send += etc_passwd()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send))

        elif '/node/?_format=hal_json' in self.path:
            send = ''.encode('utf8')
            try:
                result = re.findall(r'(\w+)%%(\w+)', req_datas.decode('utf8'))
                send = result[0][0] + "%" + result[0][1]
            except:
                pass

            self.send_response(403)
            self.send_header("Content-type", "hal+json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/autodiscover/autodiscover.json' in self.path:
            send = '<script>alert(1)'
            self.send_response(500)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp' in self.path:
            send = 'BIG-IP release'
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/graphql' in self.path:
            send = '{\"data\":{\"users\":{\"edges\":[{\"node\":{\"username\":\"\r\n\",\"email\":\"12345678@qq.com\"'
            self.send_response(200)
            self.send_header("x-runtime", "12:12:12")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v4/ci/lint' in self.path:
            send = '{\"status\":\"invalid\",\"errors\":\"does not have valid YAML syntax\"'
            self.send_response(200)
            self.send_header("Content-type", "json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/login' in self.path and '{"user":"admin","password":"admin"}'.encode('utf8') in req_datas:
            send = '\"message\":\"Logged in\"'
            self.send_response(200)
            self.send_header("Content-type", "json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/imc/javax.faces.resource/dynamiccontent.properties.xhtml' in self.path:
            send = ''
            try:
                result = re.findall(r'cmd=echo%20(\w+)\$\{(\w+)}(\w+)\^(\w+)', req_datas.decode('utf8'))
                send = result[0][0] + result[0][2] + '^' + result[0][3]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/login' in self.path and 'expr'.encode('utf8') in req_datas:
            send = ''
            try:
                req_datas = urllib.parse.unquote(req_datas.decode('utf8'))
                result = re.findall(r"(\d+ ([+,-]|\*|) \d+)", req_datas)
                send = eval(result[0][0])
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "json")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/c6/Jhsoft.Web.login/AjaxForLogin.aspx' in self.path:
            send = '\xcf\xb5\xcd\xb3\xb9\xdc\xc0\xed\xd4\xb1\x7c\r\n\xc4\xfa\xba\xc3\x7c\x7c\x7c'
            self.send_response(200)
            self.send_header("Set-Cookie", "SessionIDAdmin=")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/inter/ajax.php?cmd=get_user_login_cmd' in self.path:
            send = 'ADMIN\r\nuserSession'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/sys/ui/extend/varkind/custom.jsp' in self.path:
            if '/windows/win.ini' in req_datas.decode('utf8'):
                send = 'for 16-bit app support\r\n'.encode('utf8')
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send))
            elif '/etc/passwd' in req_datas.decode('utf8'):
                send = etc_passwd()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send))

        elif '/_ignition/execute-solution' in self.path:
            send = ''
            try:
                result = re.findall(r'"viewFile": "(\w+)"', req_datas.decode())
                send = 'file_get_contents(' + result[0] + ')' + '\r\nfailed to open stream'
            except:
                pass
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/extend/Qcloud/Sms/Sms.php' in self.path:
            send = '扫描后门\r\n反弹端口\r\n文件管理'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/minio/webrpc' in self.path:
            send = 'uiVersion\r\ntoken'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/user/login/checkPermit' in self.path:
            send = '\"agreed\":true'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/passwordrecovered.cgi?id=get_rekt' in self.path:
            send = 'right\">Router Admin Username<\r\nright\">Router Admin Password<\r\nleft'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/login/verify' in self.path:
            send = 'login success'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/login/userverify.cgi' in self.path:
            if 'panabit' in str(self.headers):
                send = 'URL=/index.htm\r\nURL=/cgi-bin/monitor.cgi'
                self.send_response(200)
                self.send_header("Set-Cookie", "paonline_admin")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            elif 'ixcache' in str(self.headers):
                send = 'URL=/cgi-bin/monitor.cgi'
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/debug/pyspidervulntest/run' in self.path:
            send = ''
            try:
                result = re.findall(r'print\(str\((\d+)\+%2B\+(\d+)\)\)', req_datas.decode())
                send = int(result[0][0]) + int(result[0][1])
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/index.php?action=login.index&host=0' in self.path:
            send = 'URL=/index.htm'
            self.send_response(302)
            self.send_header("location", "/index.php?action=admin.index&host=0")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/WEB_VMS/LEVEL15/' in self.path:
            send = 'webmaster level 2 username guest password guest'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/main.ehp' == self.path:
            send = 'document.formParent2.changepasswd1.value\r\npasswd_change.ehp'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/edr/sangforinter/v2/cssp/slog_client?token=eyJtZDUiOnRydWV9' in self.path:
            send = 'uid=0(root)'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/search.php?print(' in self.path:
            send = ''
            try:
                result = re.findall(r"print\((\d+)%2b(\d+)\)", self.path)
                send = int(result[0][0]) + int(result[0][1])
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(str(send), 'utf8'))

        elif '/server/index.php?s=/api/user/login' in self.path:
            send = 'uid\r\ngroupid\r\nuser_token'
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/graphql' == self.path:
            send = ''
            try:
                result = re.findall(r"CONCAT\('~','(\d+)','~'\)", req_datas.decode())
                send = '~' + str(result[0]) + '~'
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/php/rj_get_token.php' in self.path:
            send = "require_once ('conversion.php');\r\n$json_string = file_get_contents($fullpath);"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/php/ping.php' in self.path:
            send = ''
            try:
                result = re.findall(r"echo%20(\w+)\$\{(\w+)}(\w+)\^(\w+)", req_datas.decode('utf8'))
                send = result[0][0] + result[0][2] + '^' + result[0][3]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php?s=captcha' in self.path:
            send = "TmlnaHQgZ2F0aGVycywgYW5%kIG5vdyBteSB3YXRjaCBiZWdpbnMu1"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/install.php?finish' in self.path:
            send = ''
            try:
                body = re.findall(r'__typecho_config=(\w+)', req_datas.decode())
                body = base64.b64decode(body[0] + '==')
                result = re.findall(r"md5\('(\w+)'\)", body.decode())
                md5 = hashlib.md5()
                md5.update(result[0].encode())
                md5_data = md5.hexdigest()
                send = md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/casa/nodes/thumbprints' in self.path:
            send = "vRealize Operations Manager"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/wls-wsat/CoordinatorPortType' in self.path:
            if 'whoami' in str(self.headers):
                send = whoami_req()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                send = "225773091"
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/login.php?action=login&type=admin' in self.path:
            send = "{\"success\":\"true\", \"data\":{\"id\":1}, \"alert\":\"您正在使用默认密码登录，为保证设备安全，请立即修改密码\"}"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/Proxy' == self.path:
            if '<?xml version="1.0" encoding="GB2312"?>' in req_datas.decode('utf8'):
                send = ''
                try:
                    result = re.findall(r"set/A (\d+\*\d+)", req_datas.decode('utf8'))
                    send = str(eval(result[0]))
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))
            else:
                send = ''
                try:
                    result = re.findall(r"select%20(\d+)%2a(\d+)", req_datas.decode('utf8'))
                    send = result[0][0] + result[0][1]
                except:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/index.php' == self.path:
            send = ""
            self.send_response(302)
            self.send_header("location", "zabbix.php?action=dashboard.view")
            self.send_header("set-cookie", "zbx_session")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/Autodiscover/Autodiscover.xml' in self.path:
            send = "zmmailboxd.out\r\nRequested response schema not available"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' in self.path:
            send = ''
            try:
                result = re.findall(r"<\?=print\(md5\((\d+)\)\);\?>", req_datas.decode('utf8'))
                md5 = hashlib.md5()
                md5.update(result[0].encode())
                md5_data = md5.hexdigest()
                send = md5_data
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/v1/user/login' in self.path:
            if '{"username":"admin","password":"123456"}' in req_datas.decode('utf8'):
                send = "{\"code\":20000,\r\n\"data\":{\"token\""
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))
            else:
                send = "com.alibaba.otter.canal.admin.controller.UserController.login\r\n{\"code\":20000,\r\n\"data\":{\"token\""
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(send, 'utf8'))

        elif '/php/exportrecord.php?downname=' in self.path:
            send = "require_once ('conversion.php');\r\n$json_string = file_get_contents($fullpath);"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/_async/AsyncResponseService' in self.path:
            send = ""
            self.send_response(202)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/user/zs' in self.path:
            send = ""
            try:
                f_zs = open('zs_num', 'w')
                result = re.findall(r'select%20(\d+\*\d+)', req_datas.decode('utf8'))
                result = eval(result[0])
                f_zs.write(str(result))
                f_zs.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))


        elif '/php/change_config.php' in self.path:
            send = ""
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/druid/indexer/v1/sampler?for=connect' in self.path:
            send = "for 16-bit app support\r\n".encode('utf8')
            send += etc_passwd()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send))

        elif '/page/exportImport/uploadOperation.jsp' in self.path:
            send = ""
            try:
                result = re.findall(r'print\((\d+ \* \d+)\)', req_datas.decode('utf8'))
                result = eval(result[0])
                f_page_exportImport = open('page_exportImport', 'w')
                f_page_exportImport.write(str(result))
                f_page_exportImport.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/manager/login.php' in self.path:
            send = "<title>电信网关服务器管理后台</title>\r\nindex-shang.php\r\ndi.php"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/guest_auth/guestIsUp.php' in self.path:
            send = ""
            try:
                filename = re.findall(r"echo '(.*)'", req_datas.decode('utf8'))
                filename = base64.b64decode(filename[0]+'==')
                r1 = re.findall(r"echo '(.*)'", filename.decode('utf8'))
                f_guestIsUp = open('guestIsUp', 'w')
                f_guestIsUp.write(r1[0])
                f_guestIsUp.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/nacos/v1/auth/users' in self.path:
            send = "create user ok!"
            try:
                result = re.findall(r'username=(\w+)', self.path)
                f_nacos = open('nacos', 'w')
                f_nacos.write(result[0])
                f_nacos.close()
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/test/test1/123' in self.path:
            send = "create user ok!"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/test/test' == self.path:
            send = ""
            self.send_response(201)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/general/userinfo.php?UID=1' in self.path:
            send = "\"dept_name\":\"\r\n\"online_flag\":"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/servlet/FileReceiveServlet' in self.path:
            send = ""
            try:
                result = re.findall(r'](\d+)\[', req_datas.decode('utf8'))
                r2 = re.findall(r'print\("(\d+)"\)', req_datas.decode('utf8'))
                dict_num[result[0]] = r2[0]
            except:
                pass
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/seeyon/thirdpartyController.do' == self.path:
            send = "/seeyon/common/"
            self.send_response(200)
            self.send_header("Set-Cookie", "JSESSIONID=")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/php/getjson.php' in self.path:
            send = "require_once ('conversion.php');\r\n$json_string = file_get_contents($fullpath);"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/authorize.action' in self.path:
            send = "{\"success\": true, \"msg\": \"OK\"}"
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/api/users' == self.path:
            send = ""
            self.send_response(201)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))

        elif '/run' == self.path:
            send = "salt/wheel/d"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(send, 'utf8'))









        elif 'passwd'.encode('utf8') in req_datas:
            send = etc_passwd()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(send))

        elif '*' in req_datas.decode('utf8') or '+' in req_datas.decode('utf8') or '-' in req_datas.decode(
                'utf8') or '%2b' in req_datas.decode('utf8') or '%2B' in req_datas.decode('utf8'):
            req_datas = urllib.parse.unquote(req_datas.decode('utf8'))
            send = ''
            try:
                path_result = re.findall(r"(\d+ ([+,-]|\*|) \d+)", req_datas)
                if path_result == []:
                    pass
                else:
                    send = eval(path_result[0][0])
                if send == '':
                    try:
                        path_result = re.findall(r"(\d+([+,-]|\*|)\d+)", req_datas)
                        if path_result[0][1] == '':
                            try:
                                path_result = re.findall(r"\{(\d+([+,-]|\*|)\d+)}", req_datas)
                                try:
                                    path_result = re.findall(r"\((\d+([+,-]|\*|)\d+)\)", req_datas)
                                    send = eval(path_result[0][0])
                                except:
                                    pass
                                send = eval(path_result[0][0])
                            except:
                                pass
                        send = eval(path_result[0][0])
                    except:
                        pass
            except:
                pass

            if '/service/extdirect' in self.path:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))  # 计算出负数直接转byte报错，要转成字符串，然后utf8
            elif '/rest/beta/repositories/go/group' in self.path:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))  # 计算出负数直接转byte报错，要转成字符串，然后utf8
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))  # 计算出负数直接转byte报错，要转成字符串，然后utf8

        elif '*' in self.path or '%2b' in self.path or '+' in self.path or '-' in self.path or '*' in str(
                self.headers) or '%2b' in str(self.headers) or '+' in str(self.headers) or '-' in str(self.headers):
            path = urllib.parse.unquote(self.path)
            headers = str(self.headers)
            send = ''
            try:
                path_result = re.findall(r"(\d+ ([+,-]|\*|) \d+)", path)
                send = eval(path_result[0][0])
            except:
                pass
            try:
                headers_result = re.findall(r"(\d+ ([+,-]|\*|) \d+)", headers)
                send = eval(headers_result[0][0])
            except:
                pass
            if '/' == self.path:
                if 'username=admin&password=' in req_datas.decode('utf8'):
                    send = ''
                    self.send_response(302)
                    self.send_header("location", "/page/login/login_fail.html")
                    self.end_headers()
                    self.wfile.write(bytes(send, 'utf8'))
                else:
                    send = 'MethodNotAllowedHttpException\r\nEnvironment &amp; details\r\nvendor\\laravel\\framework\\src\\Illuminate\\Routing\\RouteCollection.php'
                    self.send_response(405)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(bytes(send, 'utf8'))
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(str(send), 'utf8'))  # 计算出负数直接转byte报错，要转成字符串，然后utf8


        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes("yes", "utf-8"))
            f.write('resonse:yes')  # test_writelog
        self.wfile.write(bytes(str(now_time), 'utf8'))
        f.write('\r\nresponse:'+str(send)) # test_writelog

def print_req(data):
    pass


def calc_md5(data):  # 计算md5
    send = ''
    result = ''
    try:
        result = re.findall(r'md5(\d+)', data.decode())
        if result == []:
            try:
                result = re.findall(r'md5\((.*?)\)', data.decode())
            except:
                pass
    except:
        pass

    res = []
    for each in result:
        md5 = hashlib.md5()
        md5.update(each.encode())
        md5_data = md5.hexdigest()
        res.append(md5_data)

    for each in res:
        send += each + '\r\n'

    return send


def whoami_req():
    send = 'whoami :'
    return send


def etc_passwd():
    send = '''
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
    systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
    systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
    messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
    syslog:x:104:110::/home/syslog:/usr/sbin/nologin
    _apt:x:105:65534::/nonexistent:/usr/sbin/nologin
    uuidd:x:106:112::/run/uuidd:/usr/sbin/nologin
    tcpdump:x:107:113::/nonexistent:/usr/sbin/nologin
    ntp:x:108:115::/nonexistent:/usr/sbin/nologin
    sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
    systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
    _chrony:x:110:121:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
    tss:x:111:122:TPM software stack,,,:/var/lib/tpm:/bin/false
    dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
    kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
    cups-pk-helper:x:114:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
    rtkit:x:115:125:RealtimeKit,,,:/proc:/usr/sbin/nologin
    whoopsie:x:116:126::/nonexistent:/bin/false
    avahi-autoipd:x:117:128:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
    usbmux:x:118:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
    avahi:x:119:129:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
    nm-openvpn:x:120:130:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
    speech-dispatcher:x:121:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
    saned:x:122:132::/var/lib/saned:/usr/sbin/nologin
    hplip:x:123:7:HPLIP system user,,,:/run/hplip:/bin/false
    colord:x:124:133:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
    geoclue:x:125:134::/var/lib/geoclue:/usr/sbin/nologin
    pulse:x:126:135:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
    gnome-initial-setup:x:127:65534::/run/gnome-initial-setup/:/bin/false
    gdm:x:128:137:Gnome Display Manager:/var/lib/gdm3:/bin/false
    datacon:x:1000:1000:,,,:/home/datacon:/bin/bash
    _rpc:x:129:65534::/run/rpcbind:/usr/sbin/nologin
    statd:x:130:65534::/var/lib/nfs:/usr/sbin/nologin
    '''.encode('utf-8')
    return send


if __name__ == "__main__":
    webServer = HTTPServer(server_address, MyServer)
    print("Server started http://%s:%s" % server_address)

    webServer.serve_forever()
    # webServer.server_close()
    # print("Server stopped.")