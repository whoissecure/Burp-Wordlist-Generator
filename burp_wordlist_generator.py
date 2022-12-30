from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from os.path import expanduser
from time import strftime, localtime
from urlparse import urlparse

def generate_file(data, file_type):
    file_name = expanduser("~") + '/' + file_type + '_' + strftime("%Y_%m_%d_%H_%M_%S", localtime()) + '.txt'
    with open(file_name, 'w') as f:
        for item in data:
            f.write(item + '\n')
    print("[+] Wordlist generated in " + file_name + "!")

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName('Burp Wordlist Generator')
        self._helpers = callbacks.getHelpers()
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE or invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            selected_messages = invocation.getSelectedMessages()
            if selected_messages:
                request_info = self._helpers.analyzeRequest(selected_messages[0])
                self.host = request_info.getUrl().getHost()
                self.invocation = invocation
                menu_items = []
                menu_item_params = JMenuItem("Generate wordlist for parameter fuzzing", None, actionPerformed=self.getParams)
                menu_item_url = JMenuItem("Generate wordlist for URL fuzzing", None, actionPerformed=self.getURLs)
                menu_items.append(menu_item_params)
                menu_items.append(menu_item_url)
                return menu_items
        else:
            return None

    def getParams(self, event):
        parameters = []
        for request in self.callbacks.getProxyHistory():
            request_info = self._helpers.analyzeRequest(request)
            if request_info.getUrl().getHost() == self.host:
                parameters += [param.getName() for param in request_info.getParameters()]
                parameters = sorted(set(parameters))

        generate_file(parameters, "parameters")

    def getURLs(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        selected_url = selected_messages[0].getUrl()
        selected_host = selected_url.getHost()
        path = []
        urls = []

        for request in self.callbacks.getProxyHistory():
            request_info = self._helpers.analyzeRequest(request)
            request_url = request_info.getUrl()
            request_host = request_url.getHost()

            if request_host == selected_host:
                urls.append(request_url.toString())
            
        urls = sorted(set(urls))

        for url in urls:
            for i in urlparse(url).path.split('/'):
                path.append(i)

        path = sorted(set(path))

        generate_file(path, "paths")