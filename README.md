# Fastjson-Scanner

闲来无事，在家写了个fastjson后端组件探测，用于探测后端是否使用fastjson。

使用的poc如下：

```
fastjson_poc = '{{"@type":"java.net.URL","val":"http://%s"}:"x"}' % val
```

### 优点

不仅能够探测POST中的json数据，还能够判断GET中的json数据，支持urlencode、urldecode等。

两种数据对应格式如下：

GET：

```
GET /?json={"fastjson":"example"}
```

POST：

```
POST /

...


{"fastjson":"example"}
```

### 使用方法

导入插件即可默认开始使用，对数据包进行被动扫描，由于使用的是burp自带的dnslog，所以稍微会有电脑延时，代码里写了sleep 10来获取result。


![first](https://s1.ax1x.com/2020/03/29/GEalbF.png)

当导入数据包后，在burp内可以看到FastjsonScanner这个窗口，代表导入成功，当探测成功后，会在其中显示对应的数据包以及参数：

![image](https://user-images.githubusercontent.com/14137698/86531657-b7e93380-bef5-11ea-91b7-3f4a87929694.png)

![image](https://user-images.githubusercontent.com/14137698/86531663-c9cad680-bef5-11ea-95f7-c57bd665d5ff.png)

![image](https://user-images.githubusercontent.com/14137698/86531675-dfd89700-bef5-11ea-9987-46ee6c08efda.png)



### 修改记录

1. 所有的payload进行打印

2. 增加多个检测的payload

3. 输出检测结果

4. 在某些场景下强行改变get为post请求
