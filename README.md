# cf-vless
cloudflare通用代理

/s=admin:123456@123.123.28.123:13333（仅SOCKS5）
/g=admin:123456@123.123.28.123:13333（全局SOCKS5）
/p=ProxyIP.US.CMLiussss.net（仅Proxyip）
/h=192.168.1.1:1080（回退http）
/gh=192.168.1.1:1080（全局http）

其中/s和/h支持?参数分流，例如/s=admin:123456@123.123.28.123:13333?ipv4.ping0.cc&*.google.com
