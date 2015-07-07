# DPI
数据清洗

客户端数据清洗，并将清洗好的数据上传至数据仓库

文件夹说明：
client/ 客户端代码
server/ 服务端代码

程序编译：
1、客户端环境如果是pfring，需要编写makefile，然后再编译
2、客户端环境依赖libevent-2.0.21-stable.tar.gz，低版本的编译会报错
3、libevent-2.0.21-stable.tar.gz安装后，修改/etc/ld.so.conf文件，增加/usr/local/lib，并执行ldconfig


