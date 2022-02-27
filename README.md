记录对目前android 常见逆向工具frida xposed ptrace等的检测，对于网上说的各种方法做了个汇总，长期不定时更新，看到好的仓库就放进来，主要目的是为了自我学习



## ptrace

1.cat /proc/uid/status  查看tracepid (detect)

2.ptrace me



## root

1. 查看ro.debuggable ro.secure
2. 检测su文件



## riru

```
   1. 查看ro.dalvik.vm.native.bridge 是不是libriruloader.so
   2.读取ro.dalvik.vm.native.bridge是xxxx.so 读取system/lib/xxx.so 寻找libriru
   3。读取maps 寻找linker 在linker的里面搜索so list so info 从里面判断是否得到riru
```

## frida

```
 检测：1.检测ps 是否有frida_server (这个用不了 ps -A还是只有它自身)
      2.检查frida 端口 dbus (超级慢,得开另一个线程慢慢看   )
      3.通过 maps 查看内存可执行区域  寻找LIBFRIDA 或者map 看so frida-agent.so这个太简单了 不写了
      4.查看一些可能的线程 gmain、gum-js-loop
      5.检查管道 frida 进行注入的时候 会使用特定管道
      6.libc比对 因为frida用的是illine hook  hook前后 必然导致 文件的结构不同  因此可以进行校验


 防止frida HOOK :
 将libc map成只读

 具体原理详见
 https://github.com/TUGOhost/anti_Android
```









## 参考

1.https://github.com/vvb2060/XposedDetector

2.https://github.com/LSPosed/NativeDetector

3.https://github.com/vvb2060/MagiskDetector

4.https://github.com/TUGOhost/anti_Android

5.https://github.com/lamster2018/EasyProtector

6.https://github.com/darvincisec/DetectMagiskHide