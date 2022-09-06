记录对目前android 常见逆向工具frida xposed ptrace等的检测，对于网上说的各种方法做了个汇总，长期不定时更新，看到好的仓库就放进来，主要目的是为了自我学习



## ptrace

```c
1.cat /proc/self/status 查看traceuid
2. ptrce me
```





## root

```c
1. 查看 ro.secure ro.debuggable 
2. 查看常用目录下有没有su文件 /sbin....
3. System分区是否可写（这个有待确认 还得先su，不大使用）【todo】
```

对抗：
1.临时root fastboot boot 修改
2.改机rom





## riru

```
   1. 查看ro.dalvik.vm.native.bridge 是不是libriruloader.so(目前无效，riru等加载后又reset原来的了)
   2.读取ro.dalvik.vm.native.bridge是xxxx.so 读取system/lib/libriruloader.so 寻找libriru
   3。读取maps 寻找linker 在linker的里面搜的so list so info 从里面判断判断有没有riru(新版也去除了)
   4.通过检测 maps 文件中的匿名内存权限位是否有 "x" 来判断这段内存是不是 riru-hide 隐藏的 so. （不能用于商用，得去看看业务逻辑是否存在）[todo]
```

## frida

```
 检测：1.检测ps 是否有frida_server (这个用不了 ps -A还是只有它自身)
      2.检查frida 端口 dbus (超级慢,得开另一个线程慢慢看   )
      3.通过 maps 查看内存可执行区域  寻找LIBFRIDA 或者map 看so frida-agent.so这个太简单了 不写了
      4.查看一些可能的线程 gmain、gum-js-loop
      5.检查管道 frida 进行注入的时候 会使用特定管道
      6.libc比对 因为frida用的是illine hook  hook前后 必然导致 文件的结构不同  因此可以进行校验
      7.比较关键函数的第一个指令（这个要去翻intel的手册）

 防止frida HOOK :
 将libc map成只读

 具体原理详见
 https://github.com/TUGOhost/anti_Android
```



## magisk

``` 
1. 去常见目录下寻找su文件 （无法针对magisk hide）
2.Magisk模块虽然能在文件系统上隐藏，但修改内容已经载入进程内存，检查进程的maps就能发现。maps显示的数据包含载入文件所在的设备。Magisk模块会导致某些文件的路径在system分区或vendor分区，但显示的设备位置却是data分区 去map查看/system的文件分区是不是data分区 看major minor设备号 （riru不行  riru hide了）
3.magisk 修改了一些selinux的规则 在一些特定版本可以查看 所有应用都能连接magisk域的socket。每个Magisk的su进程都会建立一个socket，尝试连接所有socket，没有被SELinux拒绝的socket数量，就是su进程的数量。(测试  android 10不行)
4. magisk 修改看一些selinux的规则 /dev/ptmx 伪终端 ioctl(TIOCSTI)  伪造输入 看看 是否成功 （android 10成功 magisk hide也可以） 
5.Magisk在启动时会往init.rc中注入三个自己的服务，用来接收post-fs-data等事件；这三个服务的名称是做了随机化处理，而init实际上会往系统属性里添加像init.svc.<service name>这样子的属性，值是running或者stopped，以告诉其他进程该服务的状态。MagiskDetector就利用了这个机制，遍历系统属性记录所有服务名，然后在用户重启之后就能知道是否有服务的名称发生了变化    随机只有在无法遍历的情况下才有效。如果可以遍历，使用统计方法即可准确找出每次都不一样的东西。
6.ro.boot.verifiedbootstate bl状态orange ro.boot.vbmeta.device_state unlock
7.（ssh用的设备）/dev/pts getxattr ,由于selinux 所以不能list 只能new File("/dev/pts")，在/dec/pts创建1，2，3文件是否存在,在这些文件里得到相应属性，查看u:object_r:magisk_file:s0 android8以前反射selinux调用getfilecontent,android8以后os.getxattr比较
8.magisk是根据ppid为1(init禁止)和进程名为zygote来进行附加mount等操作，因此我们可以创造一个孤儿进程（ppid为1），将进程名改为zygote来欺骗magisk附加，查看进程的status来判断magisk
```







## 参考

1.https://github.com/vvb2060/XposedDetector

2.https://github.com/LSPosed/NativeDetector

3.https://github.com/vvb2060/MagiskDetector

4.https://github.com/TUGOhost/anti_Android

5.https://github.com/lamster2018/EasyProtector

6.https://github.com/darvincisec/DetectMagiskHide

7.https://github.com/canyie/MagiskKiller/