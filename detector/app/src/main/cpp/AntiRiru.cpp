#include <jni.h>
#include "logging.h"
#include <sys/system_properties.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "solist.h"
#include "elf_util.h"
#include "enc_str.h"
//
// Created by 24657 on 2022/2/26.
//

/*
 * 原理：
 *   1. 查看ro.dalvik.vm.native.bridge 是不是libriruloader.so
 *   2. ls system/lib/ 寻找libriru
 *   3。读取maps 寻找linker 在linker的里面搜索so list so info 从里面判断是否得到riru
 */


int check_riru_nb(){
    char value[100] = {0};
    __system_property_get("ro.dalvik.vm.native.bridge",value);
    LOGD("ro.dalvik.vm.native.bridge %s",value);
    if(strstr(value,"riru")){
        LOGD("found riru by ro.dalvik.vm.native.bridge");
        return 1;
    }
    return 0;
}

int check_riru_lib(){
    char value[100] = {0};
    __system_property_get("ro.dalvik.vm.native.bridge",value);
    char command[100] = {0};
    snprintf(command,sizeof(command),"cat /system/lib/libriruloader.so | grep riru");
    LOGD("command : %s",command);
    FILE *fd =popen(command,"r");
    if(fd == NULL){
        LOGD("can not open cat");
        return 0;
    }

    char buf[1000] = {0};
    LOGD("command content start:%s");
    while (fgets(buf,sizeof(buf),fd)){
      LOGD("buf %s",buf);
      if(strstr(buf,"matches")){
          LOGD("found riru by command");
          pclose(fd);
          return 1;
      }
    }
    pclose(fd);
    return 0;
}


int check_riru_linker(){
    static auto libriru_enc = "libriru"_senc;
    static auto so_enc = ".so"_senc;
    const auto libriru = libriru_enc.obtain();
    const auto so = so_enc.obtain();
    auto paths = Solist::FindPathsFromSolist(libriru);
    if (paths.empty()){
        LOGD("not found riru by linker");
        return 0;
    }
    else{
        LOGD("found riru by linker");
        return 1;
    }
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_s20000s_detector_MainActivity_AntiRiru(JNIEnv *env, jclass clazz) {
    // TODO: implement AntiRiru()


   int ret= check_riru_nb();
   int ret1=check_riru_lib();
   int ret2=check_riru_linker();

     if(ret || ret1 || ret2)
         return env->NewStringUTF("found");
     else
    return env->NewStringUTF("security");
}