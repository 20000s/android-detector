//
// Created by 24657 on 2022/2/23.
//

#include <jni.h>
#include <stdio.h>
#include <sys/system_properties.h>

#include <fcntl.h>
#include "logging.h"
/*
 * 这里 主要是检测root的
 *   原理 1.检测ro.debuggable ro.secure
 *       2.检测是否存在su文件
 */

int check_system_property(){
    char value[5] = {0};
    char value1[5] = {0};
    __system_property_get("ro.secure",value);
    LOGD("ro.secure : %s",value);
    __system_property_get("ro.debuggable",value1);
    LOGD("ro.debuggable : %s:",value);
    if(value[0] == 0x31 || value1[0] == 0x31)
        return 1;
    else
        return 0;

}

int check_su_files(){
    FILE *fp,*fp1,*fp2,*fp3,*fp4,*fp5,*fp6,*fp7;
    fp = fopen("/sbin/su","r");
    fp1= fopen("/system/bin/su","r");
    fp2= fopen("/system/xbin/su","r");
    fp3= fopen("/data/local/xbin/su","r");
    fp4= fopen("/data/local/bin/su","r");
    fp5= fopen("/system/sd/xbin/su","r");
    fp6= fopen("/system/bin/failsafe/su","r");
    fp7= fopen("/data/local/su","r");
    if(fp || fp1 || fp2 || fp3 || fp4 || fp5 || fp6 || fp7){
        LOGD("su files has been found");
        return  1;
    } else{
        LOGD("su files has not been found");
        return 0;
    }

}


JNIEXPORT jstring JNICALL
Java_com_s20000s_detector_MainActivity_AntiRoot(JNIEnv *env, jclass clazz) {
    // TODO: implement AntiRoot()
    int ret = check_su_files();
    if(check_system_property() || ret)
        return (*env)->NewStringUTF(env,"has been rooted");
    else
        return (*env)->NewStringUTF(env,"has not been checked");
}