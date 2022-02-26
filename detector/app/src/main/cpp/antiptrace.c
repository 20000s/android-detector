#include <jni.h>
#include <stdio.h>
#include "logging.h"
#include <pthread.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <string.h>

/*
 * 原理：
 *   cat /PROC/UID/status 检测traceid 看了一下对ida有用
 *   经过测试，能够发现ida ptrace 能看见
 *   如果是防止被ptrace的话,就直接ptrace me
 */

int get_number_for_str(char *str) {
    if (str == NULL) {
        return -1;
    }
    char result[20];
    int count = 0;
    while (*str != '\0') {
        if (*str >= 48 && *str <= 57) {
            result[count] = *str;
            count++;
        }
        str++;
    }
    int val = atoi(result);
    return val;
}





int detectptrace(){

    int pid = getpid();
    char file_name[20] = {'\0'};
    sprintf(file_name, "/proc/%d/status", pid);
    char linestr[256];
    int i = 0, traceid;
    FILE *fp;
        i = 0;
        fp = fopen(file_name, "r");
        if (fp == NULL) {
            return 0;
        }
        while (!feof(fp)) {
            fgets(linestr, 256, fp);
            if (i == 7) {
                traceid = get_number_for_str(linestr);
                LOGD("traceId:%d", traceid);
                if(traceid !=0)
                    return 1;
                else
                    break;
            }
            i++;
        }
        fclose(fp);


    return 0;
}



JNIEXPORT jstring
JNICALL
Java_com_s20000s_detector_MainActivity_Antiptrace(JNIEnv *env, jclass clazz) {
    // ptrace(PTRACE_TRACEME, 0, 0, 0);
    if(detectptrace()){
        return (*env)->NewStringUTF(env,"has been detector");
    }else{
        return (*env)->NewStringUTF(env,"has not be found");
    }
}