//
// Created by 24657 on 2022/2/25.
//

#include <jni.h>
#include <string.h>
#include "logging.h"


/*
 * 原理：1.通过栈回溯 检测xposed存在
 *     2。loadclass加载xposed的类判断是否存在
 *
 *
 *  anti xposed
 *     3.尝试关闭XP框架 修改disable hooks
 *     4.查看你xposed的sHookedMethodCallbacks作用域
 *
 *
 */

#define  XPOSED_HELPERS "de.robv.android.xposed.XposedHelpers"
#define  XPOSED_BRIDGE  "de.robv.android.xposed.XposedBridge"


int check_xposed_callback(JNIEnv *env){
    jclass threadclass = (*env)->FindClass(env,"java/lang/Thread");
    jmethodID currentthread = (*env)->GetStaticMethodID(env,threadclass,"currentThread", "()Ljava/lang/Thread;");
    jmethodID getStackTrace = (*env)->GetMethodID((JNIEnv *) env, threadclass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
    jclass StackTraceElementClass = (*env)->FindClass((JNIEnv *) env, "java/lang/StackTraceElement");
    jmethodID getClassName = (*env)->GetMethodID((JNIEnv *) env, StackTraceElementClass, "getClassName", "()Ljava/lang/String;");

    jobject thread = (*env)->CallStaticObjectMethod((JNIEnv *) env, threadclass, currentthread);
    jobjectArray stackTraces = (jobjectArray) (*env)->CallObjectMethod((JNIEnv *) env, thread, getStackTrace);
    int length = (*env)->GetArrayLength((JNIEnv *) env, stackTraces);

    for (int i = 0; i < length; i++) {
        jobject stackTrace = (*env)->GetObjectArrayElement((JNIEnv *) env, stackTraces, i);
        LOGD("stacktrace : %s",stackTrace);
        jstring jclassName = (jstring) (*env)->CallObjectMethod((JNIEnv *) env, stackTrace, getClassName);
        const char *className = (*env)->GetStringUTFChars((JNIEnv *) env, jclassName, NULL);
        char methodHook[] = "de.robv.android.xposed.XC_MethodHook";
        if (memcmp(className, methodHook, strlen(methodHook)) == 0) {
            LOGD("Call stack found hook: %s", className);
            (*env)->ReleaseStringUTFChars((JNIEnv *) env, jclassName, className);
            return 1;
        }
        (*env)->ReleaseStringUTFChars((JNIEnv *) env, jclassName, className);

    }
    return 0;

}

int check_xposed_loadclass(JNIEnv * env){
   // jclass clazz = (*env)->FindClass(env, "dalvik/system/BaseDexClassLoader");
    jclass ClassLoader = (*env)->FindClass(env,"dalvik/system/DexClassLoader" );

    jmethodID loadclass = (*env)->GetMethodID(env,ClassLoader,"findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jclass clazz1 = (*env)->CallStaticObjectMethod(env,ClassLoader,XPOSED_BRIDGE);
    if(clazz1 == NULL)
        return 1;
    else
        return 0;
}


void anti_xposed_dishook(JNIEnv * env){
    jclass ClassLoader = (*env)->FindClass(env,"dalvik/system/DexClassLoader" );

    jmethodID loadclass = (*env)->GetMethodID(env,ClassLoader,"findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jclass clazz1 = (*env)->CallStaticObjectMethod(env,ClassLoader,XPOSED_BRIDGE);
    if(clazz1 != NULL){
        jfieldID field = (*env)->GetStaticFieldID((JNIEnv *) env, clazz1, "disableHooks", "Z");
        (*env)->SetStaticBooleanField((JNIEnv *) env, clazz1, field, JNI_TRUE);
    }


}


JNIEXPORT jstring JNICALL
Java_com_s20000s_detector_MainActivity_AntiXposed(JNIEnv *env, jclass clazz) {
    // TODO: implement AntiXposed()

    int ret = check_xposed_callback(env);
    int ret1 = check_xposed_loadclass(env);
}
