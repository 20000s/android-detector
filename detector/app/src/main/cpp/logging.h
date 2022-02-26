//
// Created by 24657 on 2022/2/23.
//

#ifndef DETECTOR_LOGGING_H
#define DETECTOR_LOGGING_H

#endif //DETECTOR_LOGGING_H
#include <android/log.h>
#define TAG "s20000s"
#define LOGV(...) (__android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__))
#define LOGI(...) (__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGW(...) (__android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__))
#define LOGE(...) (__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))
#define LOGD(...) (__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))