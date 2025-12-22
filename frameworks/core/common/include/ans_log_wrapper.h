/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_LOG_HELPER_H
#define BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_LOG_HELPER_H

#include <stdint.h>         // for uint8_t
#include <string>           // for basic_string

#include "hilog/log.h"
#include <chrono>

namespace OHOS {
namespace Notification {
#ifndef ANS_LOG_DOMAIN
#define ANS_LOG_DOMAIN 0xD001203
#endif

#ifndef ANS_LOG_TAG
#define ANS_LOG_TAG "Ans"
#endif

#ifndef ANS_REMINDER_LOG_TAG
#define ANS_REMINDER_LOG_TAG "ANS_REMINDER"
#endif

#define ANS_LOG_LIMIT_INTERVALS 10000 //ms

#define CUR_FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define ANS_LOGF(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, ANS_LOG_DOMAIN, ANS_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANS_LOGE(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, ANS_LOG_DOMAIN, ANS_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANS_LOGW(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, ANS_LOG_DOMAIN, ANS_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANS_LOGI(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, ANS_LOG_DOMAIN, ANS_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANS_LOGD(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, ANS_LOG_DOMAIN, ANS_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#define ANSR_LOGF(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANSR_LOGE(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANSR_LOGW(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANSR_LOGI(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG, \
    fmt, ##__VA_ARGS__))
#define ANSR_LOGD(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, CUR_FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#define ANS_COND_DO_ERR(cond, expr, format, ...)          \
    if (cond) {                                           \
        ANS_LOGE(format, ##__VA_ARGS__);                  \
        {                                                 \
            expr;                                         \
        }                                                 \
    }

#define ANS_COND_DO_WARN(cond, expr, format, ...)         \
    if (cond) {                                           \
        ANS_LOGW(format, ##__VA_ARGS__);                  \
        {                                                 \
            expr;                                         \
        }                                                 \
    }

#define ANS_PRINT_LIMIT(type, level, intervals, canPrint)                               \
do {                                                                                    \
    static auto last = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>();   \
    static uint32_t supressed = 0;                                                      \
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()); \
    auto duration = now - last;                                                         \
    if (duration.count() >= (intervals)) {                                              \
        last = now;                                                                     \
        uint32_t supressedCnt = supressed;                                              \
        supressed = 0;                                                                  \
        if (supressedCnt != 0) {                                                        \
            ((void)HILOG_IMPL((type), (level), ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG,    \
            "[%{public}s]log suppressed cnt %{public}u",         \
            __FUNCTION__, supressedCnt));                       \
        }                                                                               \
        (canPrint) = true;                                                              \
    } else {                                                                            \
        supressed++;                                                                    \
        (canPrint) = false;                                                             \
    }                                                                                   \
} while (0)

#define ANS_LOGF_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    ANS_PRINT_LIMIT(LOG_CORE, LOG_FATAL, ANS_LOG_LIMIT_INTERVALS, can); \
    if (can) {                                                          \
        ANS_LOGF(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#define ANS_LOGE_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    ANS_PRINT_LIMIT(LOG_CORE, LOG_ERROR, ANS_LOG_LIMIT_INTERVALS, can); \
    if (can) {                                                          \
        ANS_LOGE(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)


#define ANS_LOGW_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    ANS_PRINT_LIMIT(LOG_CORE, LOG_WARN, ANS_LOG_LIMIT_INTERVALS, can);  \
    if (can) {                                                          \
        ANS_LOGW(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)


#define ANS_LOGI_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    ANS_PRINT_LIMIT(LOG_CORE, LOG_INFO, ANS_LOG_LIMIT_INTERVALS, can);  \
    if (can) {                                                          \
        ANS_LOGI(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#define ANS_LOGD_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    ANS_PRINT_LIMIT(LOG_CORE, LOG_DEBUG, ANS_LOG_LIMIT_INTERVALS, can); \
    if (can) {                                                          \
        ANS_LOGD(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_LOG_HELPER_H
