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

namespace OHOS {
namespace Notification {
#ifndef ANS_LOG_DOMAIN
#define ANS_LOG_DOMAIN 0xD001200
#endif

#ifndef ANS_LOG_TAG
#define ANS_LOG_TAG "Ans"
#endif

#ifndef ANS_REMINDER_LOG_TAG
#define ANS_REMINDER_LOG_TAG "ANS_REMINDER"
#endif

enum class AnsLogLevel : uint8_t { DEBUG = 0, INFO, WARN, ERROR, FATAL };

static constexpr OHOS::HiviewDFX::HiLogLabel ANS_LABEL = {LOG_CORE, ANS_LOG_DOMAIN, ANS_LOG_TAG};
static constexpr OHOS::HiviewDFX::HiLogLabel ANS_REMINDER_LABEL = {LOG_CORE, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG};

class AnsLogWrapper {
public:
    AnsLogWrapper() = delete;
    ~AnsLogWrapper() = delete;

    /**
     * @brief Judge the level of the log.
     *
     * @param level Indicates the level of the log.
     * @return Returns ture on passed, otherwise false.
     */
    static bool JudgeLevel(const AnsLogLevel &level);

    /**
     * @brief Set the level of the log.
     *
     * @param level Indicates the level of the log.
     */
    static void SetLogLevel(const AnsLogLevel &level)
    {
        level_ = level;
    }

    /**
     * @brief Get the level of the log.
     *
     * @return Indicates the level of the log.
     */
    static const AnsLogLevel &GetLogLevel()
    {
        return level_;
    }

    /**
     * @brief Get the brief name of the file.
     *
     * @param str Indicates the full name of the file.
     * @return Indicates the file name.
     */
    static std::string GetBriefFileName(const char *str);

private:
    static AnsLogLevel level_;
};

#define PRINT_LOG(LEVEL, level, fmt, ...)                    \
    if (AnsLogWrapper::JudgeLevel(AnsLogLevel::LEVEL))   \
    HILOG_IMPL(LOG_CORE, level, ANS_LOG_DOMAIN, ANS_LOG_TAG  \
        "[%{public}s:(%{public}s):%{public}d] " fmt,         \
        AnsLogWrapper::GetBriefFileName(__FILE__).c_str(), \
        __FUNCTION__,                                        \
        __LINE__,                                            \
        ##__VA_ARGS__)

#define ANS_LOGD(fmt, ...) PRINT_LOG(DEBUG, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define ANS_LOGI(fmt, ...) PRINT_LOG(INFO, LOG_INFO, fmt, ##__VA_ARGS__)
#define ANS_LOGW(fmt, ...) PRINT_LOG(WARN, LOG_WARN, fmt, ##__VA_ARGS__)
#define ANS_LOGE(fmt, ...) PRINT_LOG(ERROR, LOG_ERROR, fmt, ##__VA_ARGS__)
#define ANS_LOGF(fmt, ...) PRINT_LOG(FATAL, LOG_FATAL, fmt, ##__VA_ARGS__)

#define PRINT_REMINDER_LOG(LEVEL, level, fmt, ...)                  \
    if (AnsLogWrapper::JudgeLevel(AnsLogLevel::LEVEL))   \
    HILOG_IMPL(LOG_CORE, level, ANS_LOG_DOMAIN, ANS_REMINDER_LOG_TAG  \
        "[%{public}s:(%{public}s):%{public}d] " fmt,         \
        AnsLogWrapper::GetBriefFileName(__FILE__).c_str(), \
        __FUNCTION__,                                        \
        __LINE__,                                            \
        ##__VA_ARGS__)

#define ANSR_LOGD(fmt, ...) PRINT_REMINDER_LOG(DEBUG, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define ANSR_LOGI(fmt, ...) PRINT_REMINDER_LOG(INFO, LOG_INFO, fmt, ##__VA_ARGS__)
#define ANSR_LOGW(fmt, ...) PRINT_REMINDER_LOG(WARN, LOG_WARN, fmt, ##__VA_ARGS__)
#define ANSR_LOGE(fmt, ...) PRINT_REMINDER_LOG(ERROR, LOG_ERROR, fmt, ##__VA_ARGS__)
#define ANSR_LOGF(fmt, ...) PRINT_REMINDER_LOG(FATAL, LOG_FATAL, fmt, ##__VA_ARGS__)
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_LOG_HELPER_H