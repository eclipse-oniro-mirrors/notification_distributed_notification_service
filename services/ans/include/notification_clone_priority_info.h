/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_PRIORITY_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_PRIORITY_INFO_H

#include "ans_const_define.h"
#include "nlohmann/json.hpp"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationClonePriorityInfo {
public:
    enum class CLONE_PRIORITY_TYPE {
        /**
         * Switch type for SetPriorityEnabled.
         */
        PRIORITY_ENABLE,

        /**
         * Switch type for SetPriorityEnabledForBundle.
         */
        PRIORITY_ENABLE_FOR_BUNDLE,

        /**
         * Priority config for SetBundlePriorityConfig.
         */
        PRIORITY_CONFIG
    };

    NotificationClonePriorityInfo() = default;
    ~NotificationClonePriorityInfo() = default;

    void SetBundleName(const std::string &name);
    std::string GetBundleName() const;
    void SetBundleUid(const int32_t uid);
    int32_t GetBundleUid() const;
    void SetAppIndex(const int32_t appIndex);
    int32_t GetAppIndex() const;
    void SetSwitchState(const int32_t enableStatus);
    int32_t GetSwitchState() const;
    void SetPriorityConfig(const std::string &config);
    std::string GetPriorityConfig() const;
    void SetClonePriorityType(const CLONE_PRIORITY_TYPE type);
    CLONE_PRIORITY_TYPE GetClonePriorityType() const;

    void ToJson(nlohmann::json &jsonObject) const;
    bool FromJson(const nlohmann::json &jsonObject);
    bool FromJson(const std::string &jsonStr);
    std::string Dump() const;

private:
    std::string bundleName_;
    int32_t uid_ = DEFAULT_UID;
    int32_t appIndex_ = DEFAULT_APP_INDEX;
    CLONE_PRIORITY_TYPE clonePriorityType_ = CLONE_PRIORITY_TYPE::PRIORITY_ENABLE;
    int32_t enableStatus_;
    std::string config_;
    static const int32_t DEFAULT_APP_INDEX = -1;
    static constexpr const char *PRIORITY_BUNDLE_NAME = "name";
    static constexpr const char *PRIORITY_SWITCH_STATE = "enable";
    static constexpr const char *PRIORITY_BUNDLE_INDEX = "index";
    static constexpr const char *PRIORITY_CLONE_CONFIG = "config";
    static constexpr const char *PRIORITY_CLONE_PRIORITY_TYPE = "type";
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_PRIORITY_INFO_H