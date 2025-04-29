/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "reminder_affected.h"
#include "string_utils.h"

#include "distributed_device_status.h"
#include "notification_config_parse.h"
namespace OHOS {
namespace Notification {
bool ReminderAffected::FromJson(const nlohmann::json &root)
{
    if (root.is_null() || !root.is_object()) {
        ANS_LOGE("ReminderAffected fromJson failed as root is null.");
        return false;
    }

    ValidStatus(root, status_);
    ValidAndGetAffectedBy(root, affectedBy_);
    if (root.find(NotificationConfigParse::CFG_KEY_REMINDER_FLAGS) != root.end() &&
        !root[NotificationConfigParse::CFG_KEY_REMINDER_FLAGS].is_null() &&
        root[NotificationConfigParse::CFG_KEY_REMINDER_FLAGS].is_string() &&
        NotificationFlags::GetReminderFlagsByString(
            root[NotificationConfigParse::CFG_KEY_REMINDER_FLAGS].get<std::string>(), reminderFlags_)) {
        return true;
    }
    return false;
}

bool ReminderAffected::ValidAndGetAffectedBy(
    const nlohmann::json &root, std::vector<std::pair<std::string, std::string>> &affectedBy)
{
    if (root.is_null() || root.find(AFFECTED_BY) == root.end()) {
        return false;
    }
    nlohmann::json affectedBysJson = root[AFFECTED_BY];
    if (!affectedBysJson.is_array() || affectedBysJson.empty()) {
        return false;
    }
    for (auto affectedByJson : affectedBysJson) {
        std::string status;
        if (affectedByJson.is_null() || !affectedByJson.is_object()) {
            continue;
        }

        if (affectedByJson.find(DEVICE_TYPE) == affectedByJson.end() ||
            affectedByJson[DEVICE_TYPE].is_null() ||
            !affectedByJson[DEVICE_TYPE].is_string() ||
            !ValidStatus(affectedByJson, status)) {
            continue;
        }

        if (status.size() <= 0) {
            continue;
        }
        affectedBy.push_back(std::make_pair(affectedByJson[DEVICE_TYPE].get<std::string>(), status));
    }
    if (affectedBy.size() <= 0) {
        return false;
    }
    return true;
}

bool ReminderAffected::ValidStatus(const nlohmann::json &root, std::string &status)
{
    if (root.is_null() || root.find(STATUS) == root.end()) {
        ANS_LOGD("ValidStatus failed as status json is empty.");
        return false;
    }
    nlohmann::json statusJson = root[STATUS];
    if (!statusJson.is_string()) {
        ANS_LOGD("ValidStatus failed as status json is not string.");
        return false;
    }
    std::string strStatusArray = statusJson.get<std::string>();
    if (strStatusArray.size() <= 0) {
        return true;
    }

    std::vector<std::string> statusVector;
    StringUtils::Split(strStatusArray, StringUtils::SPLIT_CHAR, statusVector);
    for (std::string strStatus : statusVector) {
        if (strStatus.size() != DistributedDeviceStatus::STATUS_SIZE) {
        ANS_LOGD("ValidStatus failed as invalid status size.");
        return false;
        }
        for (int32_t seq = 0; seq < DistributedDeviceStatus::STATUS_SIZE; seq++) {
            if (strStatus.at(seq) != STATUS_DEFAULT &&
                strStatus.at(seq) != STATUS_ENABLE && strStatus.at(seq) != STATUS_DISABLE) {
                ANS_LOGD("ValidStatus failed as invalid status value.");
                return false;
            }
        }
    }
    status = strStatusArray;
    return true;
}
}  // namespace Notification
}  // namespace OHOS
#endif

