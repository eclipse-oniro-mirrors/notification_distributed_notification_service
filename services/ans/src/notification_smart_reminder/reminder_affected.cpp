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

#include "reminder_affected.h"

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
    ValidStatus(root[STATUS], status_);
    ValidAndGetAffectedBy(
        root[AFFECTED_BY], affectedBy_);

    if (!root[NotificationConfigParse::CFG_KEY_REMINDER_FLAGS].is_null() &&
        root[NotificationConfigParse::CFG_KEY_REMINDER_FLAGS].is_string() &&
        NotificationFlags::GetReminderFlagsByString(
            root[NotificationConfigParse::CFG_KEY_REMINDER_FLAGS].get<std::string>(), reminderFlags_)) {
        return true;
    }
    return false;
}

bool ReminderAffected::ValidAndGetAffectedBy(
    const nlohmann::json &affectedBysJson, std::vector<std::pair<std::string, std::string>> &affectedBy)
{
    if (affectedBysJson.is_null() || !affectedBysJson.is_array() || affectedBysJson.empty()) {
        return false;
    }

    for (auto affectedByJson : affectedBysJson) {
        std::string status;
        if (affectedByJson.is_null() ||
            !affectedByJson.is_object() ||
            affectedByJson[DEVICE_TYPE].is_null() ||
            !affectedByJson[DEVICE_TYPE].is_string() ||
            !ValidStatus(affectedByJson[STATUS], status)) {
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
    if (root.is_null() || !root.is_string()) {
        ANS_LOGD("ValidStatus failed as status json is empty.");
        return false;
    }
    std::string strStatus = root.get<std::string>();
    if (strStatus.size() <= 0) {
        return true;
    }
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
    status = strStatus;
    return true;
}
}  // namespace Notification
}  // namespace OHOS

