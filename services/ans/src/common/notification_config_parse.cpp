/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <memory>

#include "notification_config_parse.h"

#include "ans_log_wrapper.h"
#include "notification_slot.h"
#include "file_utils.h"

namespace OHOS {
namespace Notification {
NotificationConfigParse::NotificationConfigParse()
{
    if (!FileUtils::GetJsonByFilePath(NOTIFICAITON_CONFIG_FILE, notificationConfigJsons_)) {
        ANS_LOGE("Failed to get notification config file, fileName: %{public}s.", NOTIFICAITON_CONFIG_FILE);
    }
    defaultCurrentSlotReminder_ = {
        {NotificationConstant::SlotType::SOCIAL_COMMUNICATION, "11111"},
        {NotificationConstant::SlotType::SERVICE_REMINDER, "11011"},
        {NotificationConstant::SlotType::CONTENT_INFORMATION, "00000"},
        {NotificationConstant::SlotType::OTHER, "00000"},
        {NotificationConstant::SlotType::LIVE_VIEW, "11011"},
        {NotificationConstant::SlotType::CUSTOMER_SERVICE, "10001"},
        {NotificationConstant::SlotType::EMERGENCY_INFORMATION, "11111"}
    };
}

bool NotificationConfigParse::GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const
{
    if (notificationConfigJsons_.size() <= 0) {
        ANS_LOGE("Failed to get config json cause empty notificationConfigJsons.");
        return false;
    }
    bool ret = false;
    std::for_each(notificationConfigJsons_.rbegin(), notificationConfigJsons_.rend(),
        [&keyCheck, &configJson, &ret](const nlohmann::json &json) {
        if (keyCheck.find("/") == std::string::npos && json.contains(keyCheck)) {
            configJson = json;
            ret = true;
        }

        if (keyCheck.find("/") != std::string::npos) {
            nlohmann::json::json_pointer keyCheckPoint(keyCheck);
            if (json.contains(keyCheckPoint)) {
                configJson = json;
                ret = true;
            }
        }
    });
    if (!ret) {
        ANS_LOGE("Cannot find keyCheck: %{public}s in notificationConfigJsons.", keyCheck.c_str());
    }
    return ret;
}

void NotificationConfigParse::GetDefaultCurrentSlotReminder(
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const
{
    for (auto defaultCurrentSlotReminder : defaultCurrentSlotReminder_) {
        std::shared_ptr<NotificationFlags> reminderFlags;
        NotificationFlags::GetReminderFlagsByString(defaultCurrentSlotReminder.second, reminderFlags);
        FillStatusIcon(defaultCurrentSlotReminder.first, reminderFlags);
        currentSlotReminder[defaultCurrentSlotReminder.first] = reminderFlags;
    }
}

bool NotificationConfigParse::GetCurrentSlotReminder(
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const
{
    nlohmann::json root;
    std::string slotJsonPoint = "/";
    slotJsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    slotJsonPoint.append("/");
    slotJsonPoint.append(CFG_KEY_SLOT_TYPE_REMINDER);
    if (!GetConfigJson(slotJsonPoint, root)) {
        return false;
    }

    nlohmann::json currentDeviceRemindJson = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_SLOT_TYPE_REMINDER];
    if (currentDeviceRemindJson.is_null() || !currentDeviceRemindJson.is_array() || currentDeviceRemindJson.empty()) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentDeviceReminder json.");
        return false;
    }
    for (auto &reminderFilterSlot : currentDeviceRemindJson) {
        std::shared_ptr<NotificationFlags> reminderFlags;
        NotificationConstant::SlotType slotType;
        if (reminderFilterSlot[CFG_KEY_NAME].is_null() ||
            !reminderFilterSlot[CFG_KEY_NAME].is_string() ||
            !NotificationSlot::GetSlotTypeByString(reminderFilterSlot[CFG_KEY_NAME].get<std::string>(), slotType) ||
            reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].is_null() ||
            !reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].is_string() ||
            !NotificationFlags::GetReminderFlagsByString(
                reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].get<std::string>(), reminderFlags)) {
            continue;
        }
        FillStatusIcon(slotType, reminderFlags);
        currentSlotReminder[slotType] = reminderFlags;
    }
    if (currentSlotReminder.size() <= 0) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentSlotReminder size.");
        return false;
    }
    return true;
}

void NotificationConfigParse::FillStatusIcon(
    const NotificationConstant::SlotType &slotType, std::shared_ptr<NotificationFlags> &reminderFlags) const
{
    switch (slotType) {
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
        case NotificationConstant::SlotType::SERVICE_REMINDER:
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
        case NotificationConstant::SlotType::LIVE_VIEW:
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            reminderFlags->SetStatusIconEnabled(true);
            break;
        case NotificationConstant::SlotType::OTHER:
            reminderFlags->SetStatusIconEnabled(false);
            break;
        default:
            break;
    }
}
} // namespace Notification
} // namespace OHOS
