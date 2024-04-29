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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SMART_REMINDER_CENTER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SMART_REMINDER_CENTER_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED

#include <bitset>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <singleton.h>

#include "advanced_notification_service.h"

#include "distributed_device_status.h"
#include "file_utils.h"
#include "nlohmann/json.hpp"
#include "notification_config_parse.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_flags.h"
#include "notification_request.h"
#include "reminder_affected.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
using namespace std;
class SmartReminderCenter : public DelayedSingleton<SmartReminderCenter> {
public:
    SmartReminderCenter();
    ~SmartReminderCenter() = default;

    void ReminderDecisionProcess(const sptr<NotificationRequest> &request) const;
    bool CompareStatus(const string &status, const bitset<DistributedDeviceStatus::STATUS_SIZE> &bitStatus) const;

private:
    void GetMultiDeviceReminder();
    void ParseReminderFilterDevice(const nlohmann::json &root, const string &deviceType);
    void ParseReminderFilterSlot(
        const nlohmann::json &root,
        const string &notificationType,
        map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const;
    void ParseReminderFilterContent(
        const nlohmann::json &root,
        const string &notificationType,
        map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const;
    void ParseReminderFilterCode(
        const nlohmann::json &root,
        const string &notificationType,
        map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const;
    void HandleReminderMethods(
        const string &deviceType,
        const map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice,
        const sptr<NotificationRequest> &request,
        set<string> &validDevices,
        shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices) const;
    bool HandleAffectedReminder(
        const string &deviceType,
        const shared_ptr<ReminderAffected> &reminderAffected,
        const set<string> &validDevices,
        shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices) const;
    void GetReminderAffecteds(
        const map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice,
        const sptr<NotificationRequest> &request,
        vector<shared_ptr<ReminderAffected>> &reminderAffecteds) const;
    void GetDeviceStatusByType(const string &deviceType, bitset<DistributedDeviceStatus::STATUS_SIZE> &bitStatus) const;
    bool IsNeedSynergy(const string &deviceType, const string &ownerBundleName) const;

    map<NotificationConstant::SlotType, shared_ptr<NotificationFlags>> currentReminderMethods_;
    map<string, map<string, vector<shared_ptr<ReminderAffected>>>> reminderMethods_;

    constexpr static const char* MULTI_DEVICE_REMINDER = "multiDeviceReminder";
    constexpr static const char* REMINDER_FILTER_DEVICE = "reminderFilterDevice";
    constexpr static const char* SLOT_TYPE = "slotType";
    constexpr static const char* REMINDER_FILTER_SLOT = "reminderFilterSlot";
    constexpr static const char* CONTENT_TYPE = "contentType";
    constexpr static const char* REMINDER_FILTER_CONTENT = "reminderFilterContent";
    constexpr static const char* TYPE_CODE = "typeCode";
    constexpr static const char* REMINDER_FILTER_CODE = "reminderFilterCode";
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SMART_REMINDER_CENTER_H
#endif
