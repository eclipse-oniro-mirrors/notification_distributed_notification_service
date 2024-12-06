/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "ans_manager_stub.h"
#include "ans_permission_def.h"
#undef private
#undef protected
#include "ansmanagerstubannexthree_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
        constexpr uint8_t SLOT_TYPE_NUM = 5;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        Notification::AnsManagerStub ansManagerStub;
        bool allow = *data % ENABLE;
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        int notificationId = 1;
        std::string stringData(data);
        int32_t removeReason = static_cast<int32_t>(GetU32Data(data));
        ansManagerStub.RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        ansManagerStub.RemoveAllNotifications(bundleOption);
        ansManagerStub.Delete(stringData, removeReason);
        ansManagerStub.DeleteByBundle(bundleOption);
        ansManagerStub.DeleteAll();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        std::vector<sptr<Notification::NotificationSlot>> slots;
        slots.emplace_back(slot);
        ansManagerStub.GetSlotsByBundle(bundleOption, slots);
        ansManagerStub.SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, allow);
        ansManagerStub.SetShowBadgeEnabledForBundle(bundleOption, allow);
        ansManagerStub.GetShowBadgeEnabledForBundle(bundleOption, allow);
        ansManagerStub.GetShowBadgeEnabled(allow);
        ansManagerStub.IsAllowedNotify(allow);
        ansManagerStub.IsAllowedNotifySelf(allow);
        ansManagerStub.IsSpecialBundleAllowedNotify(bundleOption, allow);
        ansManagerStub.CancelGroup(stringData, "");
        ansManagerStub.RemoveGroupByBundle(bundleOption, stringData);
        ansManagerStub.DoesSupportDoNotDisturbMode(allow);
        ansManagerStub.IsDistributedEnabled(allow);
        ansManagerStub.EnableDistributed(allow);
        ansManagerStub.EnableDistributedByBundle(bundleOption, allow);
        ansManagerStub.EnableDistributedSelf(allow);
        ansManagerStub.IsDistributedEnableByBundle(bundleOption, allow);
        int32_t remindType = static_cast<int32_t>(*data % SLOT_TYPE_NUM);
        Notification::NotificationConstant::RemindType remind =
            Notification::NotificationConstant::RemindType(remindType);
        ansManagerStub.GetDeviceRemindType(remind);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        ansManagerStub.PublishContinuousTaskNotification(request);
        ansManagerStub.CancelContinuousTaskNotification(stringData, removeReason);
        ansManagerStub.CancelReminder(removeReason);
        return ansManagerStub.CancelAllReminders();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        std::vector<std::string> requestPermission = {
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
        };
        SystemHapTokenGet(requestPermission);
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
