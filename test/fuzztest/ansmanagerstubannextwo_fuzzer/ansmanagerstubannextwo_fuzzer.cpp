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
#undef private
#undef protected
#include "ansmanagerstubannextwo_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
        constexpr uint8_t SLOT_TYPE_NUM = 5;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        Notification::AnsManagerStub ansManagerStub;
        MessageParcel datas;
        MessageParcel reply;
        ansManagerStub.HandleGetEnabledForBundleSlot(datas, reply);
        ansManagerStub.HandleDistributedSetEnabledWithoutApp(datas, reply);
        ansManagerStub.HandleDistributedGetEnabledWithoutApp(datas, reply);
        std::string stringData(data);
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        ansManagerStub.Publish(stringData, notification);
        int notificationId = 1;
        ansManagerStub.Cancel(notificationId, stringData, 0);
        ansManagerStub.CancelAll("");
        int32_t notificationIds = static_cast<int32_t>(GetU32Data(data));
        int32_t userId = static_cast<int32_t>(GetU32Data(data));
        ansManagerStub.CancelAsBundle(notificationIds, stringData, userId);
        uint8_t type = *data % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        ansManagerStub.AddSlotByType(slotType);
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        std::vector<sptr<Notification::NotificationSlot>> slots;
        slots.emplace_back(slot);
        ansManagerStub.AddSlots(slots);
        ansManagerStub.RemoveSlotByType(slotType);
        ansManagerStub.RemoveAllSlots();
        ansManagerStub.GetSlotByType(slotType, slot);
        ansManagerStub.GetSlots(slots);
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        uint64_t num = 1;
        ansManagerStub.GetSlotNumAsBundle(bundleOption, num);
        sptr<Notification::NotificationRequest> notificationer = new Notification::NotificationRequest();
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        notifications.emplace_back(notificationer);
        ansManagerStub.GetActiveNotifications(notifications, "");
        ansManagerStub.GetActiveNotificationNums(num);
        sptr<Notification::Notification> notificatione = new Notification::Notification();
        std::vector<sptr<Notification::Notification>> notificationes;
        notificationes.emplace_back(notificatione);
        ansManagerStub.GetAllActiveNotifications(notificationes);
        std::vector<std::string> key;
        key.emplace_back(stringData);
        ansManagerStub.GetSpecialActiveNotifications(key, notificationes);
        ansManagerStub.SetNotificationAgent(stringData);
        ansManagerStub.GetNotificationAgent(stringData);
        bool canPublish = *data % ENABLE;
        ansManagerStub.CanPublishAsBundle(stringData, canPublish);
        ansManagerStub.PublishAsBundle(notificationer, stringData);
        ansManagerStub.SetNotificationBadgeNum(notificationId);
        ansManagerStub.GetBundleImportance(notificationId);
        ansManagerStub.HasNotificationPolicyAccessPermission(canPublish);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
