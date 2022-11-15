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
#include "ansmanagerstub_fuzzer.h"
#include "notification_request.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        Notification::AnsManagerStub ansManagerStub;
        uint32_t code = GetU32Data(data);
        MessageParcel datas;
        MessageParcel reply;
        MessageOption flags;
        ansManagerStub.OnRemoteRequest(code, datas, reply, flags);
        ansManagerStub.HandlePublish(datas, reply);
        ansManagerStub.HandlePublishToDevice(datas, reply);
        ansManagerStub.HandleCancel(datas, reply);
        ansManagerStub.HandleCancelAll(datas, reply);
        ansManagerStub.HandleCancelAsBundle(datas, reply);
        ansManagerStub.HandleAddSlotByType(datas, reply);
        ansManagerStub.HandleAddSlots(datas, reply);
        ansManagerStub.HandleRemoveSlotByType(datas, reply);
        ansManagerStub.HandleRemoveAllSlots(datas, reply);
        ansManagerStub.HandleGetSlots(datas, reply);
        ansManagerStub.HandleGetSlotByType(datas, reply);
        ansManagerStub.HandleGetSlotNumAsBundle(datas, reply);
        ansManagerStub.HandleGetActiveNotifications(datas, reply);
        ansManagerStub.HandleGetActiveNotificationNums(datas, reply);
        ansManagerStub.HandleGetAllActiveNotifications(datas, reply);
        ansManagerStub.HandleGetSpecialActiveNotifications(datas, reply);
        ansManagerStub.HandleSetNotificationAgent(datas, reply);
        ansManagerStub.HandleGetNotificationAgent(datas, reply);
        ansManagerStub.HandleCanPublishAsBundle(datas, reply);
        ansManagerStub.HandlePublishAsBundle(datas, reply);
        ansManagerStub.HandleSetNotificationBadgeNum(datas, reply);
        ansManagerStub.HandleGetBundleImportance(datas, reply);
        ansManagerStub.HandleSetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleDoesSupportDoNotDisturbMode(datas, reply);
        ansManagerStub.HandlePublishContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleCancelContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleIsNotificationPolicyAccessGranted(datas, reply);
        ansManagerStub.HandleSetPrivateNotificationsAllowed(datas, reply);
        ansManagerStub.HandleGetPrivateNotificationsAllowed(datas, reply);
        ansManagerStub.HandleRemoveNotification(datas, reply);
        ansManagerStub.HandleRemoveAllNotifications(datas, reply);
        ansManagerStub.HandleDelete(datas, reply);
        ansManagerStub.HandleDeleteByBundle(datas, reply);
        ansManagerStub.HandleDeleteAll(datas, reply);
        ansManagerStub.HandleGetSlotsByBundle(datas, reply);
        ansManagerStub.HandleUpdateSlots(datas, reply);
        ansManagerStub.HandleRequestEnableNotification(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForBundle(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForAllBundles(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForSpecialBundle(datas, reply);
        ansManagerStub.HandleSetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabled(datas, reply);
        ansManagerStub.HandleSubscribe(datas, reply);
        ansManagerStub.HandleUnsubscribe(datas, reply);
        ansManagerStub.HandleAreNotificationsSuspended(datas, reply);
        ansManagerStub.HandleGetCurrentAppSorting(datas, reply);
        ansManagerStub.HandleIsAllowedNotify(datas, reply);
        ansManagerStub.HandleIsAllowedNotifySelf(datas, reply);
        ansManagerStub.HandleIsSpecialBundleAllowedNotify(datas, reply);
        ansManagerStub.HandleCancelGroup(datas, reply);
        ansManagerStub.HandleRemoveGroupByBundle(datas, reply);
        ansManagerStub.HandleIsDistributedEnabled(datas, reply);
        ansManagerStub.HandleEnableDistributed(datas, reply);
        ansManagerStub.HandleEnableDistributedByBundle(datas, reply);
        ansManagerStub.HandleEnableDistributedSelf(datas, reply);
        ansManagerStub.HandleIsDistributedEnableByBundle(datas, reply);
        ansManagerStub.HandleGetDeviceRemindType(datas, reply);
        ansManagerStub.HandleShellDump(datas, reply);
        ansManagerStub.HandlePublishReminder(datas, reply);
        ansManagerStub.HandleCancelReminder(datas, reply);
        ansManagerStub.HandleCancelAllReminders(datas, reply);
        ansManagerStub.HandleGetValidReminders(datas, reply);
        ansManagerStub.HandleIsSupportTemplate(datas, reply);
        ansManagerStub.HandleIsSpecialUserAllowedNotifyByUser(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledByUser(datas, reply);
        ansManagerStub.HandleDeleteAllByUser(datas, reply);
        ansManagerStub.HandleSetDoNotDisturbDateByUser(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDateByUser(datas, reply);
        ansManagerStub.HandleSetEnabledForBundleSlot(datas, reply);
        ansManagerStub.HandleGetEnabledForBundleSlot(datas, reply);
        ansManagerStub.HandleDistributedSetEnabledWithoutApp(datas, reply);
        ansManagerStub.HandleDistributedGetEnabledWithoutApp(datas, reply);
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        const std::string label = "this is a notification label";
        ansManagerStub.Publish(label, notification);
        const std::string deviceId = "this is a notification deviceId";
        ansManagerStub.PublishToDevice(notification, deviceId);
        int notificationId = 1;
        ansManagerStub.Cancel(notificationId, label);
        ansManagerStub.CancelAll();
        const std::string representativeBundle ="this is a notification representativeBundle";
        int32_t userId = 1;
        ansManagerStub.CancelAsBundle(notificationId, representativeBundle, userId);
        uint8_t type = *data % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        ansManagerStub.AddSlotByType(slotType);
        ansManagerStub.RemoveSlotByType(slotType);
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        ansManagerStub.GetSlotByType(slotType, slot);
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        uint64_t num = 1;
        ansManagerStub.GetSlotNumAsBundle(bundleOption, num);
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
