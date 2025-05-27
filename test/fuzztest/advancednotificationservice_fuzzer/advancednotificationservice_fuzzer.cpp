/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "notification_live_view_content.h"
#include "notification_record.h"
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "advancednotificationservice_fuzzer.h"
#include "ans_dialog_callback_proxy.h"
#include "ans_subscriber_stub.h"
#include "ans_permission_def.h"
#include "notification_request.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<Notification::AdvancedNotificationService>();
        service->InitPublishProcess();
        service->CreateDialogManager();
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<Notification::NotificationContent>(content));
        service->Publish(stringData, notification);
        int notificationId = fuzzData->ConsumeIntegral<int32_t>();
        service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString());
        service->CancelAll(fuzzData->ConsumeRandomLengthString());
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        service->CancelAsBundle(notificationId, stringData, userId);
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        service->AddSlotByType(slotType);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        service->AddSlots(slots);
        service->RemoveSlotByType(slotType);
        service->RemoveAllSlots();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        service->GetSlotByType(slotType, slot);
        service->GetSlots(slots);
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        sptr<Notification::NotificationButtonOption> buttonOption = new Notification::NotificationButtonOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        service->GetActiveNotifications(notifications, fuzzData->ConsumeRandomLengthString());
        service->GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        service->GetAllActiveNotifications(notificationss);
        std::vector<std::string> key;
        service->GetSpecialActiveNotifications(key, notificationss);
        bool canPublish = fuzzData->ConsumeBool();
        service->CanPublishAsBundle(stringData, canPublish);
        service->PublishAsBundle(notification, stringData);
        service->SetNotificationBadgeNum(num);
        int importance = fuzzData->ConsumeIntegral<int32_t>();
        service->GetBundleImportance(importance);
        bool granted = fuzzData->ConsumeBool();
        service->HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = fuzzData->ConsumeIntegral<int32_t>();
        service->RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        service->RemoveAllNotifications(bundleOption);
        service->Delete(stringData, removeReason);
        service->DeleteByBundle(bundleOption);
        service->DeleteAll();
        service->GetSlotsByBundle(bundleOption, slots);
        service->UpdateSlots(bundleOption, slots);
        bool enabled = fuzzData->ConsumeBool();
        service->SetNotificationsEnabledForBundle(stringData, enabled);
        service->SetNotificationsEnabledForAllBundles(stringData, enabled);
        service->SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        service->SetShowBadgeEnabledForBundle(bundleOption, enabled);
        service->GetShowBadgeEnabledForBundle(bundleOption, enabled);
        service->GetShowBadgeEnabled(enabled);
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();
        bool allowed = fuzzData->ConsumeBool();
        service->IsAllowedNotify(allowed);
        service->IsAllowedNotifySelf(bundleOption, allowed);
        service->IsAllowedNotifyForBundle(bundleOption, allowed);
        service->IsSpecialBundleAllowedNotify(bundleOption, allowed);
        service->CancelGroup(stringData, fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundle(bundleOption, stringData);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        service->SetDoNotDisturbDate(date);
        service->GetDoNotDisturbDate(date);
        bool doesSupport = fuzzData->ConsumeBool();
        service->DoesSupportDoNotDisturbMode(doesSupport);
        service->IsDistributedEnabled(enabled);
        service->EnableDistributedByBundle(bundleOption, enabled);
        service->EnableDistributedSelf(enabled);
        service->EnableDistributed(enabled);
        service->IsDistributedEnableByBundle(bundleOption, enabled);
        int32_t remindType;
        service->GetDeviceRemindType(remindType);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        service->PublishContinuousTaskNotification(request);
        service->CancelContinuousTaskNotification(stringData, notificationId);
        bool support = fuzzData->ConsumeBool();
        service->IsSupportTemplate(stringData, support);
        service->IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = fuzzData->ConsumeIntegral<int32_t>();
        service->SetNotificationsEnabledByUser(deviceIds, enabled);
        service->DeleteAllByUser(userId);
        service->SetDoNotDisturbDate(date);
        service->GetDoNotDisturbDate(date);
        service->SetEnabledForBundleSlot(bundleOption, slotType, enabled, false);
        service->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        std::vector<std::string> dumpInfo;
        service->ShellDump(stringData, stringData, userId, userId, dumpInfo);
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        service->SetBadgeNumber(badgeNum, fuzzData->ConsumeRandomLengthString());
        sptr<Notification::IAnsDialogCallback> dialogCallback = new Notification::AnsDialogCallbackProxy(nullptr);
        std::shared_ptr<Notification::NotificationUnifiedGroupInfo> groupInfo;
        bool enable = fuzzData->ConsumeBool();
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        std::string phoneNumber = fuzzData->ConsumeRandomLengthString();
        std::string groupName = fuzzData->ConsumeRandomLengthString();
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string localSwitch = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<Notification::NotificationRecord>> recordList;
        bool isNative = fuzzData->ConsumeBool();
        service->CanPopEnableNotificationDialog(nullptr, enable, bundleName);
        std::vector<std::string> keys;
        std::string key1 = fuzzData->ConsumeRandomLengthString();
        keys.emplace_back(fuzzData->ConsumeRandomLengthString());
        service->RemoveNotifications(keys, fuzzData->ConsumeIntegral<int32_t>());
        service->SetBadgeNumberByBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->SetDistributedEnabledByBundle(bundleOption, fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeBool());
        service->IsDistributedEnableByBundle(bundleOption, enable);
        service->SetDefaultNotificationEnabled(bundleOption, enabled);
        service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->ExcuteDelete(stringData, fuzzData->ConsumeIntegral<int32_t>());
        service->HandleBadgeEnabledChanged(bundleOption, enabled);
        service->RemoveSystemLiveViewNotifications(bundleName, fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveSystemLiveViewNotificationsOfSa(fuzzData->ConsumeIntegral<int32_t>());
        service->TriggerLocalLiveView(bundleOption, fuzzData->ConsumeIntegral<int32_t>(), buttonOption);
        service->RemoveNotificationBySlot(bundleOption, slot, fuzzData->ConsumeIntegral<int32_t>());
        service->IsNeedSilentInDoNotDisturbMode(phoneNumber, fuzzData->ConsumeIntegral<int32_t>());
        service->CheckNeedSilent(phoneNumber, fuzzData->ConsumeIntegral<int32_t>(),
            fuzzData->ConsumeIntegral<int32_t>());
        service->ExcuteCancelGroupCancel(bundleOption, groupName, fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveNotificationFromRecordList(recordList);
        service->UpdateUnifiedGroupInfo(key1, groupInfo);
        service->PublishNotificationBySa(request);
        service->IsDistributedEnabledByBundle(bundleOption, deviceType, enabled);
        service->DuplicateMsgControl(request);
        service->DeleteDuplicateMsgs(bundleOption);
        service->RemoveExpiredUniqueKey();
        service->SetSmartReminderEnabled(deviceType, enabled);
        service->IsSmartReminderEnabled(deviceType, enabled);
        service->SetTargetDeviceStatus(deviceType, fuzzData->ConsumeIntegral<int32_t>(), "");
        service->ClearAllNotificationGroupInfo(localSwitch);
        service->IsDistributedEnabledBySlot(slotType, deviceType, enabled);

        OHOS::DoTestForAdvancedNotificationUtils(service, fuzzData);
        OHOS::DoTestForAdvancedNotificationService(service, fuzzData);
        return true;
    }

    bool DoTestForAdvancedNotificationUtils(std::shared_ptr<Notification::AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(randomString);
        bundleOption->SetUid(randomInt32);
        sptr<Notification::NotificationBundleOption> targetBundleOption = nullptr;
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        request->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        request->SetContent(std::make_shared<Notification::NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<Notification::NotificationFlags>();
        request->SetFlags(flag);
        service->GetAppTargetBundle(bundleOption, targetBundleOption);
        std::vector<std::string> infos;
        infos.emplace_back(randomString);
        service->SetAgentNotification(request, randomString);
        service->ActiveNotificationDump(randomString, randomInt32, randomInt32, infos);
        service->RecentNotificationDump(randomString, randomInt32, randomInt32, infos);
        service->OnBundleRemoved(bundleOption);
        service->OnBundleDataAdd(bundleOption);
        service->OnBundleDataUpdate(bundleOption);
        service->GetBundlesOfActiveUser();
        service->InitNotificationEnableList();
        std::shared_ptr<Notification::NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new Notification::NotificationSlot(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        service->PrePublishNotificationBySa(request, randomInt32, randomString);
        service->SetRequestBundleInfo(request, randomInt32, randomString);
        service->OnResourceRemove(randomInt32);
        service->CheckApiCompatibility(bundleOption);
        service->OnBundleDataCleared(bundleOption);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        service->CheckPublishWithoutApp(randomInt32, request);
        service->GetLocalNotificationKeys(bundleOption);
        service->OnDistributedPublish(randomString, randomString, request);
        service->OnDistributedUpdate(randomString, randomString, request);
        service->OnDistributedDelete(randomString, randomString, randomString, randomInt32);
#endif
        return true;
    }

    bool DoTestForAdvancedNotificationService(std::shared_ptr<Notification::AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(randomString);
        bundleOption->SetUid(randomInt32);
        sptr<Notification::NotificationBundleOption> targetBundleOption = nullptr;
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        request->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        request->SetContent(std::make_shared<Notification::NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<Notification::NotificationFlags>();
        request->SetFlags(flag);
        std::shared_ptr<Notification::NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new Notification::NotificationSlot(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        service->PublishPreparedNotification(request, bundleOption, fuzzData->ConsumeBool());
        service->QueryDoNotDisturbProfile(randomInt32, randomString, randomString);
        service->CheckDoNotDisturbProfile(record);
        service->DoNotDisturbUpdataReminderFlags(record);
        service->UpdateSlotAuthInfo(record);
        service->Filter(record, fuzzData->ConsumeBool());
        service->ChangeNotificationByControlFlags(record, fuzzData->ConsumeBool());
        service->CheckPublishPreparedNotification(record, fuzzData->ConsumeBool());
        service->UpdateInNotificationList(record);
        service->PublishInNotificationList(record);
        service->IsNeedPushCheck(request);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
