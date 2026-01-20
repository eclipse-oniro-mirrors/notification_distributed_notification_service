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
#include "ans_result_data_synchronizer.h"
#include "mock_notification_bundle_option.h"
#include "notification_request.h"
#include "notification_preferences.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {
namespace Notification {
    bool DoTestForAdvancedNotificationUtilsV1(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        service->GetNotificationSvrQueue();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        service->GetAppTargetBundle(bundleOption, targetBundleOption);

        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        std::string bundleName = ConsumePrintableString(fuzzData);
        std::vector<std::string> dumpInfo;
        int32_t creatorUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t recvUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t nid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t ownerId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        sptr<NotificationRequest> req = new NotificationRequest(nid);
        record->request = req;
        req->SetOwnerBundleName(bundleName);
        req->SetCreatorUserId(creatorUserId);
        req->SetReceiverUserId(recvUserId);
        req->SetSlotType(slotType);
        req->SetOwnerUid(uid);
        req->SetOwnerUserId(ownerId);
        record->notification = new Notification(req);
        service->notificationList_.push_back(record);

        auto recentNotification = std::make_shared<AdvancedNotificationService::RecentNotification>();
        recentNotification->isActive = true;
        recentNotification->notification = new Notification(req);
        service->recentInfo_->list.emplace_front(recentNotification);

        std::vector<std::string> keys;
        keys.push_back(recentNotification->notification->GetKey());
        keys.push_back(fuzzData->ConsumeRandomLengthString());
        service->OnRecoverLiveView(keys);

        service->GetLockScreenPictureFromDb(req);
        service->StartPublishDelayedNotificationTimeOut(ownerId, nid);
        service->UpdateRecordByOwner(record, false);
        service->HandleUpdateLiveViewNotificationTimer(uid, true);
        service->HandleUpdateLiveViewNotificationTimer(uid, false);
        return true;
    }

    bool DoTestForAdvancedNotificationUtilsV2(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        int64_t beginDate = fuzzData->ConsumeIntegralInRange<int64_t>(0, 10000);
        int64_t endDate = fuzzData->ConsumeIntegralInRange<int64_t>(10000, 100000);
        service->AdjustDateForDndTypeOnce(beginDate, endDate);

        int32_t userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->OnUserRemoved(userId);
        service->OnUserStopped(userId);
        service->DeleteAllByUserStopped(userId);

        std::string oldKey = fuzzData->ConsumeRandomLengthString();
        std::string oldKey1 = fuzzData->ConsumeRandomLengthString();
        NotificationPreferences::GetInstance()->SetKvToDb(oldKey, "1", 0);
        NotificationPreferences::GetInstance()->SetKvToDb(oldKey1, "1", 0);
        service->ResetDistributedEnabled();

        std::string bundleName = ConsumePrintableString(fuzzData);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        NotificationCloneBundleInfo cloneBundleInfo;
        cloneBundleInfo.SetBundleName(bundleName);
        cloneBundleInfo.SetUid(uid);
        cloneBundleInfo.SetIsShowBadge(true);
        cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        cloneBundleInfo.SetSlotFlags(fuzzData->ConsumeIntegralInRange<int32_t>(0, 100));
        NotificationCloneBundleInfo::SlotInfo info;
        info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
        info.enable_ = true;
        cloneBundleInfo.AddSlotInfo(info);
        service->UpdateCloneBundleInfo(cloneBundleInfo, userId);

        return true;
    }

    bool DoTestForAdvancedNotificationLiveView(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        sptr<AnsResultDataSynchronizerImpl> synchronizer =
            new AnsResultDataSynchronizerImpl();
        if (service->CancelPreparedNotification(0, "label", nullptr, 0,
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }

        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        sptr<NotificationBundleOption> bundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        request->SetNotificationId(fuzzData->ConsumeIntegral<int32_t>());
        auto record = service->MakeNotificationRecord(request, bundle);
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
        service->SetFinishTimer(record);
        service->SetUpdateTimer(record);
        service->StartArchiveTimer(record);

        std::string phoneNum = fuzzData->ConsumeRandomLengthString();
        std::string policy = fuzzData->ConsumeRandomLengthString();
        service->QueryContactByProfileId(phoneNum, policy, fuzzData->ConsumeIntegral<int32_t>());

        service->PublishSubscriberExistFlagEvent(fuzzData->ConsumeBool(), fuzzData->ConsumeBool());
        service->RemoveAllNotificationsByBundleName(ConsumePrintableString(fuzzData),
            fuzzData->ConsumeIntegral<int32_t>(), fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveAllNotificationsByBundleName("", 0, 0);

        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
        auto content = std::make_shared<NotificationContent>(liveContent);
        request->SetContent(content);
        service->UpdateNotificationTimerInfo(record);

        return true;
    }

    bool DoTestForAdvancedNotificationEnable(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string name = "com.easy.abroad";
        std::string bundleName = ConsumePrintableString(fuzzData);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);

        service->RequestEnableNotification(name, uid);
        service->RequestEnableNotification(bundleName, uid);

        sptr<NotificationDoNotDisturbDate> getDate = new NotificationDoNotDisturbDate();

        int64_t beginDate = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int64_t endDate = fuzzData->ConsumeIntegralInRange<int32_t>(100, 1000);
        NotificationConstant::DoNotDisturbType disturbType =
            NotificationConstant::DoNotDisturbType::DAILY;
        sptr<NotificationDoNotDisturbDate> date =
            new NotificationDoNotDisturbDate(disturbType, beginDate, endDate);

        service->SetDoNotDisturbDate(-1, date);
        service->SetDoNotDisturbDate(uid, date);

        service->GetDoNotDisturbDate(uid, getDate);
        service->GetDoNotDisturbDate(-1, getDate);

        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string deviceId = fuzzData->ConsumeRandomLengthString();
        int32_t operateType = fuzzData->ConsumeIntegralInRange<int32_t>(0, 2);
        std::vector<std::string> bundleList;
        std::vector<std::string> labelList;
        labelList.emplace_back(fuzzData->ConsumeRandomLengthString());
        bundleList.emplace_back(fuzzData->ConsumeRandomLengthString());
        service->SetTargetDeviceBundleList(deviceType, deviceId, operateType, bundleList, labelList);
        service->SetTargetDeviceSwitch(deviceType, deviceId,
            fuzzData->ConsumeBool(), fuzzData->ConsumeBool());

        bool enable = fuzzData->ConsumeBool();
        service->SetDistributedEnabled(deviceType, enable);
        service->IsDistributedEnabled(deviceType, enable);

        int32_t abilityId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->GetDistributedAbility(abilityId);

        bool isAuth = fuzzData->ConsumeBool();
        service->GetDistributedAuthStatus(deviceType, deviceId, uid, isAuth);
        service->SetDistributedAuthStatus(deviceType, deviceId, uid, isAuth);

        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<AdvancedNotificationService>();
        sptr<AnsResultDataSynchronizerImpl> synchronizer =
            new AnsResultDataSynchronizerImpl();
        service->InitPublishProcess();
        service->CreateDialogManager();
        DoTestForAdvancedNotificationUtilsV1(service, fuzzData);
        DoTestForAdvancedNotificationUtilsV2(service, fuzzData);
        DoTestForAdvancedNotificationLiveView(service, fuzzData);
        DoTestForAdvancedNotificationEnable(service, fuzzData);
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        sptr<NotificationRequest> notification = new NotificationRequest();
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<NotificationContent>(content));
        service->Publish(stringData, notification);
        int notificationId = fuzzData->ConsumeIntegral<int32_t>();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString());
        if (service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAll(fuzzData->ConsumeRandomLengthString());
        if (service->CancelAll(fuzzData->ConsumeRandomLengthString(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundle(notificationId, stringData, userId);
        if (service->CancelAsBundle(notificationId, stringData, userId,
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(type);
        service->AddSlotByType(slotType);
        std::vector<sptr<NotificationSlot>> slots;
        service->AddSlots(slots);
        service->RemoveSlotByType(slotType);
        service->RemoveAllSlots();
        sptr<NotificationSlot> slot = new NotificationSlot();
        service->GetSlotByType(slotType, slot);
        service->GetSlots(slots);
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationButtonOption> buttonOption = new NotificationButtonOption();
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<NotificationRequest>> notifications;
        if (service->GetActiveNotifications(fuzzData->ConsumeRandomLengthString(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetActiveNotificationNums(num);
        std::vector<sptr<Notification>> notificationss;
        service->GetActiveNotifications(notifications, fuzzData->ConsumeRandomLengthString());
        if (service->GetAllActiveNotifications(
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
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
        if (service->GetShowBadgeEnabledForBundle(bundleOption,
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetShowBadgeEnabled(enabled);
        if (service->GetShowBadgeEnabled(
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
        bool allowed = fuzzData->ConsumeBool();
        service->IsAllowedNotify(allowed);
        service->IsAllowedNotifySelf(bundleOption, allowed);
        service->IsAllowedNotifyForBundle(bundleOption, allowed);
        service->IsSpecialBundleAllowedNotify(bundleOption, allowed);
        service->CancelGroup(stringData, fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundle(bundleOption, stringData);
        sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
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
        sptr<NotificationRequest> request = new NotificationRequest();
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
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        service->SetBadgeNumber(badgeNum, fuzzData->ConsumeRandomLengthString());
        sptr<IAnsDialogCallback> dialogCallback = new AnsDialogCallbackProxy(nullptr);
        std::shared_ptr<NotificationUnifiedGroupInfo> groupInfo;
        bool enable = fuzzData->ConsumeBool();
        std::string bundleName = ConsumePrintableString(fuzzData);
        std::string phoneNumber = fuzzData->ConsumeRandomLengthString();
        std::string groupName = fuzzData->ConsumeRandomLengthString();
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string localSwitch = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<NotificationRecord>> recordList;
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
        if (service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->ExcuteDelete(stringData, fuzzData->ConsumeIntegral<int32_t>());
        service->HandleBadgeEnabledChanged(bundleOption, enabled);
        service->RemoveSystemLiveViewNotifications(bundleName,
            fuzzData->ConsumeIntegral<int32_t>(), fuzzData->ConsumeIntegral<int32_t>());
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

        DoTestForAdvancedNotificationUtils(service, fuzzData);
        DoTestForAdvancedNotificationService(service, fuzzData);
        return true;
    }

    bool DoTestForAdvancedNotificationUtils(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = nullptr;
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        request->SetContent(std::make_shared<NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<NotificationFlags>();
        request->SetFlags(flag);
        service->GetAppTargetBundle(bundleOption, targetBundleOption);
        std::vector<std::string> infos;
        infos.emplace_back(randomString);
        service->SetAgentNotification(request, randomString);
        service->OnBundleRemoved(bundleOption);
        service->OnBundleDataAdd(bundleOption);
        service->OnBundleDataUpdate(bundleOption);
        service->GetBundlesOfActiveUser();
        service->InitNotificationEnableList();
        std::shared_ptr<NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
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

    bool DoTestForAdvancedNotificationService(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = nullptr;
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        request->SetContent(std::make_shared<NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<NotificationFlags>();
        request->SetFlags(flag);
        std::shared_ptr<NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
        service->QueryDoNotDisturbProfile(randomInt32, randomString, randomString);
        service->CheckDoNotDisturbProfile(record);
        service->DoNotDisturbUpdataReminderFlags(record);
        service->UpdateSlotAuthInfo(record);
        service->Filter(record, fuzzData->ConsumeBool());
        service->ChangeNotificationByControlFlags(record, fuzzData->ConsumeBool());
        service->ChangeNotificationByControlFlagsFor3rdApp(record);
        service->CheckPublishPreparedNotification(record, fuzzData->ConsumeBool());
        service->UpdateInNotificationList(record);
        service->PublishInNotificationList(record);
        service->IsNeedPushCheck(request);
        return true;
    }
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
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
