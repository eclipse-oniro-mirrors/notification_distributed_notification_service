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
#include "notification_helper.h"
#undef private
#undef protected
#include "notificationhelper_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "ans_permission_def.h"
#include "notification_subscriber.h"
#include "notification_button_option.h"
#include "mock_notification_subscribe_info.h"
#include "ans_dialog_host_client.h"
#include "mock_notification_donotdisturb_profile.h"
#include "notification_disable.h"
#include "mock_notification_operation_info.h"

namespace OHOS {
namespace Notification {

class FuzzNotificationSubscriber : public NotificationSubscriber {
public:
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnConnected() override
    {}
    void OnEnabledNotificationChanged(const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
 
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
};

class FuzzTestLocalLiveViewSubscriber : public NotificationLocalLiveViewSubscriber {
public:
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) override
    {}
};

    bool TestPublishAndRemove(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t intData = fdp->ConsumeIntegral<int32_t>();
        
        std::string representativeBundle = stringData;
        NotificationRequest notification;
        notification.SetOwnerUid(intData);
        notification.SetCreatorUid(intData);
        notification.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        notification.SetContent(std::make_shared<NotificationContent>(content));
        notificationHelper.PublishNotificationAsBundle(representativeBundle, notification);
        notificationHelper.RemoveNotifications();
        std::vector<std::string> hashCodes;
        hashCodes.emplace_back(fdp->ConsumeRandomLengthString());
        notificationHelper.RemoveNotifications(hashCodes, fdp->ConsumeIntegral<int32_t>());

        return true;
    }

    bool TestBundleOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t intData = fdp->ConsumeIntegral<int32_t>();
        
        bool enabled = fdp->ConsumeBool();
        notificationHelper.SetNotificationsEnabledForAllBundles(stringData, enabled);
        
        NotificationBundleOption bundleOption;
        bundleOption.SetBundleName(stringData);
        bundleOption.SetUid(intData);
        
        uint32_t flag = 0;
        notificationHelper.GetNotificationSlotFlagsAsBundle(bundleOption, flag);
        notificationHelper.SetNotificationSlotFlagsAsBundle(bundleOption, intData);
        notificationHelper.CancelAsBundle(bundleOption, intData);
        NotificationButtonOption buttonOption;
        notificationHelper.TriggerLocalLiveView(bundleOption, fdp->ConsumeIntegral<int32_t>(), buttonOption);
        return true;
    }

    bool TestNotificationSettings(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        uint32_t slotFlags = fdp->ConsumeIntegral<uint32_t>();
        notificationHelper.GetNotificationSettings(slotFlags);
        
        NotificationRequest notification;
        notificationHelper.PublishNotificationForIndirectProxy(notification);
        
        bool canPop = fdp->ConsumeBool();

        std::string stringData = fdp->ConsumeRandomLengthString();
        sptr<AnsDialogHostClient> client = nullptr;
        AnsDialogHostClient::CreateIfNullptr(client);
        client = AnsDialogHostClient::GetInstance();
        notificationHelper.CanPopEnableNotificationDialog(client, canPop, stringData);
        notificationHelper.RemoveEnableNotificationDialog();
        int32_t uid = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        notificationHelper.RequestEnableNotification(stringData, uid);
        sptr<IRemoteObject> callerToken = nullptr;
        sptr<NotificationCheckRequest> notificationCheckRequest =
            new NotificationCheckRequest();
        notificationHelper.RegisterPushCallback(callerToken, notificationCheckRequest);
        notificationHelper.UnregisterPushCallback();
        return true;
    }

    bool TestSubscriptionOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        FuzzNotificationSubscriber fuzzNotificationSub;
        std::shared_ptr<NotificationSubscriber> fuzzNotificationSubSptr =
            std::make_shared<FuzzNotificationSubscriber>();
        
        notificationHelper.SubscribeNotification(fuzzNotificationSub);
        notificationHelper.SubscribeNotification(fuzzNotificationSubSptr);
        notificationHelper.SubscribeNotificationSelf(fuzzNotificationSub);
        notificationHelper.SubscribeNotificationSelf(fuzzNotificationSubSptr);
        
        FuzzTestLocalLiveViewSubscriber fuzzLocalLiveViewSubscriber;
        notificationHelper.SubscribeLocalLiveViewNotification(fuzzLocalLiveViewSubscriber, fdp->ConsumeBool());
        
        sptr<NotificationSubscribeInfo> fuzzNotificationSubInfoSptr =
            ObjectBuilder<NotificationSubscribeInfo>::Build(fdp);
        notificationHelper.SubscribeNotification(fuzzNotificationSubSptr, fuzzNotificationSubInfoSptr);
        
        notificationHelper.UnSubscribeNotification(fuzzNotificationSub);
        notificationHelper.UnSubscribeNotification(fuzzNotificationSubSptr);
        notificationHelper.UnSubscribeNotification(fuzzNotificationSubSptr, fuzzNotificationSubInfoSptr);
        return true;
    }

    bool TestSlotConfiguration(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        NotificationBundleOption bundleOption;
        constexpr uint8_t SLOT_LEVEL_NUM = 6;
        constexpr uint8_t SLOT_VISIBLENESS_TYPE_NUM = 4;
        constexpr uint8_t SLOT_TYPE_NUM = 5;
        
        sptr<NotificationSlot> slot = new NotificationSlot();
        slot->SetDescription(fdp->ConsumeRandomLengthString());
        slot->SetEnableLight(fdp->ConsumeBool());
        slot->SetEnableVibration(fdp->ConsumeBool());
        slot->SetLedLightColor(fdp->ConsumeIntegral<uint32_t>());
        
        uint8_t level = fdp->ConsumeIntegral<uint8_t>() % SLOT_LEVEL_NUM;
        slot->SetLevel(NotificationSlot::NotificationLevel(level));
        
        uint8_t visibleness = fdp->ConsumeIntegral<uint8_t>() % SLOT_VISIBLENESS_TYPE_NUM;
        slot->SetLockscreenVisibleness(NotificationConstant::VisiblenessType(visibleness));
        
        uint8_t type = fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(type);
        slot->SetType(slotType);
        
        std::vector<NotificationSlot> slots;
        slots.emplace_back(*slot);
        
        notificationHelper.GetNotificationSlotForBundle(bundleOption, slotType, slot);
        
        std::vector<sptr<Notification>> notifications;
        notificationHelper.GetAllNotificationsBySlotType(notifications, slotType);
        return true;
    }

    bool TestDoNotDisturb(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
        size_t numProfiles = fdp->ConsumeIntegralInRange<size_t>(1, 6);
        for (size_t i = 0; i < numProfiles; ++i) {
            sptr<NotificationDoNotDisturbProfile> profile =
                ObjectBuilder<NotificationDoNotDisturbProfile>::Build(fdp);
            profiles.push_back(profile);
        }
        notificationHelper.AddDoNotDisturbProfiles(profiles);
        notificationHelper.RemoveDoNotDisturbProfiles(profiles);
        
        notificationHelper.IsNeedSilentInDoNotDisturbMode(fdp->ConsumeRandomLengthString(),
            fdp->ConsumeIntegral<int32_t>());
        return true;
    }

    bool TestBadgeOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        NotificationBundleOption bundleOption;
        bool enabled = fdp->ConsumeBool();
        int32_t uid = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        notificationHelper.SetNotificationsEnabledForAllBundles(uid, enabled);
        
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(fdp->ConsumeIntegral<uint8_t>() % 5);
        notificationHelper.GetEnabledForBundleSlotSelf(slotType, enabled);
        
        int32_t badgeNumber = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        std::string bundleName = fdp->ConsumeRandomLengthString();
        notificationHelper.SetBadgeNumber(badgeNumber, bundleName);
        notificationHelper.SetBadgeNumberByBundle(bundleOption, badgeNumber);
        notificationHelper.SetBadgeNumberForDhByBundle(bundleOption, badgeNumber);
        
        std::vector<NotificationBundleOption> bundleOptions;
        bundleOptions.push_back(bundleOption);
        notificationHelper.GetAllNotificationEnabledBundles(bundleOptions);
        return true;
    }

    bool TestDistributedOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        NotificationBundleOption bundleOption;
        std::string deviceType = fdp->ConsumeRandomLengthString();
        std::string deviceId = fdp->ConsumeRandomLengthString();
        bool enabled = fdp->ConsumeBool();
        int32_t uid = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        
        notificationHelper.SetDistributedEnabledByBundle(bundleOption, deviceType, enabled);
        notificationHelper.IsDistributedEnabledByBundle(bundleOption, deviceType, enabled);
        notificationHelper.SetDistributedEnabled(deviceType, enabled);
        notificationHelper.IsDistributedEnabled(deviceType, enabled);
        
        int32_t abilityId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        notificationHelper.GetDistributedAbility(abilityId);
        
        bool isAuth = fdp->ConsumeBool();
        notificationHelper.GetDistributedAuthStatus(deviceType, deviceId, uid, isAuth);
        notificationHelper.SetDistributedAuthStatus(deviceType, deviceId, uid, isAuth);
        
        notificationHelper.SetSmartReminderEnabled(deviceType, enabled);
        notificationHelper.IsSmartReminderEnabled(deviceType, enabled);
        
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(fdp->ConsumeIntegral<uint8_t>() % 5);
        notificationHelper.SetDistributedEnabledBySlot(slotType, deviceType, enabled);
        notificationHelper.IsDistributedEnabledBySlot(slotType, deviceType, enabled);
        notificationHelper.CancelAsBundleWithAgent(bundleOption, uid);
        notificationHelper.SetHashCodeRule(fdp->ConsumeIntegral<uint32_t>());
        return true;
    }

    bool TestAdvancedOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        std::string key = fdp->ConsumeRandomLengthString();
        std::string val = fdp->ConsumeRandomLengthString();
        notificationHelper.SetAdditionConfig(key, val);
        
        std::string deviceType = fdp->ConsumeRandomLengthString();
        std::string deviceId = fdp->ConsumeRandomLengthString();
        uint32_t status = fdp->ConsumeIntegral<uint32_t>();
        uint32_t controlFlag = fdp->ConsumeIntegral<uint32_t>();
        int32_t uid = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        
        notificationHelper.SetTargetDeviceStatus(deviceType, status, deviceId);
        notificationHelper.SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, uid);
        
        int32_t operateType = fdp->ConsumeIntegralInRange<int32_t>(0, 2);
        std::vector<std::string> bundleList;
        bundleList.emplace_back(fdp->ConsumeRandomLengthString());
        notificationHelper.SetTargetDeviceBundleList(deviceType, deviceId, operateType, bundleList);
        
        notificationHelper.SetTargetDeviceSwitch(deviceType, deviceId,
            fdp->ConsumeBool(), fdp->ConsumeBool());
        notificationHelper.GetTargetDeviceBundleList(deviceType, deviceId, bundleList);

        int32_t targetUserId;
        std::string targetDeviceId;
        notificationHelper.GetMutilDeviceStatus(deviceType, controlFlag, targetDeviceId, targetUserId);

        sptr<NotificationDoNotDisturbProfile> disturbProfile =
            ObjectBuilder<NotificationDoNotDisturbProfile>::Build(fdp);
        notificationHelper.GetDoNotDisturbProfile(uid, disturbProfile);
        
        sptr<NotificationOperationInfo> operationInfo = ObjectBuilder<NotificationOperationInfo>::Build(fdp);
        notificationHelper.DistributeOperation(operationInfo, nullptr);
        
        std::string hashCode = fdp->ConsumeRandomLengthString();
        sptr<NotificationRequest> notificationRequest;
        LiveViewFilter filter;
        notificationHelper.GetNotificationRequestByHashCode(hashCode, notificationRequest);
        notificationHelper.GetActiveNotificationByFilter(filter, notificationRequest);
        
        int32_t result = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        notificationHelper.ReplyDistributeOperation(hashCode, result);
        
        bool isPaused = fdp->ConsumeBool();
        notificationHelper.UpdateNotificationTimerByUid(uid, isPaused);
        
        NotificationDisable notificationDisable;
        notificationHelper.DisableNotificationFeature(notificationDisable);
        
        std::string bundleName = fdp->ConsumeRandomLengthString();
        bool isAllowUseReminder = fdp->ConsumeBool();
        notificationHelper.AllowUseReminder(bundleName, isAllowUseReminder);
        
        std::vector<NotificationBundleOption> bundleOptions;
        notificationHelper.GetAllLiveViewEnabledBundles(bundleOptions);
        notificationHelper.GetAllDistribuedEnabledBundles(deviceType, bundleOptions);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        NotificationHelper notificationHelper;

        TestPublishAndRemove(fdp, notificationHelper);
        TestBundleOperations(fdp, notificationHelper);
        TestNotificationSettings(fdp, notificationHelper);
        TestSubscriptionOperations(fdp, notificationHelper);
        TestSlotConfiguration(fdp, notificationHelper);
        TestDoNotDisturb(fdp, notificationHelper);
        TestBadgeOperations(fdp, notificationHelper);
        TestDistributedOperations(fdp, notificationHelper);
        TestAdvancedOperations(fdp, notificationHelper);

        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
