/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <thread>
#include <chrono>
#include "ans_subscriber_listener.h"
#include "notificationframeworks_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "ans_permission_def.h"
#include "notification_subscriber.h"
#include "notification_sorting_map.h"
#include "notification_do_not_disturb_date.h"
#include "mock_notification_operation_info.h"
#include "notification.h"
#include "ans_notification.h"
#include "notification_button_option.h"

namespace OHOS {
namespace Notification {
class FuzzTestSubscriber : public NotificationSubscriber {
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

    bool TestSubscribeListener(FuzzedDataProvider* fdp)
    {
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        std::string str = fdp->ConsumeRandomLengthString();

        std::shared_ptr<NotificationSubscriber> testSubscriber = std::make_shared<FuzzTestSubscriber>();
        sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(testSubscriber);
        listener->OnDisconnected();

        sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest();
        sptr<Notification> notification = new (std::nothrow) Notification(req);
        sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
        listener->OnConsumed(notification, notificationMap);
        listener->OnConsumed(notification);

        std::vector<sptr<Notification>> notifications;
        notifications.emplace_back(notification);
        listener->OnConsumedList(notifications, notificationMap);

        listener->OnCanceled(notification, notificationMap, id);
        listener->OnCanceled(notification, nullptr, id);
        listener->OnCanceled(notification, id);
        listener->OnCanceledList(notifications, notificationMap, id);
        listener->OnCanceledList(notifications, id);
        listener->OnUpdated(notificationMap);

        sptr<NotificationDoNotDisturbDate> date = new (std::nothrow) NotificationDoNotDisturbDate();
        listener->OnDoNotDisturbDateChange(date);

        sptr<EnabledNotificationCallbackData> callback = new (std::nothrow) EnabledNotificationCallbackData();
        listener->OnEnabledNotificationChanged(callback);
        listener->OnBadgeEnabledChanged(callback);

        sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData();
        listener->OnBadgeChanged(badgeData);

        sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
        listener->OnOperationResponse(operationInfo, id);

        listener->OnApplicationInfoNeedChanged(str);
        return true;
    }

    bool TestAnsNotification(FuzzedDataProvider* fdp)
    {
        constexpr uint8_t slotTypeNum = 5;
        AnsNotification ans;
        NotificationBundleOption bundle;
        std::string str = fdp->ConsumeRandomLengthString();
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        bundle.SetBundleName(str);
        bundle.SetUid(id);
        int32_t id2 = fdp->ConsumeIntegral<int32_t>();
        uint32_t num = fdp->ConsumeIntegralInRange<uint32_t>(0, 100);
        NotificationRequest req;
        NotificationButtonOption button;
        std::vector<std::string> strs;
        strs.emplace_back(str);

        ans.GetNotificationSlotFlagsAsBundle(bundle, num);
        ans.GetNotificationSettings(num);
        ans.SetNotificationSlotFlagsAsBundle(bundle, num);

        ans.CancelAsBundle(id, str, id2);
        ans.PublishNotificationAsBundle(str, req);
        ans.RemoveEnableNotificationDialog();
        ans.RequestEnableNotification(str, id);

        FuzzTestSubscriber subscriber;
        auto info = NotificationSubscribeInfo();
        ans.SubscribeNotificationSelf(subscriber);
        ans.UnSubscribeNotification(subscriber);
        ans.SubscribeNotification(subscriber, info);
        ans.UnSubscribeNotification(subscriber, info);

        std::shared_ptr<FuzzTestSubscriber> subscriberPtr = std::make_shared<FuzzTestSubscriber>();
        sptr<NotificationSubscribeInfo> infoPtr = new (std::nothrow) NotificationSubscribeInfo();
        ans.SubscribeNotification(subscriberPtr, infoPtr);
        ans.UnSubscribeNotification(subscriberPtr, infoPtr);
        ans.SubscribeNotification(subscriberPtr);
        ans.UnSubscribeNotification(subscriberPtr);
        ans.SubscribeNotificationSelf(subscriberPtr);
        ans.UnSubscribeNotification(subscriberPtr);

        ans.TriggerLocalLiveView(bundle, id, button);

        ans.RemoveNotifications(strs, id);
        ans.RemoveNotifications();

        uint8_t type = fdp->ConsumeIntegral<uint8_t>() % slotTypeNum;
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(type);
        sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
        ans.GetNotificationSlotForBundle(bundle, slotType, slot);
        bool enabled = fdp->ConsumeBool();
        ans.GetEnabledForBundleSlotSelf(slotType, enabled);
        ans.SetDistributedEnabledBySlot(slotType, str, enabled);
        ans.IsDistributedEnabledBySlot(slotType, str, enabled);
        ans.SetDefaultSlotForBundle(bundle, slotType, enabled, enabled);

        return true;
    }

    bool TestAnsNotification2(FuzzedDataProvider* fdp)
    {
        AnsNotification ans;
        NotificationBundleOption bundle;
        std::string str = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        bundle.SetBundleName(str);
        bundle.SetUid(id);
        std::vector<NotificationBundleOption> bundles;
        bundles.emplace_back(bundle);
        bool enabled = fdp->ConsumeBool();
        DistributedBundleOption distriBundle;
        std::vector<DistributedBundleOption> distriBundles;
        distriBundles.emplace_back(distriBundle);

        ans.GetShowBadgeEnabledForBundle(bundle, enabled);
        std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
        ans.GetShowBadgeEnabledForBundles(bundles, bundleEnable);
        std::vector<NotificationBundleOption> trustlist;
        std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
        ans.AddDoNotDisturbProfiles(profiles);
        ans.RemoveDoNotDisturbProfiles(profiles);
        sptr<NotificationDoNotDisturbProfile> disturbProfile =
            new (std::nothrow) NotificationDoNotDisturbProfile(id, str, trustlist);
        profiles.emplace_back(disturbProfile);
        ans.AddDoNotDisturbProfiles(profiles);
        ans.RemoveDoNotDisturbProfiles(profiles);
        ans.IsNeedSilentInDoNotDisturbMode(str, id);
        ans.SetNotificationsEnabledForAllBundles(str, enabled);
        ans.SetBadgeNumberByBundle(bundle, num);
        ans.SetBadgeNumberForDhByBundle(bundle, num);

        ans.GetAllNotificationEnabledBundles(bundles);
        ans.SetAdditionConfig(str, str2);
        ans.SetDistributedEnabledByBundle(bundle, str, enabled);
        ans.SetDistributedBundleOption(distriBundles, str);
        ans.IsDistributedEnabled(str, enabled);
        return true;
    }

    bool TestAnsNotification3(FuzzedDataProvider* fdp)
    {
        AnsNotification ans;
        NotificationBundleOption bundle;
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        std::vector<int32_t> nums;
        nums.emplace_back(num);
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        std::string str = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::string str3 = fdp->ConsumeRandomLengthString();
        bool enabled = fdp->ConsumeBool();
        bundle.SetBundleName(str);
        bundle.SetUid(id);
        uint32_t status = fdp->ConsumeIntegral<uint32_t>();
        std::vector<std::string> strs;
        strs.emplace_back(str);
        strs.emplace_back(str2);
        std::vector<NotificationBundleOption> bundles;
        bundles.emplace_back(bundle);

        ans.GetDistributedAbility(num);
        ans.GetDistributedAuthStatus(str, str2, id, enabled);
        ans.SetDistributedAuthStatus(str, str2, id, enabled);
        ans.UpdateDistributedDeviceList(str);
        ans.IsDistributedEnabledByBundle(bundle, str, enabled);
        ans.SetSilentReminderEnabled(bundle, enabled);
        ans.IsSilentReminderEnabled(bundle, num);
        ans.SetSmartReminderEnabled(str, enabled);
        ans.CancelAsBundleWithAgent(bundle, id);
        ans.IsSmartReminderEnabled(str, enabled);
        ans.SetTargetDeviceStatus(str, status, str2);
        ans.SetTargetDeviceStatus(str, status, status, str2, id);
        ans.SetTargetDeviceBundleList(str, str2, num, strs, strs);
        ans.GetMutilDeviceStatus(str, status, str2, num);
        ans.GetTargetDeviceBundleList(str, str2, strs, strs);
        ans.SetTargetDeviceSwitch(str, str2, enabled, enabled);
        ans.GetTargetDeviceStatus(str, num);
        ans.AllowUseReminder(str, enabled);
        ans.SetCheckConfig(num, str, str2, str3);
        ans.GetLiveViewConfig(strs);
        ans.UpdateNotificationTimerByUid(id, enabled);

        NotificationDisable notificationDisable;
        ans.DisableNotificationFeature(notificationDisable);
        ans.GetAllLiveViewEnabledBundles(bundles);
        ans.GetAllDistribuedEnabledBundles(str, bundles);
        ans.ReplyDistributeOperation(str, num);
        ans.SetHashCodeRule(status);
        ans.GetDistributedDevicelist(strs);
        ans.ProxyForUnaware(nums, enabled);
        return true;
    }

    bool TestAnsNotification4(FuzzedDataProvider* fdp)
    {
        AnsNotification ans;
        NotificationBundleOption bundle;
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        std::string str = fdp->ConsumeRandomLengthString();
        bundle.SetBundleName(str);
        bundle.SetUid(id);
        std::vector<NotificationBundleOption> bundles;
        std::vector<sptr<NotificationBundleOption>> bundlesPtr;
        bool enabled = fdp->ConsumeBool();

        NotificationRingtoneInfo ringtoneInfo;
        ans.SetRingtoneInfoByBundle(bundle, ringtoneInfo);
        ans.GetRingtoneInfoByBundle(bundle, ringtoneInfo);

        NotificationReminderInfo reminder;
        std::vector<NotificationReminderInfo> reminders;
        reminders.emplace_back(reminder);
        ans.GetReminderInfoByBundles(bundles, reminders);
        ans.SetReminderInfoByBundles(reminders);

        sptr<NotificationExtensionSubscriptionInfo> info =
            new (std::nothrow) NotificationExtensionSubscriptionInfo();
        std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
        infos.emplace_back(info);
        ans.NotificationExtensionSubscribe(infos);
        ans.NotificationExtensionUnsubscribe();
        ans.GetSubscribeInfo(infos);
        ans.IsUserGranted(enabled);
        ans.GetUserGrantedState(bundle, enabled);
        ans.SetUserGrantedState(bundle, enabled);
        ans.GetUserGrantedEnabledBundles(bundle, bundlesPtr);
        ans.GetUserGrantedEnabledBundlesForSelf(bundlesPtr);
        ans.SetUserGrantedBundleState(bundle, bundlesPtr, enabled);
        ans.GetAllSubscriptionBundles(bundlesPtr);
        ans.CanOpenSubscribeSettings();

        return true;
    }

    bool TestAnsNotification5(FuzzedDataProvider* fdp)
    {
        NotificationConstant::SubscribeType type = NotificationConstant::SubscribeType::BLUETOOTH;
        std::string str = fdp->ConsumeRandomLengthString();
        bool enabled = fdp->ConsumeBool();

        auto subscriptionInfo = std::make_shared<NotificationExtensionSubscriptionInfo>(str, type);
        subscriptionInfo->SetAddr(str);
        subscriptionInfo->GetAddr();

        subscriptionInfo->SetType(type);
        subscriptionInfo->GetType();

        subscriptionInfo->SetHfp(enabled);
        subscriptionInfo->IsHfp();

        subscriptionInfo->Dump();

        std::string addr = fdp->ConsumeRandomLengthString();
        nlohmann::json jsonObject = nlohmann::json{{"addr", addr}, {"isHfp", enabled}, {"type", 0}};
        sptr<NotificationExtensionSubscriptionInfo> subscriptionInfo2 =
            NotificationExtensionSubscriptionInfo::FromJson(jsonObject);
        subscriptionInfo2->ToJson(jsonObject);

        Parcel parcel;
        subscriptionInfo->Marshalling(parcel);
        subscriptionInfo->Unmarshalling(parcel);

        return true;
    }

    bool TestAnsNotification6(FuzzedDataProvider* fdp)
    {
        std::string str = fdp->ConsumeRandomLengthString();
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        bool enabled = fdp->ConsumeBool();

        auto bundle = std::make_shared<NotificationBundleOption>(str, id);
        auto distriBundle = std::make_shared<DistributedBundleOption>(bundle, enabled);
        distriBundle->SetBundle(bundle);
        distriBundle->GetBundle();
        distriBundle->SetEnable(enabled);
        distriBundle->isEnable();
        distriBundle->Dump();

        Parcel parcel;
        distriBundle->Marshalling(parcel);
        distriBundle->Unmarshalling(parcel);
        
        nlohmann::json jsonObject;
        distriBundle->ToJson(jsonObject);
        distriBundle->FromJson(jsonObject);
        return true;
    }

    bool TestAnsNotification7(FuzzedDataProvider* fdp)
    {
        std::string str = fdp->ConsumeRandomLengthString();
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        int32_t flag = fdp->ConsumeIntegral<int32_t>();
        bool enabled = fdp->ConsumeBool();

        auto bundle = std::make_shared<NotificationBundleOption>(str, id);
        auto reminderInfo = std::make_shared<NotificationReminderInfo>();

        reminderInfo->SetBundleOption(*bundle);
        reminderInfo->GetBundleOption();

        reminderInfo->SetReminderFlags(flag);
        reminderInfo->GetReminderFlags();

        reminderInfo->SetSilentReminderEnabled(enabled);
        reminderInfo->GetSilentReminderEnabled();

        Parcel parcel;
        reminderInfo->Marshalling(parcel);
        reminderInfo->Unmarshalling(parcel);
        
        nlohmann::json jsonObject;
        reminderInfo->ToJson(jsonObject);
        reminderInfo->FromJson(jsonObject);

        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestSubscribeListener(fdp);
        TestAnsNotification(fdp);
        TestAnsNotification2(fdp);
        TestAnsNotification3(fdp);
        TestAnsNotification4(fdp);
        TestAnsNotification5(fdp);
        TestAnsNotification6(fdp);
        TestAnsNotification7(fdp);
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
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
