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
#include "ans_permission_def.h"
#define private public

#include "notificationservice_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "ans_permission_def.h"
#include "notification_analytics_util.h"
#include "notification_request.h"
#include "notification_bundle_option.h"
#include "notification_live_view_content.h"
#include "advanced_notification_service.h"
#include "reminder_request_calendar.h"
#include "reminder_request.h"
#include "reminder_request_alarm.h"
#include "notification_clone_bundle_info.h"
#include "notification_config_parse.h"
#include "advanced_datashare_observer.h"
#include "advanced_datashare_helper.h"
#include "advanced_aggregation_data_roaming_observer.h"
#include "notification_timer_info.h"

namespace OHOS {
namespace Notification {

    bool TestNotificationService(FuzzedDataProvider *fdp)
    {
        int32_t id = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        auto service = AdvancedNotificationService::GetInstance();
        sptr<NotificationRequest> request = new NotificationRequest();
        std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
        std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
        liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        request->SetSlotType(slotType);
        request->SetContent(content);
        request->SetNotificationId(1);
        request->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
        service->IsLiveViewCanRecover(nullptr);
        service->IsLiveViewCanRecover(request);
        return true;
    }

    bool TestReminderRequestCalendar(FuzzedDataProvider *fdp)
    {
        time_t now;
        (void)time(&now);
        struct tm nowTime;
        (void)localtime_r(&now, &nowTime);
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek;
        ReminderRequestCalendar calendar;
        ReminderRequestCalendar calendar2(calendar);

        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        calendar.DelExcludeDates();
        calendar.AddExcludeDate(static_cast<uint64_t>(now) * num);
        calendar.GetExcludeDates();
        calendar.IsInExcludeDate();
        calendar.GetRRuleWantAgentInfo();

        int32_t num2 = fdp->ConsumeIntegralInRange<uint32_t>(1, 100);
        int32_t num3 = fdp->ConsumeIntegralInRange<uint16_t>(1, 100);
        int32_t num4 = fdp->ConsumeIntegralInRange<uint8_t>(1, 100);
        int32_t num5 = fdp->ConsumeIntegralInRange<uint64_t>(1, 100);
        calendar.SetRepeatDay(num2);
        calendar.SetRepeatMonth(num3);
        calendar.SetRepeatMonth(num3);
        calendar.SetFirstDesignateYear(num3);
        calendar.SetFirstDesignageMonth(num3);
        calendar.SetFirstDesignateDay(num3);
        calendar.SetYear(num3);
        calendar.SetMonth(num4);
        calendar.SetDay(num4);
        calendar.SetHour(num4);
        calendar.SetMinute(num4);
        calendar.IsRepeat();
        calendar.CheckExcludeDate();
        calendar.IsNeedNotification();
        calendar.IsPullUpService();
        calendar.SetDateTime(num5);
        calendar.SetEndDateTime(num5);
        calendar.SetLastStartDateTime(num5);
        sptr<ReminderRequest> reminder1 = new ReminderRequestCalendar(num);
        calendar.Copy(reminder1);
        std::string str = fdp->ConsumeRandomLengthString();
        calendar.DeserializationRRule("");
        calendar.DeserializationRRule(str);
        calendar.DeserializationExcludeDates("");
        calendar.DeserializationExcludeDates(str);

        return true;
    }

    bool TestReminderRequest(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        int32_t num2 = fdp->ConsumeIntegralInRange<uint8_t>(1, 100);
        ReminderRequestAlarm alarm(num);
        ReminderRequestAlarm alarm2(alarm);
        alarm.SetHour(num2);
        alarm.SetMinute(num2);
        ReminderRequest reminderRequest(num);
        std::string str1 = "12.34";
        std::string str2 = "1";
        reminderRequest.StringToDouble(str1);
        reminderRequest.StringToInt(str2);
        return true;
    }

    bool TestCloneBundleInfo(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();

        NotificationCloneBundleInfo info;
        info.SetAppIndex(num);
        info.SetHasPoppedDialog(enabled);
        info.GetHasPoppedDialog();
        info.SetSilentReminderEnabled(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
        info.GetSilentReminderEnabled();
        info.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
        info.GetEnabledExtensionSubscription();
        std::vector<sptr<NotificationExtensionSubscriptionInfo>> extensionInfo;
        info.SetExtensionSubscriptionInfos(extensionInfo);
        info.GetExtensionSubscriptionInfos();
        NotificationCloneBundleInfo::SlotInfo s1;
        NotificationCloneBundleInfo::SlotInfo s2;
        info.AddSlotInfo(s1);
        info.AddSlotInfo(s2);
        std::vector<sptr<NotificationBundleOption>> bundles;
        sptr<NotificationBundleOption> bundle = new NotificationBundleOption(str, num);
        bundles.emplace_back(bundle);
        info.SetExtensionSubscriptionBundles(bundles);
        info.GetExtensionSubscriptionBundles();
        sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
        info.AddRingtoneInfo(ringtoneInfo);
        info.GetRingtoneInfo();
        nlohmann::json jsonObject;
        info.ToJson(jsonObject);
        info.FromJson(jsonObject);
        return true;
    }

    bool TestConfigParse(FuzzedDataProvider *fdp)
    {
        NotificationConfigParse config;
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        uint32_t unum = fdp->ConsumeIntegralInRange<uint32_t>(1, 100);
        config.IsLiveViewEnabled(str);
        config.IsDistributedReplyEnabled(str);
        config.GetCollaborationFilter();
        config.IsInCollaborationFilter(str, num);
        config.CheckAppLiveViewCcm();
        config.IsReportTrustList(str);
        config.GetCloneExpiredTime(num);
        config.IsNotificationExtensionLifecycleDestroyTimeConfigured(unum);
        config.IsNotificationExtensionSubscribeSupportHfp(enabled);
        std::vector<std::string> strs;
        strs.emplace_back(str);
        config.GetNotificationExtensionEnabledBundlesWriteList(strs);
        return true;
    }

    bool TestBadgeManager(FuzzedDataProvider *fdp)
    {
        auto service = AdvancedNotificationService::GetInstance();
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();

        std::map<sptr<NotificationBundleOption>, bool> bundles;
        sptr<NotificationBundleOption> bundle = new NotificationBundleOption(str, num);
        bundles.insert({bundle, enabled});
        service->SetShowBadgeEnabledForBundles(bundles);
        std::vector<sptr<NotificationBundleOption>> bundleOptions;
        bundleOptions.emplace_back(bundle);

        service->GetShowBadgeEnabledForBundles(bundleOptions, bundles);
        return true;
    }

    bool TestDataShareObserver(FuzzedDataProvider *fdp)
    {
        std::string str = fdp->ConsumeRandomLengthString();
        sptr<AdvancedAggregationDataRoamingObserver> aggregationRoamingObserver =
        new (std::nothrow) AdvancedAggregationDataRoamingObserver();
        AdvancedDatashareObserver::GetInstance().CreateDataShareHelper();
        Uri dataEnableUri(str);
        AdvancedDatashareObserver::GetInstance().RegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);
        AdvancedDatashareObserver::GetInstance().UnRegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);
        AdvancedDatashareObserver::GetInstance().CheckIfSettingsDataReady();
        return true;
    }

    bool TestDataShareHelper(FuzzedDataProvider *fdp)
    {
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::string str3 = fdp->ConsumeRandomLengthString();
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        AdvancedDatashareHelper::SetIsDataShareReady(enabled);
        AdvancedDatashareHelper advancedDatashareHelper;
        
        // test AdvancedDatashareHelper::Init
        advancedDatashareHelper.Init();
        advancedDatashareHelper.Init();
        
        Uri enableUri(advancedDatashareHelper.GetFocusModeEnableUri(num));
        advancedDatashareHelper.Query(enableUri, str, str2);
        advancedDatashareHelper.QueryContact(enableUri, str, "6", "1", str2);
        advancedDatashareHelper.GetIntelligentExperienceUri(num);
        advancedDatashareHelper.isRepeatCall(str);
        advancedDatashareHelper.GetFocusModeEnableUri(num);
        advancedDatashareHelper.GetFocusModeProfileUri(num);
        advancedDatashareHelper.GetIntelligentExperienceUri(num);
        advancedDatashareHelper.GetFocusModeCallPolicyUri(num);
        advancedDatashareHelper.GetFocusModeRepeatCallUri(num);
        advancedDatashareHelper.GetIntelligentData(str, str2);
        advancedDatashareHelper.GetIntelligentUri();
        advancedDatashareHelper.GetContactResultSet(enableUri, str, "6", "1", str2);
        advancedDatashareHelper.SetIsDataShareReady(enabled);
        
        // test Init with dataShare ready enabled
        AdvancedDatashareHelper::SetIsDataShareReady(true);
        advancedDatashareHelper.Init();
        
        // test Init with dataShare ready disabled
        AdvancedDatashareHelper::SetIsDataShareReady(false);
        advancedDatashareHelper.Init();
        
        // test CreateIntelligentDataShareHelper without userId
        std::string intelligentUri = advancedDatashareHelper.GetIntelligentUri();
        auto intelligentHelper = advancedDatashareHelper.CreateIntelligentDataShareHelper(intelligentUri);
        
        // test CreateIntelligentDataShareHelper with userId
        auto intelligentHelperWithUser =
            advancedDatashareHelper.CreateIntelligentDataShareHelper(intelligentUri, userId);
        
        // test CreateIntelligentDataShareHelper with invalid userId
        auto intelligentHelperInvalidUser =
            advancedDatashareHelper.CreateIntelligentDataShareHelper(intelligentUri, -1);
        
        // test CreateIntelligentDataShareHelperInner with userId (private function)
        auto innerHelper = advancedDatashareHelper.CreateIntelligentDataShareHelperInner(intelligentUri, userId);
        
        // test CreateIntelligentDataShareHelperInner with SUBSCRIBE_USER_INIT (-1)
        auto innerHelperDefaultUser = advancedDatashareHelper.CreateIntelligentDataShareHelperInner(intelligentUri);
        
        // test AddDataShareItems (private function)
        Uri dataShareUri(str);
        advancedDatashareHelper.AddDataShareItems(dataShareUri, str2, str3);
        
        // test AddDataShareItems with same uri and key (update existing item)
        advancedDatashareHelper.AddDataShareItems(dataShareUri, str2, fdp->ConsumeRandomLengthString());
        
        // test AddDataShareItems with different uri
        Uri dataShareUri2(fdp->ConsumeRandomLengthString());
        advancedDatashareHelper.AddDataShareItems(dataShareUri2, str2, str3);
        
        // test QueryContact with various parameters and policies
        advancedDatashareHelper.QueryContact(enableUri, str, "4", "1", str2);
        advancedDatashareHelper.QueryContact(enableUri, str, "5", "1", str2);
        advancedDatashareHelper.QueryContact(enableUri, str, "6", "1", str2);
        
        // test QueryContact with userId parameter
        advancedDatashareHelper.QueryContact(enableUri, str, "4", "1", str2, userId);
        advancedDatashareHelper.QueryContact(enableUri, str, "5", "1", str2, userId);
        advancedDatashareHelper.QueryContact(enableUri, str, "6", "1", str2, userId);
        
        // test QueryContact with invalid userId
        advancedDatashareHelper.QueryContact(enableUri, str, "4", "1", str2, -1);
        
        // test QuerydataShareItems (private function)
        std::string queryValue;
        advancedDatashareHelper.QuerydataShareItems(dataShareUri, str2, queryValue);
        
        // test GetIntelligentData with userId
        advancedDatashareHelper.GetIntelligentData(str, str2, userId);
        
        // test GetContactResultSet with userId
        auto resultSet = advancedDatashareHelper.GetContactResultSet(enableUri, str, "6", "1", str2, userId);
        
        // test GetContactResultSet without userId (default version)
        auto resultSetDefault = advancedDatashareHelper.GetContactResultSet(enableUri, str, "4", "1", str2);
        
        // test GetContactResultSet with invalid userId
        auto resultSetInvalid = advancedDatashareHelper.GetContactResultSet(enableUri, str, "5", "1", str2, -1);
        
        // test GetContactResultSetInner (private function) with userId
        auto resultSetInner = advancedDatashareHelper.GetContactResultSetInner(enableUri, str, "6", "1", str2, userId);
        
        // test GetContactResultSetInner (private function) with default userId
        auto resultSetInnerDefault = advancedDatashareHelper.GetContactResultSetInner(enableUri, str, "4", "1", str2);
        
        // test dealWithContactResult (private function) with resultSet
        if (resultSet != nullptr) {
            advancedDatashareHelper.dealWithContactResult(resultSet, "4");
            advancedDatashareHelper.dealWithContactResult(resultSet, "5");
            advancedDatashareHelper.dealWithContactResult(resultSet, "6");
            advancedDatashareHelper.dealWithContactResult(resultSet, "0");
        }
        
        // test dealWithContactResult with nullptr
        advancedDatashareHelper.dealWithContactResult(nullptr, "4");
        
        // test RegisterObserver (private function)
        AdvancedDatashareHelper::SetIsDataShareReady(true);
        advancedDatashareHelper.RegisterObserver(userId,
            advancedDatashareHelper.GetFocusModeEnableUri(userId), { "focus_mode_enable" });
        advancedDatashareHelper.RegisterObserver(userId,
            advancedDatashareHelper.GetFocusModeProfileUri(userId), { "focus_mode_profile" });
        advancedDatashareHelper.RegisterObserver(userId,
            advancedDatashareHelper.GetIntelligentExperienceUri(userId), { "intelligent_experience" });
        
        // test RegisterObserver with multiple keys
        std::vector<std::string> keys = { "key1", "key2", "key3" };
        advancedDatashareHelper.RegisterObserver(userId,
            advancedDatashareHelper.GetFocusModeCallPolicyUri(userId), keys);
        
        // test UnregisterObserver (private function)
        advancedDatashareHelper.UnregisterObserver();
        
        // test OnUserSwitch
        advancedDatashareHelper.OnUserSwitch(userId);
        advancedDatashareHelper.OnUserSwitch(fdp->ConsumeIntegralInRange<int32_t>(0, 100));
        
        // test OnUserSwitch with same userId again (should return early due to existing observer)
        advancedDatashareHelper.OnUserSwitch(userId);
        
        // test OnUserSwitch with dataShare not ready
        AdvancedDatashareHelper::SetIsDataShareReady(false);
        advancedDatashareHelper.OnUserSwitch(userId);
        
        // test UnregisterObserver again after re-register
        AdvancedDatashareHelper::SetIsDataShareReady(true);
        advancedDatashareHelper.OnUserSwitch(fdp->ConsumeIntegralInRange<int32_t>(100, 200));
        advancedDatashareHelper.UnregisterObserver();
        
        // test IsPCModeEnabled and SetPCModeEnabled
        bool currentPCMode = advancedDatashareHelper.IsPCModeEnabled();
        advancedDatashareHelper.SetPCModeEnabled(enabled);
        bool newPCMode = advancedDatashareHelper.IsPCModeEnabled();
        advancedDatashareHelper.SetPCModeEnabled(!enabled);
        bool toggledPCMode = advancedDatashareHelper.IsPCModeEnabled();
        
        // test SetPCModeEnabled with true
        advancedDatashareHelper.SetPCModeEnabled(true);
        bool pcModeTrue = advancedDatashareHelper.IsPCModeEnabled();
        
        // test SetPCModeEnabled with false
        advancedDatashareHelper.SetPCModeEnabled(false);
        bool pcModeFalse = advancedDatashareHelper.IsPCModeEnabled();
        
        // test GetPCModeUri with various userIds
        std::string pcModeUri1 = advancedDatashareHelper.GetPCModeUri(userId);
        std::string pcModeUri2 = advancedDatashareHelper.GetPCModeUri(num);
        std::string pcModeUri3 = advancedDatashareHelper.GetPCModeUri(0);
        std::string pcModeUri4 = advancedDatashareHelper.GetPCModeUri(100);
        
        // test IsPCModeEnabled with PC mode enabled during OnUserSwitch
        advancedDatashareHelper.SetPCModeEnabled(true);
        AdvancedDatashareHelper::SetIsDataShareReady(true);
        advancedDatashareHelper.OnUserSwitch(userId);
        bool pcModeAfterSwitch = advancedDatashareHelper.IsPCModeEnabled();
        
        return true;
    }

    bool TestTimerInfo(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        uint64_t unum = fdp->ConsumeIntegralInRange<uint64_t>(1, 100);
        bool enabled = fdp->ConsumeBool();
        NotificationTimerInfo time;
        time.SetType(num);
        time.SetRepeat(enabled);
        time.SetInterval(unum);
        time.OnTrigger();
        return true;
    }

    bool TestLiveView(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();
        auto service = AdvancedNotificationService::GetInstance();
        service->OnSubscriberAdd(nullptr, num);

        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        request->SetSlotType(slotType);
        request->SetNotificationId(num);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        liveContent->SetIsOnlyLocalUpdate(enabled);
        auto content = std::make_shared<NotificationContent>(liveContent);
        request->SetContent(content);
        sptr<NotificationBundleOption> bundle = new NotificationBundleOption(str, num);

        service->SetLockScreenPictureToDb(request);

        auto record2 = service->MakeNotificationRecord(request, bundle);
        service->UpdateInDelayNotificationList(record2);
        service->AddToDelayNotificationList(record2);
        service->SaPublishSystemLiveViewAsBundle(record2);
        service->StartPublishDelayedNotification(record2);
        service->IsNotificationExistsInDelayList(str);
        service->HandleUpdateLiveViewNotificationTimer(num, enabled);
        return true;
    }

    bool TestSlotService(FuzzedDataProvider *fdp)
    {
        bool enabled = fdp->ConsumeBool();
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        uint32_t unum = fdp->ConsumeIntegralInRange<uint32_t>(1, 100);
        std::string str = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::string str3 = fdp->ConsumeRandomLengthString();
        std::vector<std::string> strs;
        strs.emplace_back(str);
        strs.emplace_back(str2);
        strs.emplace_back(str3);
        sptr<NotificationBundleOption> bundle = new NotificationBundleOption(str, num);
        std::vector<sptr<NotificationBundleOption>> bundles;
        bundles.emplace_back(bundle);

        auto service = AdvancedNotificationService::GetInstance();
        service->GetNotificationSettings(unum);
        service->SetDefaultSlotForBundle(bundle, num, enabled, enabled);
        service->InvokeCheckConfig(str);
        service->InvockLiveViewSwitchCheck(bundles, num, unum);
        service->TriggerLiveViewSwitchCheck(num);
        service->SetCheckConfig(num, str, str2, str3);
        service->GetLiveViewConfig(strs);
        service->SetAdditionConfig(str, str2);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestNotificationService(fdp);
        TestReminderRequestCalendar(fdp);
        TestReminderRequest(fdp);
        TestCloneBundleInfo(fdp);
        TestConfigParse(fdp);
        TestBadgeManager(fdp);
        TestDataShareObserver(fdp);
        TestDataShareHelper(fdp);
        TestTimerInfo(fdp);
        TestLiveView(fdp);
        TestSlotService(fdp);
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
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
