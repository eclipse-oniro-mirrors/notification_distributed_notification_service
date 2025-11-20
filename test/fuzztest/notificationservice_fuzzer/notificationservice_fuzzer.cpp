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

        service->TryStartReminderAgentService();
        std::vector<NotificationReminderInfo> reminders;
        std::vector<sptr<NotificationReminderInfo>> reminderSptr;
        sptr<NotificationReminderInfo> reminder = new NotificationReminderInfo();
        reminderSptr.emplace_back(reminder);
        service->GetReminderInfoByBundles(bundleOptions, reminders);
        service->SetReminderInfoByBundles(reminderSptr);

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
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        AdvancedDatashareHelper::SetIsDataShareReady(enabled);
        AdvancedDatashareHelper advancedDatashareHelper;
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
        auto record = NotificationSubscriberManager::GetInstance()->CreateSubscriberRecord(nullptr);
        service->OnSubscriberAdd(record, num);

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
