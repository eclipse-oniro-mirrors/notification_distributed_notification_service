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

#include "notifhelper_fuzzer.h"
#include "notification_helper.h"
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
namespace {
constexpr int32_t MAX_VECTOR_SIZE = 3;
constexpr int32_t MIN_USER_ID = -1;
constexpr int32_t MAX_USER_ID = 100;
}
    bool TestAdvancedOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        constexpr uint8_t SLOT_TYPE_NUM = 5;

        NotificationBundleOption bundleOption;
        std::string str = fdp->ConsumeRandomLengthString();
        int32_t id = fdp->ConsumeIntegral<int32_t>();
        bundleOption.SetBundleName(str);
        bundleOption.SetUid(id);

        uint32_t type = fdp->ConsumeIntegralInRange<uint32_t>(0, 100);
        notificationHelper.SetHashCodeRule(type);

        std::string str1 = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::vector<std::string> strList;
        strList.push_back(str1);
        strList.push_back(str2);
        std::vector<NotificationBundleOption> bundles;
        bundles.emplace_back(bundleOption);
        notificationHelper.GetDistributedDevicelist(strList);
        notificationHelper.GetMutilDeviceStatus(str1, type, str2, id);
        notificationHelper.GetTargetDeviceBundleList(str1, str2, strList, strList);

        NotificationRingtoneInfo ring;
        notificationHelper.SetRingtoneInfoByBundle(bundleOption, ring);
        notificationHelper.GetRingtoneInfoByBundle(bundleOption, ring);

        uint8_t type2 = fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(type2);
        bool enabled = fdp->ConsumeBool();
        bool isForceControl = fdp->ConsumeBool();
        notificationHelper.SetDefaultSlotForBundle(bundleOption, slotType, enabled, isForceControl);

        int32_t num = fdp->ConsumeIntegral<int32_t>();
        notificationHelper.SetCheckConfig(num, str, str1, str2);
        notificationHelper.GetLiveViewConfig(strList);

        std::vector<int32_t> intList;
        bool isProxy = fdp->ConsumeBool();
        intList.emplace_back(num);
        notificationHelper.ProxyForUnaware(intList, isProxy);

        std::vector<NotificationReminderInfo> reminders;
        notificationHelper.GetReminderInfoByBundles(bundles, reminders);
        notificationHelper.SetReminderInfoByBundles(reminders);
        return true;
    }

    bool TestExtensionOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        bool enabled = fdp->ConsumeBool();
        notificationHelper.NotificationExtensionUnsubscribe();
        notificationHelper.IsUserGranted(enabled);
        NotificationBundleOption bundle;
        std::string str = fdp->ConsumeRandomLengthString();
        int32_t uid = fdp->ConsumeIntegral<int32_t>();
        bundle.SetBundleName(str);
        bundle.SetUid(uid);
        notificationHelper.GetUserGrantedState(bundle, enabled);
        notificationHelper.SetUserGrantedState(bundle, enabled);

        std::vector<NotificationBundleOption> bundles;
        std::vector<sptr<NotificationBundleOption>> bundlePtrs;
        notificationHelper.GetUserGrantedEnabledBundles(bundle, bundlePtrs);
        notificationHelper.GetUserGrantedEnabledBundlesForSelf(bundlePtrs);
        notificationHelper.SetUserGrantedBundleState(bundle, bundlePtrs, enabled);
        notificationHelper.GetAllSubscriptionBundles(bundlePtrs);
        notificationHelper.CanOpenSubscribeSettings();
        return true;
    }

    bool TestGeofenceOperations(FuzzedDataProvider* fdp, NotificationHelper& notificationHelper)
    {
        bool setEnabled = fdp->ConsumeBool();
        notificationHelper.SetGeofenceEnabled(setEnabled);

        bool isEnabled;
        notificationHelper.IsGeofenceEnabled(isEnabled);

        auto triggerKeysSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        std::vector<std::string> triggerKeys;
        for (int i = 0; i < triggerKeysSize; ++i) {
            triggerKeys.push_back(fdp->ConsumeRandomLengthString());
        }
        auto userIdsSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        std::vector<int32_t> userIds;
        for (int i = 0; i < userIdsSize; ++i) {
            userIds.push_back(fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID));
        }
        notificationHelper.ClearDelayNotification(triggerKeys, userIds);

        auto triggerKey = fdp->ConsumeRandomLengthString();
        auto userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
        notificationHelper.PublishDelayedNotification(triggerKey, userId);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        NotificationHelper notificationHelper;
        TestAdvancedOperations(fdp, notificationHelper);
        TestExtensionOperations(fdp, notificationHelper);
        TestGeofenceOperations(fdp, notificationHelper);
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
