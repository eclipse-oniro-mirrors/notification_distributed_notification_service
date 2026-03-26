/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "advanced_notification_service_ability.h"
#include "notification_extension_wrapper.h"
#include "system_event_observer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#ifdef ALL_SCENARIO_COLLABORATION
#include "distributed_device_manager.h"
#include "distributed_extension_service.h"
#endif
#include "advanced_notification_service.h"
#ifdef ENABLE_ANS_TELEPHONY_CUST_WRAPPER
#include "telephony_extension_wrapper.h"
#endif
#include "advanced_datashare_helper.h"
#include "notification_ai_extension_wrapper.h"
#include "advanced_notification_inline.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {
namespace {
REGISTER_SYSTEM_ABILITY_BY_ID(AdvancedNotificationServiceAbility, ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, true);
}

const std::string EXTENSION_BACKUP = "backup";
const std::string EXTENSION_RESTORE = "restore";
const int32_t ALL_CONNECT_SA_ID = 70633;
static int64_t g_saStartTime;
static int64_t g_saStartBootTime;

AdvancedNotificationServiceAbility::AdvancedNotificationServiceAbility(const int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), service_(nullptr)
{}

AdvancedNotificationServiceAbility::~AdvancedNotificationServiceAbility()
{}

void AdvancedNotificationServiceAbility::OnStart()
{
    if (service_ != nullptr) {
        return;
    }
    g_saStartTime = GetCurrentTime();
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    g_saStartBootTime = timer->GetBootTimeMs();
    service_ = AdvancedNotificationService::GetInstance();
    service_->CreateDialogManager();
    service_->InitPublishProcess();
    
    if (!Publish(service_)) {
        return;
    }

    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
#ifdef ENABLE_ANS_TELEPHONY_CUST_WRAPPER
    TEL_EXTENTION_WRAPPER->InitTelExtentionWrapper();
#endif
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    NOTIFICATION_AI_EXTENSION_WRAPPER->Init();
#endif
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(ALL_CONNECT_SA_ID);
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    service_->TryStartExtensionSubscribeService();
#endif
}

void AdvancedNotificationServiceAbility::OnStop()
{
    service_ = nullptr;
}

bool AdvancedNotificationServiceAbility::SubscribeCommonEvent()
{
    ANS_LOGW("COMMON_EVENT_SERVICE_ID");
    if (isDatashaReready_) {
        return false;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.DATA_SHARE_READY");
#ifdef ANS_FEATURE_NOTIFICATION_STATISTICS
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
#endif
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<SystemEventSubscriber>(
        subscribeInfo, std::bind(&AdvancedNotificationServiceAbility::OnReceiveEvent, this, std::placeholders::_1));
    if (subscriber_ == nullptr) {
        ANS_LOGD("subscriber_ is nullptr");
        return false;
    }
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);

    return true;
}

void AdvancedNotificationServiceAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    ANS_LOGI("SA %{public}d start", systemAbilityId);
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        ANS_LOGW("DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID");
        if (AdvancedDatashareObserver::GetInstance().CheckIfSettingsDataReady()) {
            if (isDatashaReready_) {
                return;
            }
#ifdef ENABLE_ANS_AGGREATION
            EXTENTION_WRAPPER->CheckIfSetlocalSwitch();
#endif
            AdvancedDatashareHelper::SetIsDataShareReady(true);
            DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->Init();
            isDatashaReready_ = true;
        }
    } else if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        if (!SubscribeCommonEvent()) {
            return;
        }
    } else if (systemAbilityId == BUNDLE_MGR_SERVICE_SYS_ABILITY_ID) {
        ANS_LOGW("BUNDLE_MGR_SERVICE_SYS_ABILITY_ID");
        if (isDatashaReready_) {
            return;
        }
        auto notificationService = AdvancedNotificationService::GetInstance();
        if (notificationService == nullptr) {
            ANS_LOGW("notification service is not initial.");
            return;
        }
        notificationService->ResetDistributedEnabled();
    } else if (systemAbilityId == DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID) {
#ifdef ALL_SCENARIO_COLLABORATION
        DistributedDeviceManager::GetInstance().RegisterDms(true);
#endif
    } else if (systemAbilityId == ALL_CONNECT_SA_ID) {
#ifdef ALL_SCENARIO_COLLABORATION
        DistributedExtensionService::GetInstance().OnAllConnectOnline();
#endif
    }
}

void AdvancedNotificationServiceAbility::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    ANS_LOGI("receive %{public}s", action.c_str());
    if (action == "usual.event.DATA_SHARE_READY") {
        if (isDatashaReready_) {
            return;
        }
        AdvancedDatashareHelper::SetIsDataShareReady(true);
        DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->Init();
        isDatashaReready_ = true;
#ifdef ENABLE_ANS_AGGREATION
        EXTENTION_WRAPPER->CheckIfSetlocalSwitch();
#endif
    }
#ifdef ANS_FEATURE_NOTIFICATION_STATISTICS
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED) {
        int64_t current = GetCurrentTime();
        sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
        int64_t bootTimeMs = timer->GetBootTimeMs();
        int64_t realTime = g_saStartTime + (bootTimeMs - g_saStartBootTime);
        int64_t diffTime = current - realTime;
        g_saStartTime = current;
        g_saStartBootTime = bootTimeMs;
        NotificationPreferences::GetInstance()->UpdateCustomTimeData(diffTime);
        NotificationAnalyticsUtil::UpdateCleanExperDataTimer();
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        AppExecFwk::ElementName ele = data.GetWant().GetElement();
        std::string bundleName = ele.GetBundleName();
        int32_t uid = data.GetWant().GetIntParam(AppExecFwk::Constants::UID, -1);
        int32_t userId = data.GetWant().GetIntParam(AppExecFwk::Constants::USER_ID, -1);

        NotificationPreferences::GetInstance()->DeleteStatisticsByBundle(userId, bundleName, uid);
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        NotificationPreferences::GetInstance()->DropStatisticsTable(data.GetCode());
    }
#endif
}

void AdvancedNotificationServiceAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        return;
    }
}

int32_t AdvancedNotificationServiceAbility::OnExtension(const std::string& extension,
    MessageParcel& data, MessageParcel& reply)
{
    ANS_LOGI("extension is %{public}s.", extension.c_str());
    auto notificationService = AdvancedNotificationService::GetInstance();
    if (notificationService == nullptr) {
        ANS_LOGW("notification service is not initial.");
        return ERR_OK;
    }
    if (extension == EXTENSION_BACKUP) {
        return notificationService->OnBackup(data, reply);
    } else if (extension == EXTENSION_RESTORE) {
        return notificationService->OnRestore(data, reply);
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
