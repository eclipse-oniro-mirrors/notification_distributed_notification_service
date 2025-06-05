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
#include "liveview_all_scenarios_extension_wrapper.h"
#include "distributed_device_manager.h"
#include "advanced_datashare_helper.h"
#include "distributed_extension_service.h"

namespace OHOS {
namespace Notification {
namespace {
REGISTER_SYSTEM_ABILITY_BY_ID(AdvancedNotificationServiceAbility, ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, true);
}

const std::string EXTENSION_BACKUP = "backup";
const std::string EXTENSION_RESTORE = "restore";
const int32_t ALL_CONNECT_SA_ID = 70633;

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
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(ALL_CONNECT_SA_ID);
}

void AdvancedNotificationServiceAbility::OnStop()
{
    service_ = nullptr;
}

void AdvancedNotificationServiceAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    ANS_LOGD("SubSystemAbilityListener::OnAddSystemAbility enter !");
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        if (AdvancedDatashareObserver::GetInstance().CheckIfSettingsDataReady()) {
            if (isDatashaReready_) {
                return;
            }
#ifdef ENABLE_ANS_AGGREATION
            EXTENTION_WRAPPER->CheckIfSetlocalSwitch();
#endif
            isDatashaReready_ = true;
        }
    } else if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        if (isDatashaReready_) {
            return;
        }
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent("usual.event.DATA_SHARE_READY");
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        subscriber_ = std::make_shared<SystemEventSubscriber>(
            subscribeInfo, std::bind(&AdvancedNotificationServiceAbility::OnReceiveEvent, this, std::placeholders::_1));
        if (subscriber_ == nullptr) {
            ANS_LOGD("subscriber_ is nullptr");
            return;
        }
        EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    } else if (systemAbilityId == BUNDLE_MGR_SERVICE_SYS_ABILITY_ID) {
        if (isDatashaReready_) {
            return;
        }
        auto notificationService = AdvancedNotificationService::GetInstance();
        if (notificationService == nullptr) {
            return;
        }
        notificationService->ResetDistributedEnabled();
    } else if (systemAbilityId == DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID) {
        ANS_LOGW("DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID");
        DistributedDeviceManager::GetInstance().RegisterDms(true);
    } else if (systemAbilityId == ALL_CONNECT_SA_ID) {
        DistributedExtensionService::GetInstance().OnAllConnectOnline();
    }
}

void AdvancedNotificationServiceAbility::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    ANS_LOGI("CheckIfSettingsDataReady() ok!");
    if (isDatashaReready_) {
        return;
    }
    auto const &want = data.GetWant();
    std::string action = want.GetAction();
    if (action == "usual.event.DATA_SHARE_READY") {
        AdvancedDatashareHelper::SetIsDataShareReady(true);
        isDatashaReready_ = true;
        ANS_LOGI("COMMON_EVENT_SERVICE_ID OnReceiveEvent ok!");
#ifdef ENABLE_ANS_AGGREATION
        EXTENTION_WRAPPER->CheckIfSetlocalSwitch();
#endif
    }
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
