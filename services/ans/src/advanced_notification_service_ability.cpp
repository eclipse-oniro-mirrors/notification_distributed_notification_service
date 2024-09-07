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
#include "telephony_extension_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
REGISTER_SYSTEM_ABILITY_BY_ID(AdvancedNotificationServiceAbility, ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, true);
}

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
    if (!Publish(service_)) {
        return;
    }
    service_->CreateDialogManager();
    service_->InitPublishProcess();
    reminderAgent_ = ReminderDataManager::InitInstance(service_);

#ifdef ENABLE_ANS_EXT_WRAPPER
    EXTENTION_WRAPPER->InitExtentionWrapper();
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
#else
    ANS_LOGI("Not enabled ans_ext");
#endif

#ifdef ENABLE_ANS_TELEPHONY_CUST_WRAPPER
    TEL_EXTENTION_WRAPPER->InitTelExtentionWrapper();
#endif
}

void AdvancedNotificationServiceAbility::OnStop()
{
    service_ = nullptr;
    reminderAgent_ = nullptr;
}

void AdvancedNotificationServiceAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    ANS_LOGD("SubSystemAbilityListener::OnAddSystemAbility enter !");
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        if (AdvancedDatashareObserver::GetInstance().CheckIfSettingsDataReady()) {
            if (isDatashaReready_) {
                return;
            }
            EXTENTION_WRAPPER->CheckIfSetlocalSwitch();
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
        isDatashaReready_ = true;
        ANS_LOGI("COMMON_EVENT_SERVICE_ID OnReceiveEvent ok!");
        EXTENTION_WRAPPER->CheckIfSetlocalSwitch();
    }
}

void AdvancedNotificationServiceAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        return;
    }
}
}  // namespace Notification
}  // namespace OHOS
