/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "ans_manager_death_recipient.h"

#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
void AnsManagerDeathRecipient::SubscribeSAManager()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (statusChangeListener_ != nullptr) {
        return;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) AnsManagerDeathRecipient::SystemAbilityStatusChangeListener();
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        ANS_LOGE("GetSystemAbilityManager failed or new SystemAbilityStatusChangeListener failed");
        statusChangeListener_ = nullptr;
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, statusChangeListener_);
    if (ret != ERR_OK) {
        ANS_LOGE("SubscribeSystemAbility to sa manager failed");
        statusChangeListener_ = nullptr;
    }
}
void AnsManagerDeathRecipient::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId) {}

void AnsManagerDeathRecipient::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    ANS_LOGI("Ans manager service died");
    DelayedSingleton<AnsNotification>::GetInstance()->OnServiceDied();
}
}  // namespace Notification
}  // namespace OHOS