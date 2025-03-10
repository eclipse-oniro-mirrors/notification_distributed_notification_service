/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "ability_manager_helper.h"


namespace OHOS {
namespace Notification {

AbilityManagerHelper::AbilityManagerHelper()
{
    operationQueue_ = std::make_shared<ffrt::queue>("dans_operation");
    if (operationQueue_ == nullptr) {
        ANS_LOGW("ffrt create failed!");
        return;
    }
    ANS_LOGI("Operation service init successfully.");
}

AbilityManagerHelper& AbilityManagerHelper::GetInstance()
{
    static AbilityManagerHelper abilityManagerHelper;
    return abilityManagerHelper;
}

int AbilityManagerHelper::ConnectAbility(const std::string &eventId, const AAFwk::Want &want,
    const std::string& userInputKey, const std::string& userInput)
{
    ANS_LOGI("enter, target bundle = %{public}s", want.GetBundle().c_str());
    std::lock_guard<std::mutex> lock(connectionLock_);
    sptr<DistributedOperationConnection> connection =
        new (std::nothrow) DistributedOperationConnection(eventId, userInputKey, userInput);
    if (connection == nullptr) {
        ANS_LOGI("failed to create obj!");
        return -1;
    }
    int32_t result = AAFwk::AbilityManagerClient::GetInstance()->StartAbilityByCall(want, connection);
    if (result == ERR_OK) {
        operationConnection_[eventId] = connection;
    }
    ANS_LOGI("Ability manager connect call %{public}d %{public}u!", result, operationConnection_.size());
    return result;
}

void AbilityManagerHelper::DisconnectServiceAbility(const std::string &eventId, const AppExecFwk::ElementName& element)
{
    ANS_LOGI("DisconnectServiceAbility %{public}s", eventId.c_str());
    if (operationQueue_ == nullptr) {
        ANS_LOGI("operationQueue is nullptr");
        return;
    }

    std::function<void()> task = [this, eventId, element]() {
        std::lock_guard<std::mutex> lock(connectionLock_);
        auto iter = operationConnection_.find(eventId);
        if (iter == operationConnection_.end()) {
            ANS_LOGI("failed to find connection!");
            return;
        }

        auto ret = AAFwk::AbilityManagerClient::GetInstance()->ReleaseCall(iter->second, element);
        operationConnection_.erase(eventId);
        ANS_LOGI("Ability manager releas call %{public}d %{public}u!", ret, operationConnection_.size());
    };
    operationQueue_->submit(task);
}

}
}
