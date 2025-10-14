/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_CONNECTION_H
#define DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_CONNECTION_H

#include "ffrt.h"

#include "ability_connect_callback_stub.h"
#include "extension_service_common.h"
#include "notification_subscriber_proxy.h"
#include "remote_death_recipient.h"

namespace OHOS {
namespace Notification {

class ExtensionServiceConnection : public AAFwk::AbilityConnectionStub {
public:
    ExtensionServiceConnection(const ExtensionSubscriberInfo& subscriberInfo,
        std::function<void(const ExtensionSubscriberInfo& subscriberInfo)> onDisconnected);
    virtual ~ExtensionServiceConnection();
    void Close();
    void NotifyOnReceiveMessage(const sptr<NotificationRequest> notificationRequest);
    void NotifyOnCancelMessages(const std::shared_ptr<std::vector<std::string>> hashCodes);

    /**
     * OnAbilityConnectDone, Ability Manager Service notify caller ability the result of connect.
     *
     * @param element, Indicates elementName of service ability.
     * @param remoteObject, Indicates the session proxy of service ability.
     * @param resultCode, Returns ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;

    /**
     * OnAbilityDisconnectDone, Ability Manager Service notify caller ability the result of disconnect.
     *
     * @param element, Indicates elementName of service ability.
     * @param resultCode, Returns ERR_OK on success, others on failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    static void SetExtensionLifecycleDestroyTime(uint32_t value);

private:
    void PrepareFreeze();
    void Freeze();
    void Unfreeze();
    void PrepareDisconnect();
    void Disconnect();
    void GetPid();
    void DoFreezeUnfreeze(bool isFreeze);
    void HandleDisconnectedState();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    enum class NotifyType {
        OnReceiveMessage,
        OnCancelMessages
    };
    struct NotifyParam {
        sptr<NotificationRequest> notificationRequest = nullptr;
        std::shared_ptr<std::vector<std::string>> hashCodes = nullptr;
    };
    static uint32_t DISCONNECT_DELAY_TIME;
    sptr<NotificationSubscriberProxy> proxy_ = nullptr;
    ffrt::recursive_mutex mutex_;
    std::vector<std::pair<NotifyType, NotifyParam>> messages_;
    std::shared_ptr<ffrt::queue> messageQueue_ = nullptr;
    ExtensionServiceConnectionState state_ = ExtensionServiceConnectionState::CREATED;
    std::string connectionKey_;
    uint64_t timerIdFreeze_ = 0L;
    uint64_t timerIdDisconnect_ = 0L;
    ExtensionSubscriberInfo subscriberInfo_;
    int32_t pid_ = -1;
    sptr<IRemoteObject> remoteObject_ = nullptr;
    sptr<RemoteDeathRecipient> deathRecipient_ = nullptr;
    std::function<void(const ExtensionSubscriberInfo& subscriberInfo)> onDisconnected_;
};
}
}
#endif // DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_CONNECTION_H
