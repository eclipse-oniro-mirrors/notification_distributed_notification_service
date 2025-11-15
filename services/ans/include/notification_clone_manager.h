/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_MANAGER_H

#include <set>
#include <map>
#include <string>

#include "unique_fd.h"
#include "iremote_proxy.h"
#include "common_event_data.h"
#include "notification_clone_template.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
namespace OHOS {
namespace Notification {

class AncoRestoreStartEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    DISALLOW_COPY_AND_MOVE(AncoRestoreStartEventSubscriber);
    explicit AncoRestoreStartEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    ~AncoRestoreStartEventSubscriber() override;
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;
    static std::shared_ptr<AncoRestoreStartEventSubscriber> create();

private:
    inline static const std::string EVENT_NAME = "usual.event.ANCO_RESTORE_START";
    inline static const std::string EVENT_PUBLISHER_PERMISSION = "ohos.permission.RECEIVE_BMS_BROKER_MESSAGES";
};

class NotificationCloneManager {
public:
    static NotificationCloneManager& GetInstance();

    int32_t OnBackup(MessageParcel& data, MessageParcel& reply);
    int32_t OnRestore(MessageParcel& data, MessageParcel& reply);
    void OnUserSwitch(int32_t userId);
    void OnRestoreStart(EventFwk::Want want);
    void OnDhRestoreStart(const std::string bundleName, const int32_t uid);

private:
    NotificationCloneManager();
    ~NotificationCloneManager();

    void RemoveBackUpFile();
    ErrCode LoadConfig(UniqueFd &fd, std::string& config);
    ErrCode SaveConfig(const std::string& config);
    void GetRestoreSystemApp(const std::string& extralInfo, std::set<std::string>& bundles);
    std::vector<std::pair<std::string, std::shared_ptr<NotificationCloneTemplate>>> cloneTemplates;
    std::shared_ptr<AncoRestoreStartEventSubscriber> restoreStartEventSubscriber_ = nullptr;
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_MANAGER_H
