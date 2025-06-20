/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H
#define BASE_NOTIFICATION_ANS_SERVICES_DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H

#include <vector>

#include "refbase.h"
#include "singleton.h"
#include "notification_request.h"

namespace OHOS::Notification {
class DistributedLiveviewAllScenariosExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(DistributedLiveviewAllScenariosExtensionWrapper);
public:
    void InitExtentionWrapper();
    void CloseExtentionWrapper();
    typedef ErrCode (*UPDATE_LIVEVIEW_ENCODE_CONTENT)(const sptr<NotificationRequest> &request,
        std::vector<uint8_t> &buffer);
    ErrCode UpdateLiveviewEncodeContent(const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer);
    typedef ErrCode (*UPDATE_LIVEVIEW_DECODE_CONTENT)(const sptr<NotificationRequest> &request,
        std::vector<uint8_t> &buffer);
    typedef ErrCode (*TRIGGER_PUSH_WANT_AGENT)(const sptr<NotificationRequest> &request,
        int32_t actionType, const AAFwk::WantParams extraInfo);
    typedef ErrCode (*SUBSCRIBE_ALL_CONNECT)();
    typedef ErrCode (*UNSUBSCRIBE_ALL_CONNECT)();
    typedef ErrCode (*LIVE_VIEW_MULTI_SCREEN_SYNC_OPER)(
        sptr<NotificationRequest> &request, const int32_t operationType, const int32_t btnIndex);
    typedef ErrCode (*RESTORE_COLLABORATION_WINDOW)(const std::string &networkId);
    ErrCode UpdateLiveviewDecodeContent(const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer);
    ErrCode TriggerPushWantAgent(const sptr<NotificationRequest> &request, int32_t actionType,
        const AAFwk::WantParams extraInfo);
    ErrCode SubscribeAllConnect();
    ErrCode UnSubscribeAllConnect();
    ErrCode LiveViewMultiScreenSyncOper(
        sptr<NotificationRequest> &request, const int32_t operationType, const int32_t btnIndex);
    int32_t RestoreCollaborationWindow(const std::string &networkId);
private:
    void* ExtensionHandle_ = nullptr;
    SUBSCRIBE_ALL_CONNECT subscribeHandler_ = nullptr;
    UNSUBSCRIBE_ALL_CONNECT unSubscribeHandler_ = nullptr;
    TRIGGER_PUSH_WANT_AGENT triggerHandler_ = nullptr;
    UPDATE_LIVEVIEW_ENCODE_CONTENT updateLiveviewEncodeContent_ = nullptr;
    UPDATE_LIVEVIEW_DECODE_CONTENT updateLiveviewDecodeContent_ = nullptr;
    LIVE_VIEW_MULTI_SCREEN_SYNC_OPER liveViewMultiScreenSyncOper_ = nullptr;
    RESTORE_COLLABORATION_WINDOW restoreCollaborationWindow_ = nullptr;
};

#define DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER \
    ::OHOS::DelayedSingleton<DistributedLiveviewAllScenariosExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H
