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
        std::vector<uint8_t> &buffer, const std::string& deviceType);
    ErrCode UpdateLiveviewEncodeContent(const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer,
        const std::string& deviceType);
    typedef ErrCode (*UPDATE_LIVEVIEW_DECODE_CONTENT)(const sptr<NotificationRequest> &request,
        std::vector<uint8_t> &buffer, const std::string& deviceType);
    typedef ErrCode (*TRIGGER_PUSH_WANT_AGENT)(const sptr<NotificationRequest> &request,
        int32_t actionType, const AAFwk::WantParams extraInfo);
    typedef ErrCode (*SUBSCRIBE_ALL_CONNECT)();
    typedef ErrCode (*UNSUBSCRIBE_ALL_CONNECT)();
    typedef ErrCode (*DISTRIBUTED_LIVE_VIEW_OPERATION)(
        sptr<NotificationRequest> &request, const int32_t operationType, const int32_t btnIndex);
    typedef int32_t (*RESTORE_COLLABORATION_WINDOW)(const std::string &networkId);
    typedef ErrCode (*DISTRIBUTED_ANCO_NOTIFICATION_CLICK)(
        const sptr<NotificationRequest> &request, bool &triggerWantInner);
    typedef ErrCode (*UPDATE_LIVE_VIEW_BIN_FILE_2_PIEXL_MAP)(
        std::shared_ptr<Media::PixelMap> &pixelMap, const std::vector<uint8_t> &buffer);
    typedef ErrCode (*UPDATE_LIVE_VIEW_PIEXL_MAP_2_BIN_FILE)(
        const std::shared_ptr<Media::PixelMap> pixelMap, std::vector<uint8_t> &buffer);
    ErrCode UpdateLiveviewDecodeContent(const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer,
        const std::string& deviceType);
    ErrCode TriggerPushWantAgent(const sptr<NotificationRequest> &request, int32_t actionType,
        const AAFwk::WantParams extraInfo);
    ErrCode SubscribeAllConnect();
    ErrCode UnSubscribeAllConnect();
    ErrCode DistributedLiveViewOperation(
        sptr<NotificationRequest> &request, const int32_t operationType, const int32_t btnIndex);
    ErrCode DistributedAncoNotificationClick(const sptr<NotificationRequest> &request, bool &triggerWantInner);
    int32_t RestoreCollaborationWindow(const std::string &networkId);
    ErrCode UpdateLiveviewBinFile2PiexlMap(
        std::shared_ptr<Media::PixelMap> &pixelMap, const std::vector<uint8_t> &buffer);
    ErrCode UpdateLiveviewPiexlMap2BinFile(
        const std::shared_ptr<Media::PixelMap> pixelMap, std::vector<uint8_t> &buffer);
private:
    void InitDistributedCollaborateClick();

    void* ExtensionHandle_ = nullptr;
    SUBSCRIBE_ALL_CONNECT subscribeHandler_ = nullptr;
    UNSUBSCRIBE_ALL_CONNECT unSubscribeHandler_ = nullptr;
    TRIGGER_PUSH_WANT_AGENT triggerHandler_ = nullptr;
    UPDATE_LIVEVIEW_ENCODE_CONTENT updateLiveviewEncodeContent_ = nullptr;
    UPDATE_LIVEVIEW_DECODE_CONTENT updateLiveviewDecodeContent_ = nullptr;
    DISTRIBUTED_LIVE_VIEW_OPERATION distributedLiveViewOperation_ = nullptr;
    RESTORE_COLLABORATION_WINDOW restoreCollaborationWindow_ = nullptr;
    DISTRIBUTED_ANCO_NOTIFICATION_CLICK distributedAncoNotificationClick_ = nullptr;
    UPDATE_LIVE_VIEW_BIN_FILE_2_PIEXL_MAP updateLiveviewBinFile2PiexlMap_ = nullptr;
    UPDATE_LIVE_VIEW_PIEXL_MAP_2_BIN_FILE updateLiveviewPiexlMap2BinFile_ = nullptr;
};

#define DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER \
    ::OHOS::DelayedSingleton<DistributedLiveviewAllScenariosExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H
