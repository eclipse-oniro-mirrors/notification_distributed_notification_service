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

#include "distributed_liveview_all_scenarios_extension_wrapper.h"

#include <dlfcn.h>
#include <string>

namespace OHOS::Notification {
const std::string DISTRIBUTED_EXTENTION_LIVEVIEW_ALL_SCENARIOS_PATH = "libliveview.z.so";
DistributedLiveviewAllScenariosExtensionWrapper::DistributedLiveviewAllScenariosExtensionWrapper()
{
    InitExtentionWrapper();
}

DistributedLiveviewAllScenariosExtensionWrapper::~DistributedLiveviewAllScenariosExtensionWrapper()
{
    CloseExtentionWrapper();
}

void DistributedLiveviewAllScenariosExtensionWrapper::InitExtentionWrapper()
{
    ExtensionHandle_ = dlopen(DISTRIBUTED_EXTENTION_LIVEVIEW_ALL_SCENARIOS_PATH.c_str(), RTLD_NOW);
    if (ExtensionHandle_ == nullptr) {
        ANS_LOGE("distributed liveview all scenarios extension wrapper dlopen failed, error: %{public}s", dlerror());
        return;
    }

    updateLiveviewEncodeContent_ = (UPDATE_LIVEVIEW_ENCODE_CONTENT)dlsym(ExtensionHandle_,
        "UpdateLiveviewEncodeTlv");
    if (updateLiveviewEncodeContent_ == nullptr) {
        ANS_LOGE("distributed liveview all scenarios extension wrapper dlsym updateLiveviewEncodeContent_ failed, "
            "error: %{public}s", dlerror());
        return;
    }

    updateLiveviewDecodeContent_ = (UPDATE_LIVEVIEW_DECODE_CONTENT)dlsym(ExtensionHandle_,
        "UpdateLiveviewDecodeTlv");
    if (updateLiveviewDecodeContent_ == nullptr) {
        ANS_LOGE("distributed liveview all scenarios extension wrapper dlsym updateLiveviewDecodeContent_ failed, "
            "error: %{public}s", dlerror());
        return;
    }

    triggerHandler_ = (TRIGGER_PUSH_WANT_AGENT)dlsym(ExtensionHandle_, "TriggerPushWantAgent");
    if (triggerHandler_ == nullptr) {
        ANS_LOGE("distributed liveview all trigger failed, error: %{public}s", dlerror());
        return;
    }
    subscribeHandler_ = (SUBSCRIBE_ALL_CONNECT)dlsym(ExtensionHandle_, "SubscribeAllConnect");
    if (subscribeHandler_ == nullptr) {
        ANS_LOGE("distributed subscribe all conncet failed, error: %{public}s", dlerror());
        return;
    }
    unSubscribeHandler_ = (UNSUBSCRIBE_ALL_CONNECT)dlsym(ExtensionHandle_, "UnSubscribeAllConnect");
    if (unSubscribeHandler_ == nullptr) {
        ANS_LOGE("distributed unsubscribe all conncet failed, error: %{public}s", dlerror());
        return;
    }

    InitDistributedCollaborateClick();
    ANS_LOGI("distributed liveview all scenarios extension wrapper init success");
}

void DistributedLiveviewAllScenariosExtensionWrapper::InitDistributedCollaborateClick()
{
    distributedLiveViewOperation_ =
        (DISTRIBUTED_LIVE_VIEW_OPERATION)dlsym(ExtensionHandle_, "DistributedLiveViewOperation");
    if (distributedLiveViewOperation_ == nullptr) {
        ANS_LOGE("distributed liveView operation failed, error: %{public}s", dlerror());
        return;
    }

    restoreCollaborationWindow_ =
        (RESTORE_COLLABORATION_WINDOW)dlsym(ExtensionHandle_, "RestoreCollaborationWindow");
    if (restoreCollaborationWindow_ == nullptr) {
        ANS_LOGE("distributed restore collaboration window failed, error: %{public}s", dlerror());
        return;
    }

    distributedAncoNotificationClick_ =
        (DISTRIBUTED_ANCO_NOTIFICATION_CLICK)dlsym(ExtensionHandle_, "DistributedAncoNotificationClick");
    if (distributedAncoNotificationClick_ == nullptr) {
        ANS_LOGE("distributed anco notification click failed, error: %{public}s", dlerror());
        return;
    }

    updateLiveviewBinFile2PiexlMap_ =
        (UPDATE_LIVE_VIEW_BIN_FILE_2_PIEXL_MAP)dlsym(ExtensionHandle_, "UpdateLiveviewBinFile2PiexlMap");
    if (updateLiveviewBinFile2PiexlMap_ == nullptr) {
        ANS_LOGE("update liveview Bin File 2 PiexlMap failed, error: %{public}s", dlerror());
        return;
    }

    updateLiveviewPiexlMap2BinFile_ =
        (UPDATE_LIVE_VIEW_PIEXL_MAP_2_BIN_FILE)dlsym(ExtensionHandle_, "UpdateLiveviewPiexlMap2BinFile");
    if (updateLiveviewPiexlMap2BinFile_ == nullptr) {
        ANS_LOGE("update liveview PiexlMap 2 Bin File failed, error: %{public}s", dlerror());
        return;
    }
}

void DistributedLiveviewAllScenariosExtensionWrapper::CloseExtentionWrapper()
{
    if (ExtensionHandle_ != nullptr) {
        dlclose(ExtensionHandle_);
        subscribeHandler_ = nullptr;
        unSubscribeHandler_ = nullptr;
        ExtensionHandle_ = nullptr;
        triggerHandler_ = nullptr;
        updateLiveviewEncodeContent_ = nullptr;
        updateLiveviewDecodeContent_ = nullptr;
        distributedLiveViewOperation_ = nullptr;
        restoreCollaborationWindow_ = nullptr;
        distributedAncoNotificationClick_ = nullptr;
        updateLiveviewBinFile2PiexlMap_ = nullptr;
        updateLiveviewPiexlMap2BinFile_ = nullptr;
    }
    ANS_LOGI("distributed liveview all scenarios extension wrapper close success");
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::UpdateLiveviewEncodeContent(
    const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer, const std::string& deviceType)
{
    if (updateLiveviewEncodeContent_ == nullptr) {
        ANS_LOGE("distributed UpdateLiveviewEncodeContent wrapper symbol failed");
        return 0;
    }
    return updateLiveviewEncodeContent_(request, buffer, deviceType);
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::UpdateLiveviewDecodeContent(
    const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer, const std::string& deviceType)
{
    if (updateLiveviewDecodeContent_ == nullptr) {
        ANS_LOGE("distributed UpdateLiveviewDecodeContent wrapper symbol failed");
        return 0;
    }
    return updateLiveviewDecodeContent_(request, buffer, deviceType);
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::TriggerPushWantAgent(
    const sptr<NotificationRequest> &request, int32_t actionType, const AAFwk::WantParams extraInfo)
{
    if (triggerHandler_ == nullptr) {
        ANS_LOGE("distributed TriggerPushWantAgent wrapper symbol failed");
        return 0;
    }
    return triggerHandler_(request, actionType, extraInfo);
}

void DistributedLiveviewAllScenariosExtensionWrapper::SubscribeAllConnect(bool isPadOrPc)
{
    if (subscribeHandler_ == nullptr) {
        ANS_LOGE("Subscribe all connect wrapper symbol failed");
        return;
    }
    subscribeHandler_(isPadOrPc);
    return;
}

void DistributedLiveviewAllScenariosExtensionWrapper::UnSubscribeAllConnect()
{
    if (unSubscribeHandler_ == nullptr) {
        ANS_LOGE("UnSubscribe all connect wrapper symbol failed");
        return;
    }
    unSubscribeHandler_();
    return;
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::DistributedLiveViewOperation(
    sptr<NotificationRequest> &request, const int32_t operationType, const int32_t btnIndex)
{
    if (distributedLiveViewOperation_ == nullptr) {
        ANS_LOGE("distributed liveView operation wrapper symbol failed");
        return 0;
    }
    return distributedLiveViewOperation_(request, operationType, btnIndex);
}

int32_t DistributedLiveviewAllScenariosExtensionWrapper::RestoreCollaborationWindow(const std::string &networkId)
{
    if (restoreCollaborationWindow_ == nullptr) {
        ANS_LOGE("restore collaboration window wrapper symbol failed");
        return 0;
    }
    return restoreCollaborationWindow_(networkId);
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::DistributedAncoNotificationClick(
    const sptr<NotificationRequest> &request, bool &triggerWantInner)
{
    if (distributedAncoNotificationClick_ == nullptr) {
        ANS_LOGE("distributed anco notification click wrapper symbol failed");
        return 0;
    }
    return distributedAncoNotificationClick_(request, triggerWantInner);
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::UpdateLiveviewBinFile2PiexlMap(
    std::shared_ptr<Media::PixelMap> &pixelMap, const std::vector<uint8_t> &buffer)
{
    if (updateLiveviewBinFile2PiexlMap_ == nullptr) {
        ANS_LOGE("update liveview Bin File 2 PiexlMap wrapper symbol failed");
        return 0;
    }
    return updateLiveviewBinFile2PiexlMap_(pixelMap, buffer);
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::UpdateLiveviewPiexlMap2BinFile(
    const std::shared_ptr<Media::PixelMap> pixelMap, std::vector<uint8_t> &buffer)
{
    if (updateLiveviewPiexlMap2BinFile_ == nullptr) {
        ANS_LOGE("update liveview PiexlMap 2 Bin File wrapper symbol failed");
        return 0;
    }
    return updateLiveviewPiexlMap2BinFile_(pixelMap, buffer);
}
}
