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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_EXT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_EXT_H

#include <string>

#include "errors.h"
#include "nocopyable.h"
#include "notification.h"
#include "notification_request.h"
#include "notification_unified_group_Info.h"
#include "singleton.h"
#include "advanced_aggregation_data_roaming_observer.h"

namespace OHOS::Notification {
class ExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(ExtensionWrapper);
public:
    DISALLOW_COPY_AND_MOVE(ExtensionWrapper);
    void InitExtentionWrapper();
    typedef void (*SYNC_ADDITION_CONFIG)(const std::string& key, const std::string& value);
    typedef void (*UPDATE_BY_CANCEL)(const std::vector<sptr<Notification>>& notifications, int deleteType);
    typedef ErrCode (*GET_UNIFIED_GROUP_INFO)(const sptr<NotificationRequest> &request);
    typedef void (*UPDATE_GROUP_INFO)(std::string &key, std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo);
    typedef void (*INIT_SUMMARY)(UPDATE_GROUP_INFO func);
    typedef void (*SET_LOCAL_SWITCH)(bool status);

    void SyncAdditionConfig(const std::string& key, const std::string& value);
    void UpdateByCancel(const std::vector<sptr<Notification>>& notifications, int deleteReason);
    ErrCode GetUnifiedGroupInfo(const sptr<NotificationRequest> &request);
    void RegisterDataSettingObserver();
    void SetlocalSwitch(std::string &enable);

private:
    static int32_t convertToDelType(int32_t deleteReason);

    void* extensionWrapperHandle_ = nullptr;
    SYNC_ADDITION_CONFIG syncAdditionConfig_ = nullptr;
    UPDATE_BY_CANCEL updateByCancel_ = nullptr;
    GET_UNIFIED_GROUP_INFO getUnifiedGroupInfo_ = nullptr;
    INIT_SUMMARY initSummary_ = nullptr;
    SET_LOCAL_SWITCH setLocalSwitch_ = nullptr;
    sptr<AdvancedAggregationDataRoamingObserver> aggregationRoamingObserver_;
};

#define EXTENTION_WRAPPER ::OHOS::DelayedSingleton<ExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_EXT_H
