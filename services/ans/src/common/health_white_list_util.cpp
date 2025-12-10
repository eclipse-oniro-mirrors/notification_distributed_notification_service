/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "health_white_list_util.h"
#include "ans_log_wrapper.h"
#include "notification_constant.h"
#include "bool_wrapper.h"

namespace OHOS {
namespace Notification {
   
HealthWhiteListUtil::HealthWhiteListUtil() = default;
    
HealthWhiteListUtil::~HealthWhiteListUtil() = default;

const std::string OUT_HEALTH_WHITE_LIST = "out_health_white_list";

bool HealthWhiteListUtil::CheckInLiveViewList(const std::string& bundleName)
{
    if (bundleName.empty()) {
        return true;
    }
    nlohmann::json bundles;
    if (!ParseDbDate(bundles)) {
        return true;
    }
    for (const auto& item : bundles) {
        if (item == bundleName) {
            return true;
        }
    }
    ANS_LOGI("not in white list. bundleName = %{public}s", bundleName.c_str());
    return false;
}

void HealthWhiteListUtil::AddExtendFlagForRequest(std::vector<sptr<Notification>> &notifications)
{
    if (notifications.empty()) {
        return;
    }
    
    nlohmann::json bundles;
    if (!ParseDbDate(bundles)) {
        return;
    }
    for (sptr<Notification> notification : notifications) {
        sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
        std::string bundleName = request->GetOwnerBundleName();
        std::shared_ptr<AAFwk::WantParams> extendInfo = request->GetExtendInfo();
        if (extendInfo != nullptr) {
            extendInfo->Remove(OUT_HEALTH_WHITE_LIST);
        }
        if (!bundleName.empty() && NotificationConstant::SlotType::LIVE_VIEW == request->GetSlotType()) {
            for (const auto& item : bundles) {
                if (item == bundleName) {
                    return;
                }
            }
            
            if (extendInfo == nullptr) {
                extendInfo = std::make_shared<AAFwk::WantParams>();
            }
            extendInfo->SetParam(OUT_HEALTH_WHITE_LIST, AAFwk::Boolean::Box(true));
            request->SetExtendInfo(extendInfo);
        }
    }
}

 bool HealthWhiteListUtil::ParseDbDate(nlohmann::json& bundles)
{
    std::string dBvalue;
    NotificationPreferences::GetInstance()->GetKvFromDb(NotificationConstant::HEALTH_BUNDLE_WHITE_LIST,
        dBvalue, SUBSCRIBE_USER_INIT);
    if (dBvalue.empty()) {
        return false;
    }
    bundles = nlohmann::json::parse(dBvalue, nullptr, false);
    if (bundles.is_null() || !bundles.is_array() || bundles.size() <= 0) {
        ANS_LOGE("json data error, %{public}s", dBvalue.c_str());
        return false;
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS
