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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_ANALYTICS_UTIL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_ANALYTICS_UTIL_H

#include <string>
#include <map>
#include "notification_request.h"

namespace OHOS {
namespace Notification {
constexpr const int32_t PUBLISH_ERROR_EVENT_CODE = 0;
constexpr const int32_t ANS_CUSTOMIZE_CODE = 7;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t OPERATION_DELETE_BRANCH = 2;
constexpr const int32_t BRANCH1_ID = 1;
constexpr const int32_t BRANCH2_ID = 2;
constexpr const int32_t BRANCH3_ID = 3;
constexpr const int32_t BRANCH4_ID = 4;
constexpr const int32_t BRANCH6_ID = 6;
constexpr const int32_t BRANCH7_ID = 7;
constexpr const int32_t BRANCH8_ID = 8;
constexpr const int32_t BRANCH9_ID = 9;

class AnalyticsUtil {
public:
    static AnalyticsUtil& GetInstance();
    void InitHACallBack(std::function<void(int32_t, int32_t, uint32_t, std::string)> callback);
    void InitSendReportCallBack(std::function<void(int32_t, int32_t, std::string)> callback);
    void SendHaReport(int32_t eventCode, int32_t errorCode, uint32_t branchId,
        const std::string& errorReason, int32_t code = -1);
    void SendEventReport(int32_t messageType, int32_t errCode, const std::string& errorReason);
    void AbnormalReporting(int32_t eventCode, int result, uint32_t branchId,
        const std::string &errorReason);
    void OperationalReporting(int branchId, int32_t slotType);

private:
    AnalyticsUtil() = default;
    ~AnalyticsUtil() = default;
    std::function<void(int32_t, int32_t, uint32_t, std::string)> haCallback_ = nullptr;
    std::function<void(int32_t, int32_t, std::string)> sendReportCallback_ = nullptr;
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_ANALYTICS_UTIL_H
