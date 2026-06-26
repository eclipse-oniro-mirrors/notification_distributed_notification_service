/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_OHOS_NOTIFICATIONMANAGER_INCLUDE_COMMAND_OUTPUT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_OHOS_NOTIFICATIONMANAGER_INCLUDE_COMMAND_OUTPUT_H

#include <string>
#include "nlohmann/json.hpp"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"

namespace OHOS {
namespace Notification {
void OutputSuccess(const nlohmann::json& data, std::string& output);
void OutputError(const std::string& errCode, const std::string& errMsg,
    const std::string& suggestion, std::string& output);
void OutputApiError(ErrCode internalErrCode, const std::string& action,
    const std::string& exampleCmd, std::string& output);
}  // namespace Notification
}  // namespace OHOS
#endif
