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

#ifndef MOCK_NOTIFICATION_CHECK_REQUEST_BUILDER_H
#define MOCK_NOTIFICATION_CHECK_REQUEST_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_check_request.h"

namespace OHOS {
namespace Notification {

const int MAX_SLOT_TYPE = 8;
const int MAX_CONTENT_TYPE = 10;
const int MAX_ARRAY_SIZE = 10;
const int MAX_STRING_SIZE = 20;

template <>
NotificationCheckRequest* ObjectBuilder<NotificationCheckRequest>::Build(FuzzedDataProvider *fdp)
{
    auto checkRequest = new NotificationCheckRequest();

    checkRequest->SetContentType(static_cast<NotificationContent::Type>(
            fdp->ConsumeIntegralInRange<int>(0, MAX_CONTENT_TYPE)));

    checkRequest->SetSlotType(static_cast<OHOS::Notification::NotificationConstant::SlotType>(
            fdp->ConsumeIntegralInRange<int>(0, MAX_SLOT_TYPE)));
    std::vector<std::string> extraKeys;
    for (int i = 0; i < fdp->ConsumeIntegralInRange(0, MAX_ARRAY_SIZE); i++) {
        extraKeys.push_back(fdp->ConsumeRandomLengthString(MAX_STRING_SIZE));
    }
    checkRequest->SetExtraKeys(extraKeys);
    checkRequest->SetUid(fdp->ConsumeIntegral<int32_t>());

    ANS_LOGE("Build mock veriables");
    return checkRequest;
}
}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_CHECK_REQUEST_BUILDER_H