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

#ifndef MOCK_NOTIFICATION_DISABLE_BUILDER_H
#define MOCK_NOTIFICATION_DISABLE_BUILDER_H

#include "mock_fuzz_object.h"
#include "mock_notification_content.h"
#include "mock_notification_distributed_options.h"
#include "mock_notification_template.h"
#include "mock_notification_flags.h"
#include "mock_notification_bundle_option.h"
#include "mock_notification_action_button.h"
#include "notification_request.h"

namespace OHOS {
namespace Notification {
constexpr int32_t DONOTDISTURB_TYPE_LENGTH = 3;
template <>
NotificationSlot* ObjectBuilder<NotificationSlot>::Build(FuzzedDataProvider *fdp)
{
    auto disturbDate = new NotificationDoNotDisturbDate();
    disturbDate->SetBeginDate(fdp->ConsumeIntegral<int64_t>());
    disturbDate->SetEndDate(fdp->ConsumeIntegral<int64_t>());
    disturbDate->SetDoNotDisturbType(static_cast<NotificationConstant::NotificationConstant::DoNotDisturbType>(
        fdp->ConsumeIntegralInRange<int>(0, DONOTDISTURB_TYPE_LENGTH)));
    return slot;
}
} // namespace Notification
} // namespace OHOS
#endif // MOCK_NOTIFICATION_DISABLE_BUILDER_H
