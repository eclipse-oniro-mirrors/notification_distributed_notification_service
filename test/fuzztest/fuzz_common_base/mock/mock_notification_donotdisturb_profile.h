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

#ifndef MOCK_NOTIFICATION_DONOT_DISTURB_PROFILE_BUILDER_H
#define MOCK_NOTIFICATION_DONOT_DISTURB_PROFILE_BUILDER_H

#include "mock_fuzz_object.h"
#include "mock_notification_bundle_option.h"
#include "notification_do_not_disturb_profile.h"

namespace OHOS {
namespace Notification {

template <>
NotificationDoNotDisturbProfile* ObjectBuilder<NotificationDoNotDisturbProfile>::Build(FuzzedDataProvider *fdp)
{
    int64_t id = fdp->ConsumeIntegral<int64_t>();
    std::string profileName = fdp->ConsumeRandomLengthString();
    std::vector<NotificationBundleOption> trustList;
    size_t listSize = fdp->ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < listSize; ++i) {
        std::unique_ptr<NotificationBundleOption> bundleOption(
            ObjectBuilder<NotificationBundleOption>::Build(fdp));
        trustList.push_back(*bundleOption);
    }
    return new NotificationDoNotDisturbProfile(id, profileName, trustList);
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_DONOT_DISTURB_PROFILE_BUILDER_H
