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

#ifndef MOCK_NOTIFICATION_BUNDLE_OPTION_BUILDER_H
#define MOCK_NOTIFICATION_BUNDLE_OPTION_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {

template <>
NotificationBundleOption* ObjectBuilder<NotificationBundleOption>::Build(FuzzedDataProvider *fdp)
{
    std::string bundleName = fdp->ConsumeRandomLengthString(32);
    int32_t uid = fdp->ConsumeIntegral<int32_t>();
    auto bundleOption = new NotificationBundleOption(bundleName, uid);
    bundleOption->SetInstanceKey(fdp->ConsumeIntegral<int32_t>());
    bundleOption->SetAppInstanceKey(fdp->ConsumeRandomLengthString(16));
    bundleOption->SetAppIndex(fdp->ConsumeIntegral<int32_t>());
    ANS_LOGE("Build mock veriables");
    return bundleOption;
}
}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_BUNDLE_OPTION_BUILDER_H
