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

#include "servicenotificationextensiongetbundleicon_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "notification_helper.h"
#include "notification_bundle_icon_info.h"
#include "ans_permission_def.h"
#include "advanced_notification_service.h"

namespace OHOS {
namespace Notification {

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    std::string bundleName = fuzzData->ConsumeRandomLengthString();

    sptr<NotificationBundleIconInfo> bundleIcon = nullptr;
    ErrCode result = NotificationHelper::GetUserGrantedBundleIcon(bundleName, bundleIcon);

    (void)result;
    return true;
}

} // namespace Notification
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);

    return 0;
}
