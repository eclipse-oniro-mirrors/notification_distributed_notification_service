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

#ifndef MOCK_NOTIFICATION_WANT_PARAMS_BUILDER_H
#define MOCK_NOTIFICATION_WANT_PARAMS_BUILDER_H

#include "mock_fuzz_object.h"
#include "want.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {

template <>
AAFwk::WantParams* ObjectBuilder<AAFwk::WantParams>::Build(FuzzedDataProvider *fdp)
{
    AAFwk::Want want;
    for (size_t i = 0; i < fdp->ConsumeIntegralInRange<size_t>(0, 10); i++) {
        want.SetParam(fdp->ConsumeRandomLengthString(10), fdp->ConsumeRandomLengthString(10));
        want.SetParam(fdp->ConsumeRandomLengthString(10), fdp->ConsumeIntegral<int>());
    }
    ANS_LOGE("Build mock veriables");
    return new AAFwk::WantParams(want.GetParams());
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_WANT_PARAMS_BUILDER_H
