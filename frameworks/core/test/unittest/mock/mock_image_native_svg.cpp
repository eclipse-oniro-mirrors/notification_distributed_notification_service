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

// This translation unit must NOT include image framework headers: the real
// declaration of OH_ImageSourceNative_SetSvgResourceLimitLevel uses an enum
// parameter whose type name varies across image framework versions. The C
// linkage definition below keeps an ABI-identical signature (pointer + int)
// so it links against any declaration without conflicts.
// IMAGE_SUCCESS = 0, IMAGE_BAD_PARAMETER = 401 (image_common.h).

struct OH_ImageSourceNative;

namespace OHOS {
namespace Notification {
namespace Mock {
bool MockIsSvgResourceLimitLevelFail();
void MockRecordSvgResourceLimitLevelCall(OH_ImageSourceNative* source);
}  // namespace Mock
}  // namespace Notification
}  // namespace OHOS

extern "C" int OH_ImageSourceNative_SetSvgResourceLimitLevel(OH_ImageSourceNative* source, int level)
{
    OHOS::Notification::Mock::MockRecordSvgResourceLimitLevelCall(source);
    if (OHOS::Notification::Mock::MockIsSvgResourceLimitLevelFail()) {
        return 401;
    }
    return 0;
}
