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

#ifndef BASE_NOTIFICATION_MOCK_IMAGE_NATIVE_H
#define BASE_NOTIFICATION_MOCK_IMAGE_NATIVE_H

#include "image_source_native.h"
#include "raw_file.h"

namespace OHOS {
namespace Notification {
namespace Mock {

void MockOHImageSourceNativeCreateFromRawFileFail(bool fail);
void MockOHImageSourceNativeCreateFromRawFileReturnNull(bool returnNull);
void MockOHImageSourceNativeCreatePixelmapFail(bool fail);
void MockOHImageSourceNativeCreatePixelmapReturnNull(bool returnNull);
void MockOHImageSourceNativeGetImageInfoFail(bool fail);
void MockOHImageSourceInfoGetWidthFail(bool fail);
void MockOHImageSourceInfoGetHeightFail(bool fail);
void MockOHPixelmapNativeReadPixelsFail(bool fail);
void MockOHImageSourceInfoCreateFail(bool fail);
void MockOHImageSourceInfoCreateReturnNull(bool returnNull);
void MockOHDecodingOptionsCreateReturnNull(bool returnNull);

void MockSetImageWidth(uint32_t width);
void MockSetImageHeight(uint32_t height);

void MockResetImageNativeState();

}  // namespace Mock
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_MOCK_IMAGE_NATIVE_H