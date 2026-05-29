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
#ifndef BASE_NOTIFICATION_ANS_IMAGE_PIXELMAP_HELPER_H
#define BASE_NOTIFICATION_ANS_IMAGE_PIXELMAP_HELPER_H

#include <string>
#include <memory>

#include "image_source_native.h"
#include "notification_request.h"

namespace OHOS {
namespace Notification {
class ImagePixelmapHelper {
public:
    ImagePixelmapHelper(const sptr<NotificationRequest> &request_, const std::string &imagePath);
    ~ImagePixelmapHelper();

    ErrCode Init();
    uint32_t GetImageWidth();
    uint32_t GetImageHeight();
    uint8_t *GetPixelmapBuff();

private:
    ErrCode CreateImageSource();
    ErrCode CreatePixelMap();
    ErrCode GetImageSourceInfo();
    ErrCode ReadPixelData();
    ErrCode InitRawfileData();

    OH_ImageSourceNative *imageSource_ = nullptr;
    OH_PixelmapNative *resPixMap_ = nullptr;
    OH_ImageSource_Info *imageInfo_ = nullptr;
    sptr<NotificationRequest> request_ = nullptr;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager_ = nullptr;
    Global::Resource::ResourceManager::RawFileDescriptor rawFileDesc_;

    std::string imageFile_{};
    std::unique_ptr<uint8_t[]> pixelmapBuff_;
    uint32_t imageWidth_{0};
    uint32_t imageHeight_{0};
};
}  // namespace Notification
}  // namespace OHOS

#endif