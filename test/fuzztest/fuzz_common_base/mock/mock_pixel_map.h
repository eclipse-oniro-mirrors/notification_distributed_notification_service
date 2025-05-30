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

#ifndef MOCK_NOTIFICATION_PIXEL_MAP_BUILDER_H
#define MOCK_NOTIFICATION_PIXEL_MAP_BUILDER_H

#include "mock_fuzz_object.h"

#include "pixel_map.h"
#include <fstream>

namespace OHOS {
namespace Notification {

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;

std::unique_ptr<Media::PixelMap> GetPixelMapFromOpts(FuzzedDataProvider *fdp,
    Media::PixelFormat pixelFormat = Media::PixelFormat::UNKNOWN)
{
    int32_t width = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LENGTH_MODULO);
    int32_t height = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LENGTH_MODULO);
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.srcPixelFormat = pixelFormat == Media::PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(fdp->ConsumeIntegralInRange<int32_t>(0, PIXELFORMAT_MODULO)) : pixelFormat;
    opts.pixelFormat = pixelFormat == Media::PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(fdp->ConsumeIntegralInRange<int32_t>(0, PIXELFORMAT_MODULO)) : pixelFormat;
    opts.alphaType = static_cast<Media::AlphaType>(fdp->ConsumeIntegralInRange<int32_t>(0, ALPHATYPE_MODULO));
    opts.scaleMode = static_cast<Media::ScaleMode>(fdp->ConsumeIntegralInRange<int32_t>(0, SCALEMODE_MODULO));
    opts.editable = fdp->ConsumeBool();
    opts.useSourceIfMatch = fdp->ConsumeBool();
    return Media::PixelMap::Create(opts);
}

template <>
std::shared_ptr<Media::PixelMap> ObjectBuilder<Media::PixelMap>::BuildSharedPtr(FuzzedDataProvider *fdp)
{
    auto pixelMap = GetPixelMapFromOpts(fdp);
    if (pixelMap == nullptr) {
        return nullptr;
    }
    ANS_LOGE("Build mock veriables");
    return std::shared_ptr<Media::PixelMap>(std::move(pixelMap.release()));
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_PIXEL_MAP_BUILDER_H
