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

#include "image_pixelmap_helper.h"

#include <algorithm>

#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "application_context.h"
#include "pixelmap_native_impl.h"

namespace OHOS {
namespace Notification {
ImagePixelmapHelper::ImagePixelmapHelper(const sptr<NotificationRequest> &request, const std::string &imageFile)
{
    imageFile_ = imageFile;
    request_ = request;
    rawFileDesc_ = {0, 0, 0};
}

ImagePixelmapHelper::~ImagePixelmapHelper()
{
    imageWidth_ = 0;
    imageHeight_ = 0;
    if (imageSource_ != nullptr) {
        OH_ImageSourceNative_Release(imageSource_);
        imageSource_ = nullptr;
    }

    if (imageInfo_ != nullptr) {
        OH_ImageSourceInfo_Release(imageInfo_);
        imageInfo_ = nullptr;
    }

    if (resourceManager_ != nullptr) {
        auto ret = resourceManager_->CloseRawFileDescriptor(imageFile_);
        if (ret != ERR_OK) {
            ANS_LOGI("CloseRawFileDescriptor fail.");
        }
        resourceManager_ = nullptr;
    }

    request_ = nullptr;
    rawFileDesc_ = {0, 0, 0};
}

ErrCode ImagePixelmapHelper::GetPixelMap(std::shared_ptr<Media::PixelMap> &pixelMap)
{
    if (imageFile_.empty()) {
        ANS_LOGE("Init failed, imagePath is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (request_ == nullptr) {
        ANS_LOGE("Init failed, request is null.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    ErrCode ret = InitRawfileData();
    if (ret != ERR_OK) {
        ANS_LOGE("ImagePixelmapHelper CreateImageSource failed.");
        return ret;
    }

    ret = CreateImageSource();
    if (ret != ERR_OK) {
        ANS_LOGE("ImagePixelmapHelper CreateImageSource failed.");
        return ret;
    }

    ret = CreatePixelMap();
    if (ret != ERR_OK) {
        ANS_LOGE("ImagePixelmapHelper CreatePixelMap failed.");
        return ret;
    }
    pixelMap = pixelMap_;
    return ERR_OK;
}

ErrCode ImagePixelmapHelper::InitRawfileData()
{
    auto bundleName = request_->GetOwnerBundleName();
    auto appContext = OHOS::AbilityRuntime::Context::GetApplicationContext();
    if (appContext == nullptr) {
        ANS_LOGE("Get appContext nullptr.");
        return ERR_ANS_INNER_PERMISSION_DENIED;
    }
    if (!appContext->CreateBundleContext(bundleName)) {
        ANS_LOGE("CreateBundleContext failed.");
        return ERR_ANS_INNER_PERMISSION_DENIED;
    }
    resourceManager_ = appContext->CreateBundleContext(bundleName)->GetResourceManager();
    if (!resourceManager_) {
        ANS_LOGE("Get resourceManager nullptr.");
        return ERR_ANS_INNER_PERMISSION_DENIED;
    }
    auto result = resourceManager_->GetRawFileDescriptor(imageFile_, rawFileDesc_);
    if (result != ERR_OK) {
        ANS_LOGE("GetRawFileDescriptor fail.");
        return result;
    }
    return ERR_OK;
}

ErrCode ImagePixelmapHelper::CreateImageSource()
{
    RawFileDescriptor rawFileDesc{rawFileDesc_.fd, rawFileDesc_.offset, rawFileDesc_.length};
    Image_ErrorCode imageErrCode = OH_ImageSourceNative_CreateFromRawFile(&rawFileDesc, &imageSource_);
    if (imageErrCode != IMAGE_SUCCESS || imageSource_ == nullptr) {
        ANS_LOGE("OH_ImageSourceNative_CreateFromUri failed, errCode: %{public}d.", imageErrCode);
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return ERR_OK;
}

ErrCode ImagePixelmapHelper::CreatePixelMap()
{
    ErrCode ret = GetImageSourceInfo();
    if (ret != ERR_OK) {
        return ret;
    }
    constexpr uint32_t MAX_SIZE = 500;
    uint32_t targetWidth = imageWidth_;
    uint32_t targetHeight = imageHeight_;
    if (imageWidth_ > MAX_SIZE || imageHeight_ > MAX_SIZE) {
        float scale = std::min(static_cast<float>(MAX_SIZE) / imageWidth_,
            static_cast<float>(MAX_SIZE) / imageHeight_);
        targetWidth = static_cast<uint32_t>(imageWidth_ * scale);
        targetHeight = static_cast<uint32_t>(imageHeight_ * scale);
        ANS_LOGI("Start scale image width: %{public}u, height: %{public}u", targetWidth, targetHeight);
    }

    OH_DecodingOptions *ops = nullptr;
    OH_DecodingOptions_Create(&ops);
    Image_Size desiredSize = {targetWidth, targetHeight};
    OH_DecodingOptions_SetDesiredSize(ops, &desiredSize);
    int32_t format = static_cast<int32_t>(Media::PixelFormat::ASTC_4x4);
    OH_DecodingOptions_SetPixelFormat(ops, format);
    OH_PixelmapNative *resPixMap_ = nullptr;
    Image_ErrorCode imageErrCode = OH_ImageSourceNative_CreatePixelmap(imageSource_, ops, &resPixMap_);
    OH_DecodingOptions_Release(ops);
    if (imageErrCode != IMAGE_SUCCESS || resPixMap_ == nullptr) {
        ANS_LOGE("OH_ImageSourceNative_CreatePixelmap failed, errCode: %{public}d.", imageErrCode);
        OH_PixelmapNative_Release(resPixMap_);
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    pixelMap_ = resPixMap_->GetInnerPixelmap();
    OH_PixelmapNative_Release(resPixMap_);
    return ERR_OK;
}

ErrCode ImagePixelmapHelper::GetImageSourceInfo()
{
    Image_ErrorCode imageErrCode = OH_ImageSourceInfo_Create(&imageInfo_);
    if (imageErrCode != IMAGE_SUCCESS || imageInfo_ == nullptr) {
        ANS_LOGE("OH_ImageSourceInfo_Create failed, errCode: %{public}d.", imageErrCode);
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    imageErrCode = OH_ImageSourceNative_GetImageInfo(imageSource_, 0, imageInfo_);
    if (imageErrCode != IMAGE_SUCCESS) {
        ANS_LOGE("OH_ImageSourceNative_GetImageInfo failed, errCode: %{public}d.", imageErrCode);
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    imageErrCode = OH_ImageSourceInfo_GetWidth(imageInfo_, &imageWidth_);
    if (imageErrCode != IMAGE_SUCCESS) {
        ANS_LOGE("OH_ImageSourceInfo_GetWidth failed, errCode: %{public}d.", imageErrCode);
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    imageErrCode = OH_ImageSourceInfo_GetHeight(imageInfo_, &imageHeight_);
    if (imageErrCode != IMAGE_SUCCESS) {
        ANS_LOGE("OH_ImageSourceInfo_GetHeight failed, errCode: %{public}d.", imageErrCode);
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    ANS_LOGI("GetImageSourceInfo width:%{public}d, height:%{public}d.", imageWidth_, imageHeight_);
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS