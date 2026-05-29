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

#include "subscriber_image_util.h"

#include "ans_log_wrapper.h"
#include "image_pixelmap_helper.h"
#include "notification_content.h"
#include "notification_live_view_content.h"
#include "string_wrapper.h"
#include "array_wrapper.h"

namespace OHOS {
namespace Notification {
using PictureMap = std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>>;

void SubscriberImageUtil::ProcessPictureOption(
    const std::shared_ptr<Notification> &notification,
    const sptr<PictureOption> &pictureOption)
{
    if (notification == nullptr || pictureOption == nullptr) {
        ANS_LOGE("Notification or pictureOption is null");
        return;
    }
    auto request = notification->GetNotificationRequestPoint();
    if (request == nullptr || request->GetNotificationType() != NotificationContent::Type::LIVE_VIEW) {
        ANS_LOGI("No need parse pic, not liveView");
        return;
    }
    auto content = request->GetContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
        content->GetNotificationContent());
    if (liveViewContent == nullptr || liveViewContent->GetExtraInfo() == nullptr) {
        ANS_LOGI("No need parse pic, no extraInfo");
        return;
    }
    auto picList = pictureOption->GetPreparseLiveViewPicList();
    if (picList.empty()) {
        ANS_LOGI("No need parse pic, empty PicKey");
        return;
    }
    PictureMap pictureMap = liveViewContent->GetPicture();
    auto extraInfo = liveViewContent->GetExtraInfo();
    
    for (const auto &picPathKey : picList) {
        std::vector<std::string> picPaths = GetPicPathsFromParam(extraInfo, picPathKey);
        if (picPaths.empty()) {
            continue;
        }
        for (const auto &picPath : picPaths) {
            auto pixelMap = GetPixelMapByRes(request, picPath);
            if (pixelMap != nullptr) {
                pictureMap[picPathKey].push_back(std::move(pixelMap));
                ANS_LOGI("Parse picPath(%{public}s) success", picPath.c_str());
            }
        }
    }
    liveViewContent->SetPicture(pictureMap);
}

std::unique_ptr<Media::PixelMap> SubscriberImageUtil::GetPixelMapByRes(
    const sptr<NotificationRequest> &request,
    const std::string &resPath)
{
    ImagePixelmapHelper imagePixelmapHelper(request, resPath);
    ANS_LOGI("GetPixelMapByRes resPath: %{public}s", resPath.c_str());
    auto ret = imagePixelmapHelper.Init();
    if (ret != ERR_OK) {
        ANS_LOGE("init failed pic %{public}s", resPath.c_str());
        return nullptr;
    }
    auto width = imagePixelmapHelper.GetImageWidth();
    auto height = imagePixelmapHelper.GetImageHeight();
    Media::InitializationOptions opts;
    opts.size.width = static_cast<int32_t>(width);
    opts.size.height = static_cast<int32_t>(height);
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.srcPixelFormat = Media::PixelFormat::BGRA_8888;
    auto pixelMap = Media::PixelMap::Create(
        reinterpret_cast<uint32_t *>(imagePixelmapHelper.GetPixelmapBuff()),
        width * height, 0, width, opts, true);
    return pixelMap;
}

std::vector<std::string> SubscriberImageUtil::GetPicPathsFromParam(
    const std::shared_ptr<AAFwk::WantParams>& extraInfo,
    const std::string& picPathKey)
{
    std::vector<std::string> picPaths;
    if (!extraInfo->HasParam(picPathKey)) {
        ANS_LOGI("No param found, picPathKey: %{public}s", picPathKey.c_str());
        return picPaths;
    }
    auto param = extraInfo->GetParam(picPathKey);
    if (ExtractFromString(param, picPaths)) {
        return picPaths;
    }
    if (ExtractFromStringArray(param, picPaths)) {
        return picPaths;
    }
    ANS_LOGI("Param is not string or Array<string>, picPathKey: %{public}s", picPathKey.c_str());
    return picPaths;
}

bool SubscriberImageUtil::ExtractFromString(
    const sptr<AAFwk::IInterface>& param,
    std::vector<std::string>& picPaths)
{
    AAFwk::IString* iString = AAFwk::IString::Query(param);
    if (iString == nullptr) {
        return false;
    }
    
    std::string path = AAFwk::String::Unbox(iString);
    if (!path.empty()) {
        picPaths.push_back(path);
    }
    
    return true;
}

bool SubscriberImageUtil::ExtractFromStringArray(
    const sptr<AAFwk::IInterface>& param,
    std::vector<std::string>& picPaths)
{
    AAFwk::IArray* iArray = AAFwk::IArray::Query(param);
    if (iArray == nullptr || !AAFwk::Array::IsStringArray(iArray)) {
        return false;
    }
    long size = 0;
    if (iArray->GetLength(size) != ERR_OK) {
        return false;
    }
    if (size == 0) {
        ANS_LOGI("Empty Array<string> found");
        return true;
    }
    
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> iface = nullptr;
        if (iArray->Get(i, iface) != ERR_OK || iface == nullptr) {
            continue;
        }
        AAFwk::IString* element = AAFwk::IString::Query(iface);
        if (element == nullptr) {
            continue;
        }
        std::string path = AAFwk::String::Unbox(element);
        if (!path.empty()) {
            picPaths.push_back(path);
        }
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS