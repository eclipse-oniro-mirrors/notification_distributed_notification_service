/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "image_source.h"
#undef private
#undef protected
#include "mock_image_related_class.h"

namespace {
bool g_mockImageSourceCreateImageSourceRet = true;
uint32_t g_mockImageSourceCreateImageSourceErrorCode = 0;
bool g_mockImageSourceCreatePixelMapRet = true;
uint32_t g_mockImageSourceCreatePixelMapErrorCode = 0;
uint32_t g_mockImageSourceGetSupportedFormatsRet = 0;
}

void MockImageSourceCreateImageSource(bool mockRet, uint32_t errorCode)
{
    g_mockImageSourceCreateImageSourceRet = mockRet;
    g_mockImageSourceCreateImageSourceErrorCode = errorCode;
}

void MockImageSourceCreatePixelMap(bool mockRet, uint32_t errorCode)
{
    g_mockImageSourceCreatePixelMapRet = mockRet;
    g_mockImageSourceCreatePixelMapErrorCode = errorCode;
}

void MockImageSourceGetSupportedFormats(uint32_t mockRet)
{
    g_mockImageSourceGetSupportedFormatsRet = mockRet;
}

void MockResetImageSourceState()
{
    g_mockImageSourceCreateImageSourceRet = true;
    g_mockImageSourceCreateImageSourceErrorCode = 0;
    g_mockImageSourceCreatePixelMapRet = true;
    g_mockImageSourceCreatePixelMapErrorCode = 0;
}

namespace OHOS {
namespace Media {
using namespace ImagePlugin;

uint32_t ImageSource::GetSupportedFormats(std::set<std::string> &formats)
{
    return g_mockImageSourceGetSupportedFormatsRet;
}

std::unique_ptr<ImageSource> ImageSource::CreateImageSource(std::unique_ptr<std::istream> is,
    const SourceOptions &opts, uint32_t &errorCode)
{
    return nullptr;
}

std::unique_ptr<ImageSource> ImageSource::CreateImageSource(const uint8_t *data, uint32_t size,
    const SourceOptions &opts, uint32_t &errorCode, bool isUserBuffer)
{
    errorCode = g_mockImageSourceCreateImageSourceErrorCode;
    if (g_mockImageSourceCreateImageSourceRet) {
        std::unique_ptr<OHOS::Media::SourceStream> stream = nullptr;
        OHOS::Media::SourceOptions opts;
        ImageSource *sourcePtr = new (std::nothrow) ImageSource(std::move(stream), opts);
        return std::unique_ptr<ImageSource>(sourcePtr);
    }
    return nullptr;
}

std::unique_ptr<ImageSource> ImageSource::CreateImageSource(const std::string &pathName, const SourceOptions &opts,
    uint32_t &errorCode)
{
    errorCode = g_mockImageSourceCreateImageSourceErrorCode;
    if (g_mockImageSourceCreateImageSourceRet) {
        std::unique_ptr<OHOS::Media::SourceStream> stream = nullptr;
        OHOS::Media::SourceOptions opts;
        ImageSource *sourcePtr = new (std::nothrow) ImageSource(std::move(stream), opts);
        return std::unique_ptr<ImageSource>(sourcePtr);
    }
    return nullptr;
}

std::unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, const SourceOptions &opts,
    uint32_t &errorCode)
{
    return nullptr;
}

std::unique_ptr<ImageSource> ImageSource::CreateIncrementalImageSource(const IncrementalSourceOptions &opts,
    uint32_t &errorCode)
{
    return nullptr;
}

void ImageSource::Reset()
{}

std::unique_ptr<PixelMap> ImageSource::CreatePixelMapEx(uint32_t index, const DecodeOptions &opts, uint32_t &errorCode)
{
    errorCode = g_mockImageSourceCreatePixelMapErrorCode;
    if (g_mockImageSourceCreatePixelMapRet) {
        PixelMap *pixelMap = new (std::nothrow) PixelMap();
        return std::unique_ptr<PixelMap>(pixelMap);
    }
    return nullptr;
}

std::unique_ptr<PixelMap> ImageSource::CreatePixelMap(uint32_t index, const DecodeOptions &opts, uint32_t &errorCode)
{
    return nullptr;
}

std::unique_ptr<IncrementalPixelMap> ImageSource::CreateIncrementalPixelMap(uint32_t index, const DecodeOptions &opts,
    uint32_t &errorCode)
{
    return nullptr;
}

uint32_t ImageSource::PromoteDecoding(uint32_t index, const DecodeOptions &opts, PixelMap &pixelMap,
    ImageDecodingState &state, uint8_t &decodeProgress)
{
    return 0;
}

void ImageSource::DetachIncrementalDecoding(PixelMap &pixelMap)
{}

uint32_t ImageSource::UpdateData(const uint8_t *data, uint32_t size, bool isCompleted)
{
    return 0;
}

DecodeEvent ImageSource::GetDecodeEvent()
{
    return decodeEvent_;
}

uint32_t ImageSource::GetImageInfo(uint32_t index, ImageInfo &imageInfo)
{
    return 0;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const std::string &path)
{
    return 0;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const int fd)
{
    return 0;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, uint8_t *data, uint32_t size)
{
    return 0;
}

uint32_t ImageSource::GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value)
{
    return 0;
}

uint32_t ImageSource::GetImagePropertyString(uint32_t index, const std::string &key, std::string &value)
{
    return 0;
}

const SourceInfo &ImageSource::GetSourceInfo(uint32_t &errorCode)
{
    return sourceInfo_;
}

void ImageSource::RegisterListener(PeerListener *listener)
{}

void ImageSource::UnRegisterListener(PeerListener *listener)
{}

void ImageSource::AddDecodeListener(DecodeListener *listener)
{}

void ImageSource::RemoveDecodeListener(DecodeListener *listener)
{}

ImageSource::~ImageSource()
{}

bool ImageSource::IsStreamCompleted()
{
    return true;
}

ImageSource::ImageSource(std::unique_ptr<SourceStream> &&stream, const SourceOptions &opts)
{}

ImageSource::FormatAgentMap ImageSource::InitClass()
{
    FormatAgentMap tempAgentMap;
    return tempAgentMap;
}

uint32_t ImageSource::CheckEncodedFormat(AbsImageFormatAgent &agent)
{
    return 0;
}

uint32_t ImageSource::CheckFormatHint(const std::string &formatHint, FormatAgentMap::iterator &formatIter)
{
    return 0;
}

uint32_t ImageSource::GetEncodedFormat(const std::string &formatHint, std::string &format)
{
    return 0;
}

uint32_t ImageSource::OnSourceRecognized(bool isAcquiredImageNum)
{
    return 0;
}

uint32_t ImageSource::OnSourceUnresolved()
{
    return 0;
}

uint32_t ImageSource::DecodeSourceInfo(bool isAcquiredImageNum)
{
    return 0;
}

uint32_t ImageSource::DecodeImageInfo(uint32_t index, ImageStatusMap::iterator &iter)
{
    return 0;
}

uint32_t ImageSource::InitMainDecoder()
{
    return 0;
}

AbsImageDecoder *ImageSource::CreateDecoder(uint32_t &errorCode)
{
    return nullptr;
}

uint32_t ImageSource::SetDecodeOptions(std::unique_ptr<AbsImageDecoder> &decoder, uint32_t index,
    const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo)
{
    return 0;
}

uint32_t ImageSource::UpdatePixelMapInfo(const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo,
    PixelMap &pixelMap)
{
    return 0;
}

void ImageSource::CopyOptionsToPlugin(const DecodeOptions &opts, PixelDecodeOptions &plOpts)
{}

void ImageSource::CopyOptionsToProcOpts(const DecodeOptions &opts, DecodeOptions &procOpts, PixelMap &pixelMap)
{}

ImageSource::ImageStatusMap::iterator ImageSource::GetValidImageStatus(uint32_t index, uint32_t &errorCode)
{
    return imageStatusMap_.find(index);
}

uint32_t ImageSource::AddIncrementalContext(PixelMap &pixelMap, IncrementalRecordMap::iterator &iterator)
{
    return 0;
}

uint32_t ImageSource::DoIncrementalDecoding(uint32_t index, const DecodeOptions &opts, PixelMap &pixelMap,
    IncrementalDecodingContext &recordContext)
{
    return 0;
}

const NinePatchInfo &ImageSource::GetNinePatchInfo() const
{
    return ninePatchInfo_;
}

void ImageSource::SetMemoryUsagePreference(const MemoryUsagePreference preference)
{}

MemoryUsagePreference ImageSource::GetMemoryUsagePreference()
{
    return preference_;
}

uint32_t ImageSource::GetFilterArea(const int &redactionType,
    std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    return 0;
}

void ImageSource::SetIncrementalSource(const bool isIncrementalSource)
{
    isIncrementalSource_ = isIncrementalSource;
}

bool ImageSource::IsIncrementalSource()
{
    return isIncrementalSource_;
}

FinalOutputStep ImageSource::GetFinalOutputStep(const DecodeOptions &opts, PixelMap &pixelMap, bool hasNinePatch)
{
    return FinalOutputStep::NO_CHANGE;
}

bool ImageSource::HasDensityChange(const DecodeOptions &opts, ImageInfo &srcImageInfo, bool hasNinePatch)
{
    return true;
}

bool ImageSource::ImageSizeChange(int32_t width, int32_t height, int32_t desiredWidth, int32_t desiredHeight)
{
    return false;
}

bool ImageSource::ImageConverChange(const Rect &cropRect, ImageInfo &dstImageInfo, ImageInfo &srcImageInfo)
{
    return true;
}

std::unique_ptr<SourceStream> ImageSource::DecodeBase64(const uint8_t *data, uint32_t size)
{
    return DecodeBase64("");
}

std::unique_ptr<SourceStream> ImageSource::DecodeBase64(const std::string &data)
{
    return nullptr;
}

bool ImageSource::IsSpecialYUV()
{
    return true;
}

bool ImageSource::ConvertYUV420ToRGBA(uint8_t *data, uint32_t size,
    bool isSupportOdd, bool isAddUV, uint32_t &errorCode)
{
    return true;
}

std::unique_ptr<PixelMap> ImageSource::CreatePixelMapForYUV(uint32_t &errorCode)
{
    return nullptr;
}
} // namespace Media
} // namespace OHOS
