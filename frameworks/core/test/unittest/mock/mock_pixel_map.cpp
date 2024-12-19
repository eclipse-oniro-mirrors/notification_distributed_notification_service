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

#include "pixel_map.h"

namespace {
int32_t g_mockPixelMapGetByteCountRet = 128;
}

void MockPixelMapGetByteCount(int32_t mockRet)
{
    g_mockPixelMapGetByteCountRet = mockRet;
}

void MockResetPixelMapState()
{
    g_mockPixelMapGetByteCountRet = 128; // 128 ：initial test result
}
namespace OHOS {
namespace Media {
PixelMap::~PixelMap()
{}

void PixelMap::FreePixelMap() __attribute__((no_sanitize("cfi")))
{}

void PixelMap::ReleaseSharedMemory(void *addr, void *context, uint32_t size)
{}

void PixelMap::SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type, CustomFreePixelMap func)
{}

std::unique_ptr<PixelMap> PixelMap::Create(const uint32_t *colors, uint32_t colorLength,
    const InitializationOptions &opts)
{
    return nullptr;
}

std::unique_ptr<PixelMap> PixelMap::Create(const uint32_t *colors, uint32_t colorLength, int32_t offset,
    int32_t stride, const InitializationOptions &opts)
{
    return nullptr;
}

bool PixelMap::CheckParams(const uint32_t *colors, uint32_t colorLength, int32_t offset, int32_t stride,
                           const InitializationOptions &opts)
{
    return true;
}

std::unique_ptr<PixelMap> PixelMap::Create(const InitializationOptions &opts)
{
    return nullptr;
}

void PixelMap::UpdatePixelsAlpha(const AlphaType &alphaType, const PixelFormat &pixelFormat, uint8_t *dstPixels,
                                 PixelMap &dstPixelMap)
{}

std::unique_ptr<PixelMap> PixelMap::Create(PixelMap &source, const InitializationOptions &opts)
{
    return nullptr;
}

std::unique_ptr<PixelMap> PixelMap::Create(PixelMap &source, const Rect &srcRect, const InitializationOptions &opts)
{
    return nullptr;
}

bool PixelMap::SourceCropAndConvert(PixelMap &source, const ImageInfo &srcImageInfo, const ImageInfo &dstImageInfo,
                                    const Rect &srcRect, PixelMap &dstPixelMap)
{
    return true;
}

bool PixelMap::ScalePixelMap(const Size &targetSize, const Size &dstSize, const ScaleMode &scaleMode,
                             PixelMap &dstPixelMap)
{
    return true;
}

void PixelMap::InitDstImageInfo(const InitializationOptions &opts, const ImageInfo &srcImageInfo,
                                ImageInfo &dstImageInfo)
{}

bool PixelMap::CopyPixelMap(PixelMap &source, PixelMap &dstPixelMap)
{
    return true;
}

bool PixelMap::IsSameSize(const Size &src, const Size &dst)
{
    return true;
}

bool PixelMap::GetPixelFormatDetail(const PixelFormat format)
{
    return true;
}

uint32_t PixelMap::SetImageInfo(ImageInfo &info)
{
    return 0;
}

uint32_t PixelMap::SetImageInfo(ImageInfo &info, bool isReused)
{
    return 0;
}

const uint8_t *PixelMap::GetPixel8(int32_t x, int32_t y)
{
    return nullptr;
}

const uint16_t *PixelMap::GetPixel16(int32_t x, int32_t y)
{
    return nullptr;
}

const uint32_t *PixelMap::GetPixel32(int32_t x, int32_t y)
{
    return nullptr;
}

const uint8_t *PixelMap::GetPixel(int32_t x, int32_t y)
{
    return nullptr;
}

bool PixelMap::GetARGB32Color(int32_t x, int32_t y, uint32_t &color)
{
    return true;
}

bool PixelMap::ALPHA8ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    return true;
}

bool PixelMap::RGB565ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    return true;
}

bool PixelMap::ARGB8888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    return true;
}

bool PixelMap::RGBA8888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    return true;
}

bool PixelMap::BGRA8888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    return true;
}

bool PixelMap::RGB888ToARGB(const uint8_t *in, uint32_t inCount, uint32_t *out, uint32_t outCount)
{
    return true;
}

int32_t PixelMap::GetPixelBytes()
{
    return 0;
}

int32_t PixelMap::GetRowBytes()
{
    return 0;
}

int32_t PixelMap::GetByteCount()
{
    return g_mockPixelMapGetByteCountRet;
}

int32_t PixelMap::GetWidth()
{
    return 0;
}

int32_t PixelMap::GetHeight()
{
    return 0;
}

int32_t PixelMap::GetBaseDensity()
{
    return 0;
}

void PixelMap::GetImageInfo(ImageInfo &imageInfo)
{}

PixelFormat PixelMap::GetPixelFormat()
{
    return imageInfo_.pixelFormat;
}

ColorSpace PixelMap::GetColorSpace()
{
    return imageInfo_.colorSpace;
}

AlphaType PixelMap::GetAlphaType()
{
    return imageInfo_.alphaType;
}

const uint8_t *PixelMap::GetPixels()
{
    return data_;
}

uint8_t PixelMap::GetARGB32ColorA(uint32_t color)
{
    return 0;
}

uint8_t PixelMap::GetARGB32ColorR(uint32_t color)
{
    return 0;
}

uint8_t PixelMap::GetARGB32ColorG(uint32_t color)
{
    return 0;
}

uint8_t PixelMap::GetARGB32ColorB(uint32_t color)
{
    return 0;
}

bool PixelMap::IsSameImage(const PixelMap &other)
{
    return true;
}

uint32_t PixelMap::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    return 0;
}

bool PixelMap::CheckPixelsInput(const uint8_t *dst, const uint64_t &bufferSize, const uint32_t &offset,
                                const uint32_t &stride, const Rect &region)
{
    return true;
}

uint32_t PixelMap::ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
                              const Rect &region, uint8_t *dst)
{
    return 0;
}

uint32_t PixelMap::ReadPixel(const Position &pos, uint32_t &dst)
{
    return 0;
}

uint32_t PixelMap::ResetConfig(const Size &size, const PixelFormat &format)
{
    return 0;
}

bool PixelMap::SetAlphaType(const AlphaType &alphaType)
{
    return true;
}

uint32_t PixelMap::WritePixel(const Position &pos, const uint32_t &color)
{
    return 0;
}

uint32_t PixelMap::WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
                               const uint32_t &stride, const Rect &region)
{
    return 0;
}

uint32_t PixelMap::WritePixels(const uint8_t *source, const uint64_t &bufferSize)
{
    return 0;
}

bool PixelMap::WritePixels(const uint32_t &color)
{
    return true;
}

AllocatorType PixelMap::GetAllocatorType()
{
    return allocatorType_;
}

void *PixelMap::GetFd() const
{
    return context_;
}

void PixelMap::ReleaseMemory(AllocatorType allocType, void *addr, void *context, uint32_t size)
{}

bool PixelMap::WriteImageData(Parcel &parcel, size_t size) const
{
    return true;
}

uint8_t *PixelMap::ReadImageData(Parcel &parcel, int32_t size,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    return nullptr;
}

bool PixelMap::WriteFileDescriptor(Parcel &parcel, int fd)
{
    return true;
}

int PixelMap::ReadFileDescriptor(Parcel &parcel)
{
    return 0;
}

bool PixelMap::WriteImageInfo(Parcel &parcel) const
{
    return true;
}

bool PixelMap::Marshalling(Parcel &parcel) const
{
    return true;
}

bool PixelMap::ReadImageInfo(Parcel &parcel, ImageInfo &imgInfo)
{
    return true;
}

PixelMap *PixelMap::Unmarshalling(Parcel &data,
    std::function<int(Parcel &parcel, std::function<int(Parcel&)> readFdDefaultFunc)> readSafeFdFunc)
{
    return nullptr;
}

uint32_t PixelMap::SetAlpha(const float percent)
{
    return 0;
}

void PixelMap::scale(float xAxis, float yAxis)
{}

void PixelMap::translate(float xAxis, float yAxis)
{}

void PixelMap::rotate(float degrees)
{}

void PixelMap::flip(bool xAxis, bool yAxis)
{}

uint32_t PixelMap::crop(const Rect &rect)
{
    return 0;
}
} // namespace Media
} // namespace OHOS
