/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "image_packer.h"
#include "mock_image_related_class.h"
#include "securec.h"

namespace {
const uint8_t COUNT = 64;
uint32_t g_mockImagePackerGetSupportedFormatsRet = 0;
const uint8_t *g_mockImagePackerStartPackingRet = nullptr;
uint32_t g_mockImagePackerFinalizePackingRet = 16;
}

void MockImagePackerGetSupportedFormats(uint32_t mockRet)
{
    g_mockImagePackerGetSupportedFormatsRet = mockRet;
}

void MockImagePackerStartPacking(const uint8_t *mockRet)
{
    g_mockImagePackerStartPackingRet = mockRet;
}

void MockImagePackerFinalizePacking(uint32_t mockRet)
{
    g_mockImagePackerFinalizePackingRet = mockRet;
}

void MockResetImagePackerState()
{
    g_mockImagePackerGetSupportedFormatsRet = 0;
    g_mockImagePackerStartPackingRet = nullptr;
    g_mockImagePackerFinalizePackingRet = 16; // 16 ：initial test result
}

namespace OHOS {
namespace Media {
using namespace ImagePlugin;
using namespace MultimediaPlugin;

uint32_t ImagePacker::GetSupportedFormats(std::set<std::string> &formats)
{
    return g_mockImagePackerGetSupportedFormatsRet;
}

uint32_t ImagePacker::StartPackingImpl(const PackOption &option)
{
    return 0;
}

uint32_t ImagePacker::StartPacking(uint8_t *outputData, uint32_t maxSize, const PackOption &option)
{
    memcpy_s(outputData, COUNT, g_mockImagePackerStartPackingRet, COUNT);
    return 0;
}

uint32_t ImagePacker::StartPacking(const std::string &filePath, const PackOption &option)
{
    return 0;
}

uint32_t ImagePacker::StartPacking(const int &fd, const PackOption &option)
{
    return 0;
}

uint32_t ImagePacker::StartPacking(std::ostream &outputStream, const PackOption &option)
{
    return 0;
}

uint32_t ImagePacker::StartPackingAdapter(PackerStream &outputStream, const PackOption &option)
{
    return 0;
}

uint32_t ImagePacker::AddImage(PixelMap &pixelMap)
{
    return 0;
}

uint32_t ImagePacker::AddImage(ImageSource &source)
{
    return 0;
}

uint32_t ImagePacker::AddImage(ImageSource &source, uint32_t index)
{
    return 0;
}

uint32_t ImagePacker::FinalizePacking()
{
    return 0;
}

uint32_t ImagePacker::FinalizePacking(int64_t &packedSize)
{
    packedSize = g_mockImagePackerFinalizePackingRet;
    return 0;
}

bool ImagePacker::GetEncoderPlugin(const PackOption &option)
{
    return true;
}

void ImagePacker::CopyOptionsToPlugin(const PackOption &opts, PlEncodeOptions &plOpts)
{}

void ImagePacker::FreeOldPackerStream()
{}

bool ImagePacker::IsPackOptionValid(const PackOption &option)
{
    return true;
}

// class reference need explicit constructor and destructor, otherwise unique_ptr<T> use unnormal
ImagePacker::ImagePacker()
{}

ImagePacker::~ImagePacker()
{}
} // namespace Media
} // namespace OHOS
