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

#include "mock_image_native.h"
#include "ans_inner_errors.h"
#include "raw_file.h"

namespace {
const uint32_t DEFAULT_IMAGE_SIZE = 100;
bool g_mockCreateFromRawFileFail = false;
bool g_mockCreateFromRawFileReturnNull = false;
bool g_mockCreatePixelmapFail = false;
bool g_mockCreatePixelmapReturnNull = false;
bool g_mockGetImageInfoFail = false;
bool g_mockGetWidthFail = false;
bool g_mockGetHeightFail = false;
bool g_mockReadPixelsFail = false;
bool g_mockImageSourceInfoCreateFail = false;
bool g_mockImageSourceInfoCreateReturnNull = false;
bool g_mockDecodingOptionsCreateReturnNull = false;
uint32_t g_mockImageWidth = DEFAULT_IMAGE_SIZE;
uint32_t g_mockImageHeight = DEFAULT_IMAGE_SIZE;

struct MockImageSourceNative {
    int dummy = 0;
};

struct MockPixelmapNative {
    int dummy = 0;
};

struct MockImageSourceInfo {
    uint32_t width = DEFAULT_IMAGE_SIZE;
    uint32_t height = DEFAULT_IMAGE_SIZE;
};

struct MockDecodingOptions {
    int dummy = 0;
};

MockImageSourceNative* g_mockImageSourceNative = nullptr;
MockPixelmapNative* g_mockPixelmapNative = nullptr;
MockImageSourceInfo* g_mockImageSourceInfo = nullptr;
}

namespace OHOS {
namespace Notification {
namespace Mock {
void MockOHImageSourceNativeCreateFromRawFileFail(bool fail)
{
    g_mockCreateFromRawFileFail = fail;
}

void MockOHImageSourceNativeCreateFromRawFileReturnNull(bool returnNull)
{
    g_mockCreateFromRawFileReturnNull = returnNull;
}

void MockOHImageSourceNativeCreatePixelmapFail(bool fail)
{
    g_mockCreatePixelmapFail = fail;
}

void MockOHImageSourceNativeCreatePixelmapReturnNull(bool returnNull)
{
    g_mockCreatePixelmapReturnNull = returnNull;
}

void MockOHImageSourceNativeGetImageInfoFail(bool fail)
{
    g_mockGetImageInfoFail = fail;
}

void MockOHImageSourceInfoGetWidthFail(bool fail)
{
    g_mockGetWidthFail = fail;
}

void MockOHImageSourceInfoGetHeightFail(bool fail)
{
    g_mockGetHeightFail = fail;
}

void MockOHPixelmapNativeReadPixelsFail(bool fail)
{
    g_mockReadPixelsFail = fail;
}

void MockOHImageSourceInfoCreateFail(bool fail)
{
    g_mockImageSourceInfoCreateFail = fail;
}

void MockOHImageSourceInfoCreateReturnNull(bool returnNull)
{
    g_mockImageSourceInfoCreateReturnNull = returnNull;
}

void MockOHDecodingOptionsCreateReturnNull(bool returnNull)
{
    g_mockDecodingOptionsCreateReturnNull = returnNull;
}

void MockSetImageWidth(uint32_t width)
{
    g_mockImageWidth = width;
}

void MockSetImageHeight(uint32_t height)
{
    g_mockImageHeight = height;
}

void MockResetImageNativeState()
{
    g_mockCreateFromRawFileFail = false;
    g_mockCreateFromRawFileReturnNull = false;
    g_mockCreatePixelmapFail = false;
    g_mockCreatePixelmapReturnNull = false;
    g_mockGetImageInfoFail = false;
    g_mockGetWidthFail = false;
    g_mockGetHeightFail = false;
    g_mockReadPixelsFail = false;
    g_mockImageSourceInfoCreateFail = false;
    g_mockImageSourceInfoCreateReturnNull = false;
    g_mockDecodingOptionsCreateReturnNull = false;
    g_mockImageWidth = DEFAULT_IMAGE_SIZE;
    g_mockImageHeight = DEFAULT_IMAGE_SIZE;
    if (g_mockImageSourceNative != nullptr) {
        delete g_mockImageSourceNative;
        g_mockImageSourceNative = nullptr;
    }
    if (g_mockPixelmapNative != nullptr) {
        delete g_mockPixelmapNative;
        g_mockPixelmapNative = nullptr;
    }
    if (g_mockImageSourceInfo != nullptr) {
        delete g_mockImageSourceInfo;
        g_mockImageSourceInfo = nullptr;
    }
}
}  // namespace Mock
}  // namespace Notification
}  // namespace OHOS

extern "C" {
Image_ErrorCode OH_ImageSourceNative_CreateFromRawFile(
    RawFileDescriptor* rawFileDescriptor,
    OH_ImageSourceNative** imageSourceNative)
{
    if (g_mockCreateFromRawFileFail || g_mockCreateFromRawFileReturnNull) {
        *imageSourceNative = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    if (g_mockImageSourceNative == nullptr) {
        g_mockImageSourceNative = new MockImageSourceNative();
    }
    *imageSourceNative = reinterpret_cast<OH_ImageSourceNative*>(g_mockImageSourceNative);
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceNative_CreatePixelmap(
    OH_ImageSourceNative* imageSourceNative,
    OH_DecodingOptions* decodingOptions,
    OH_PixelmapNative** pixelmapNative)
{
    if (g_mockCreatePixelmapFail || g_mockCreatePixelmapReturnNull) {
        *pixelmapNative = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    if (g_mockPixelmapNative == nullptr) {
        g_mockPixelmapNative = new MockPixelmapNative();
    }
    *pixelmapNative = reinterpret_cast<OH_PixelmapNative*>(g_mockPixelmapNative);
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceNative_GetImageInfo(
    OH_ImageSourceNative* source,
    int32_t index,
    OH_ImageSource_Info* imageInfo)
{
    if (g_mockGetImageInfoFail) {
        return IMAGE_BAD_PARAMETER;
    }
    MockImageSourceInfo* mockInfo = reinterpret_cast<MockImageSourceInfo*>(imageInfo);
    if (mockInfo != nullptr) {
        mockInfo->width = g_mockImageWidth;
        mockInfo->height = g_mockImageHeight;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceInfo_Create(OH_ImageSource_Info** imageInfo)
{
    if (g_mockImageSourceInfoCreateFail || g_mockImageSourceInfoCreateReturnNull) {
        *imageInfo = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    if (g_mockImageSourceInfo == nullptr) {
        g_mockImageSourceInfo = new MockImageSourceInfo();
        g_mockImageSourceInfo->width = g_mockImageWidth;
        g_mockImageSourceInfo->height = g_mockImageHeight;
    }
    *imageInfo = reinterpret_cast<OH_ImageSource_Info*>(g_mockImageSourceInfo);
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceInfo_GetWidth(OH_ImageSource_Info* imageInfo, uint32_t* width)
{
    if (g_mockGetWidthFail) {
        return IMAGE_BAD_PARAMETER;
    }
    MockImageSourceInfo* mockInfo = reinterpret_cast<MockImageSourceInfo*>(imageInfo);
    if (mockInfo != nullptr && width != nullptr) {
        *width = mockInfo->width;
    } else {
        *width = g_mockImageWidth;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceInfo_GetHeight(OH_ImageSource_Info* imageInfo, uint32_t* height)
{
    if (g_mockGetHeightFail) {
        return IMAGE_BAD_PARAMETER;
    }
    MockImageSourceInfo* mockInfo = reinterpret_cast<MockImageSourceInfo*>(imageInfo);
    if (mockInfo != nullptr && height != nullptr) {
        *height = mockInfo->height;
    } else {
        *height = g_mockImageHeight;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_PixelmapNative_ReadPixels(
    OH_PixelmapNative* pixelmapNative,
    uint8_t* buffer,
    size_t* bufferSize)
{
    if (g_mockReadPixelsFail) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceNative_Release(OH_ImageSourceNative* imageSourceNative)
{
    MockImageSourceNative* mockSource = reinterpret_cast<MockImageSourceNative*>(imageSourceNative);
    if (mockSource == g_mockImageSourceNative) {
        delete g_mockImageSourceNative;
        g_mockImageSourceNative = nullptr;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_PixelmapNative_Release(OH_PixelmapNative* pixelmapNative)
{
    MockPixelmapNative* mockPixelmap = reinterpret_cast<MockPixelmapNative*>(pixelmapNative);
    if (mockPixelmap == g_mockPixelmapNative) {
        delete g_mockPixelmapNative;
        g_mockPixelmapNative = nullptr;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageSourceInfo_Release(OH_ImageSource_Info* imageInfo)
{
    MockImageSourceInfo* mockInfo = reinterpret_cast<MockImageSourceInfo*>(imageInfo);
    if (mockInfo == g_mockImageSourceInfo) {
        delete g_mockImageSourceInfo;
        g_mockImageSourceInfo = nullptr;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_Create(OH_DecodingOptions** decodingOptions)
{
    if (g_mockDecodingOptionsCreateReturnNull) {
        *decodingOptions = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    MockDecodingOptions* mockOptions = new MockDecodingOptions();
    *decodingOptions = reinterpret_cast<OH_DecodingOptions*>(mockOptions);
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_Release(OH_DecodingOptions* decodingOptions)
{
    MockDecodingOptions* mockOptions = reinterpret_cast<MockDecodingOptions*>(decodingOptions);
    if (mockOptions != nullptr) {
        delete mockOptions;
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_SetDesiredSize(
    OH_DecodingOptions* decodingOptions,
    Image_Size* desiredSize)
{
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_SetPixelFormat(
    OH_DecodingOptions* decodingOptions,
    int32_t pixelFormat)
{
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_SetDesiredDynamicRange(
    OH_DecodingOptions* decodingOptions,
    int32_t desiredDynamicRange)
{
    return IMAGE_SUCCESS;
}
}